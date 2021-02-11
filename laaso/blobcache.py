#!/usr/bin/env python3
#
# laaso/blobcache.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Tool for prefetching blob lists and storing them in a common format
that abstracts the account type.
'''

import datetime
from enum import Enum
import math
import multiprocessing
import pickle
import queue
import re
import stat
import traceback

from azure.storage.blob import BlobProperties
from azure.storage.filedatalake import PathProperties

# In case it's non-obvious, dateutil is a 3rd-party package,
# so pylint likes it to be imported down here with the rest of them.
import dateutil

from laaso.lustre_ctypes import CTimespec
from laaso.storagenaming import ContainerName, BlobName

class Ftypes(Enum):
    '''
    The file types that we support (a subset of the file types available)
    '''
    UNKNOWN = 0
    FILE = stat.S_IFREG
    DIR = stat.S_IFDIR
    SYMLINK = stat.S_IFLNK

    @staticmethod
    def is_matching(ftype, stat_res):
        '''
        Check if the given Ftype matches the results of a stat call.
        '''
        if ftype == Ftypes.FILE:
            return stat.S_ISREG(stat_res.st_mode) != 0
        if ftype == Ftypes.DIR:
            return stat.S_ISDIR(stat_res.st_mode) != 0
        if ftype == Ftypes.SYMLINK:
            return stat.S_ISLNK(stat_res.st_mode) != 0
        assert ftype in [Ftypes.FILE, Ftypes.DIR, Ftypes.SYMLINK]
        # it's a bug if we get here
        return False

class XAttr():
    '''
    Base class for xattr - the key and the value are the same.
    '''
    def __init__(self,
                 key_str,
                 value_bytes=b''):
        assert key_str

        self._key_str = key_str
        self._key_bytes = self._key_str.encode()

        self._value_bytes = value_bytes if value_bytes else self._key_bytes

        # Default behavior is to populate the key bytes if they weren't provided.

    @property
    def key_str(self):
        '''
        Retrieve the key as a string.
        '''
        return self._key_str

    @property
    def key_bytes(self):
        '''
        Retrieve the key as bytes.
        '''
        return self._key_bytes

    @property
    def value_bytes(self):
        '''
        Retrieve the value as bytes.
        '''
        return self._value_bytes

    def to_setxattr_params(self):
        '''
        Return a tuple that can be used as params to an os.setxattr call.
        '''
        return (self.key_str, self.key_bytes, self.value_bytes)

class UUIDXAttr(XAttr):
    '''
    Derived xattr, pass in the string, and also the value
    '''
    def __init__(self, container, name, key_str):
        super().__init__(key_str=key_str, value_bytes='az://{container}/{name}'.format(container=container, name=name).encode())

class HashXAttr(XAttr):
    '''
    An xattr representing a hash value.
    '''
    def __init__(self, key_str):
        super().__init__(key_str=key_str,
                         value_bytes=key_str.encode().hex().upper().encode())

class BlobAttributes():
    '''
    Convenient stat-looking structure to contain blob attributes that we care about.
    Adds valid status for the various stat values that we care about.
    '''

    # regex's for the various permission bit formats that azure supports
    # Azure supports the sticky bit and the owner/group/world perms.
    MODE_RE_OCTAL = re.compile('[0-1][0-7]{3}')
    MODE_RE_STR = re.compile('([r-][w-][x-]){3}[t]{0,1}')

    NSEC_PER_SEC = 1000 * 1000 * 1000

    DEFAULT_UID = 0
    DEFAULT_GID = 0

    DEFAULT_MODE_FILES = 0o644
    DEFAULT_MODE_DIRS = 0o777

    # Support all lower-case blob metadata keys and first letter upper case.
    # The latter is required by the wastore copytool.
    BLOB_ISDIR_KEYS = ['hdi_isfolder', 'Hdi_isfolder']
    BLOB_ISDIR_VAL = 'true'
    BLOB_FTYPE_KEYS = ['ftype', 'Ftype']
    BLOB_LNK_VAL = 'LNK'
    BLOB_UID_KEYS = ['owner', 'Owner']
    BLOB_GID_KEYS = ['group', 'Group']
    BLOB_MODE_KEYS = ['permissions', 'Permissions']

    # The set of mode bits that we care about
    ALL_MODE_BITS = stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO | stat.S_ISVTX

    # POSIX maximums
    PATH_MAX = 4096
    NAME_MAX = 255

    # Lemur attrs that are common to all deployments
    XATTR_URL = XAttr(key_str='trusted.lhsm_url')
    XATTR_HASH = HashXAttr(key_str='trusted.lhsm_hash')
    BASE_LEMUR_ATTRS = [XATTR_URL.to_setxattr_params(), XATTR_HASH.to_setxattr_params()]

    # Flip this switch to True to prefer the HNS PathProperties over the Blob metadata
    # when populating from an HNS-enabled storage account.
    # HNS owner/group cannot generally be translated to an integer uid/gid, so this tool
    # relies on the blob metadata instead.
    USE_HNS_ATTRIBUTES = False

    def __init__(self, blob=None, contents=None):
        '''
        Init attributes and valid flags.
        '''
        self.name = ''
        self.contents = contents or bytes()
        assert isinstance(self.contents, bytes)
        self.st_type = Ftypes.UNKNOWN
        self.st_mode = 0
        self.st_mode_valid = False
        self.st_uid = 0
        self.st_uid_valid = False
        self.st_gid = 0
        self.st_gid_valid = False
        # Every blob has a size and an mtime
        self.st_size = 0
        self.st_mtim = CTimespec(0, 0)
        self.warnings = []

        if blob:
            self.stat(blob)

    def __str__(self):
        '''
        Print a BlobAttributes as a string.
        '''
        fmt = "name({name}) type({tp}) lnk({lnk}) mode({mode_valid}/{mode}) uid({uid_valid}/{uid}) gid({gid_valid}/{gid}) sz({size}) mtime({mtime_sec}:{mtime_nsec})"
        return fmt.format(name=self.name, tp=self.st_type, lnk=self.contents,
                          mode_valid=self.st_mode_valid, mode=self.st_mode,
                          uid_valid=self.st_uid_valid, uid=self.st_uid,
                          gid_valid=self.st_gid_valid, gid=self.st_gid,
                          size=self.st_size,
                          mtime_sec=self.st_mtim.tv_sec, mtime_nsec=self.st_mtim.tv_nsec)

    @staticmethod
    def symlink_hint(blob):
        '''
        Return True if the blob represents a symlink.
        This is a helper so callers know if the blob contents are required.
        '''
        if isinstance(blob, BlobProperties):
            if blob.metadata:
                return BlobAttributes.get_metadata_val(BlobAttributes.BLOB_FTYPE_KEYS, blob).upper() == BlobAttributes.BLOB_LNK_VAL
        # PathProperties (HNS) blobs do not support symlinks
        return False

    @staticmethod
    def get_metadata_val(keys, blob):
        '''
        Return the metadata val associated with one of they keys in the list
        if the any of the keys exist.  Return the empty string if none of the keys exist.
        '''
        if blob.metadata:
            for key in keys:
                if key in blob.metadata:
                    return blob.metadata[key]
        return ''

    def stat(self, blob):
        '''
        You can call this separately from the constructor to load the attributes.
        '''
        if isinstance(blob, BlobProperties):
            ftype = Ftypes.FILE
            if blob.metadata:
                isdir_val = self.get_metadata_val(BlobAttributes.BLOB_ISDIR_KEYS, blob).lower()
                if isdir_val:
                    if isdir_val == BlobAttributes.BLOB_ISDIR_VAL:
                        ftype = Ftypes.DIR
                    else:
                        self.warnings.append("invalid value for key %r: %r" % (BlobAttributes.BLOB_ISDIR_KEYS[0], isdir_val))
                ftype_val = self.get_metadata_val(BlobAttributes.BLOB_FTYPE_KEYS, blob).upper()
                if ftype_val:
                    if isdir_val:
                        self.warnings.append("invalid blob attribute combination, cannot have both '%s' and '%s'" %
                                             (BlobAttributes.BLOB_ISDIR_KEYS[0], BlobAttributes.BLOB_FTYPE_KEYS[0]))
                    else:
                        if ftype_val == BlobAttributes.BLOB_LNK_VAL:
                            ftype = Ftypes.SYMLINK
                        else:
                            self.warnings.append("invalid value for attribute %s: '%s'" % (BlobAttributes.BLOB_FTYPE_KEYS, ftype_val))
            self.blob2attrs(blob.name,
                            ftype,
                            self.get_metadata_val(BlobAttributes.BLOB_UID_KEYS, blob),
                            self.get_metadata_val(BlobAttributes.BLOB_GID_KEYS, blob),
                            self.get_metadata_val(BlobAttributes.BLOB_MODE_KEYS, blob),
                            blob.last_modified, blob.size)
        else:
            assert isinstance(blob, PathProperties)
            ftype = Ftypes.FILE
            if blob.is_directory:
                ftype = Ftypes.DIR
            self.blob2attrs(blob.name,
                            ftype,
                            blob.owner, blob.group,
                            blob.permissions, blob.last_modified,
                            blob.content_length)

    def is_directory(self):
        '''
        Returns true if we should interpret the blob as a directory.
        '''
        return self.st_type == Ftypes.DIR

    def is_symlink(self):
        '''
        Returns true if we should interpret the blob as a symlink.
        '''
        return self.st_type == Ftypes.SYMLINK

    def is_reg(self):
        '''
        Returns true if the blob represents a regular file.
        '''
        return self.st_type == Ftypes.FILE

    @staticmethod
    def float_to_nsec_sec(fl):
        '''
        Separate a floating point number into seconds and nanoseconds portions.
        '''
        nsecs_frac, secs = math.modf(fl)
        nsecs = nsecs_frac * BlobAttributes.NSEC_PER_SEC
        return int(nsecs), int(secs)

    def id_to_int(self, value):
        '''
        Convert a uid/gid to an integer if necessary.
        '''
        if not value:
            return -1
        # generally, we can't convert a username to a uid or gid since we have no lookup mechanism,
        # however, we'll support the following well-known keywords
        if 'superuser' in value or 'supergroup' in value or value == 'root' or value == 'wheel':
            return 0
        try:
            return int(value)
        except ValueError:
            self.warnings.append("could not interpret uid or gid '%s'" % (value))
        return -1

    def get_lemur_xattrs(self, container):
        '''
        Return the lemur xattrs to be applied as a list of tuples of (key_str, key_bytes, value_bytes)
        '''
        # The uuid xattr includes the blob name and container name, so we build it on the fly and append
        # it to the other attrs.
        xattr_uuid = UUIDXAttr(container, self.name, key_str='trusted.lhsm_uuid')
        return self.BASE_LEMUR_ATTRS + [xattr_uuid.to_setxattr_params()]

    def blob2attrs(self, name, ftype, uid, gid, mode, mtime, size):
        '''
        Store the attributes returned by the blob metadata.
        '''
        self.name = name
        self.st_type = ftype
        if self.st_type == Ftypes.SYMLINK:
            if not self.contents:
                self.warnings.append("blob marked as symlink, but contents are empty")
            if size > self.PATH_MAX:
                # We only read up to PATH_MAX bytes (BlobCache.read_blob()) for symlinks
                # However, if the blob size indicates that it was larger, then we have truncated some bytes.
                self.warnings.append("truncated link target to PATH_MAX(%d) bytes" % self.PATH_MAX)
        uid = self.id_to_int(uid)
        if uid != -1:
            self.st_uid = uid
            self.st_uid_valid = True
        gid = self.id_to_int(gid)
        if gid != -1:
            self.st_gid = gid
            self.st_gid_valid = True

        if mode:
            if self.read_mode_bits(mode):
                self.st_mode_valid = True
            else:
                self.warnings.append("could not read mode bits '%s'" % mode)

        if isinstance(mtime, str):  # hns occasionally returns mtime as a datetime str
            try:
                mtime = dateutil.parser.parse(mtime)
            except ValueError:
                self.warnings.append("could not interpret '%s' as an mtime, used current time instead" % mtime)
                mtime = datetime.datetime.now()
        nsecs, secs = self.float_to_nsec_sec(mtime.timestamp())
        self.st_mtim.tv_sec = secs
        self.st_mtim.tv_nsec = nsecs

        self.st_size = size

    def read_mode_bits_from_octal(self, mode):
        '''
        Read the mode bits from Azure octal notation.
        The only [documented] supported format is like this: 0666.
        '''
        self.st_mode = int(mode, base=8)

    def read_mode_bits_from_str(self, mode):
        '''
        Read the mode bits from Azure as a string.
        The documented acceptable format is like this: "rw-rw-r---".
        '''
        pos = 0
        if mode[pos] == 'r':
            self.st_mode |= stat.S_IRUSR
        pos += 1
        if mode[pos] == 'w':
            self.st_mode |= stat.S_IWUSR
        pos += 1
        if mode[pos] == 'x':
            self.st_mode |= stat.S_IXUSR
        pos += 1
        if mode[pos] == 'r':
            self.st_mode |= stat.S_IRGRP
        pos += 1
        if mode[pos] == 'w':
            self.st_mode |= stat.S_IWGRP
        pos += 1
        if mode[pos] == 'x':
            self.st_mode |= stat.S_IXGRP
        pos += 1
        if mode[pos] == 'r':
            self.st_mode |= stat.S_IROTH
        pos += 1
        if mode[pos] == 'w':
            self.st_mode |= stat.S_IWOTH
        pos += 1
        if mode[pos] == 'x':
            self.st_mode |= stat.S_IXOTH
        pos += 1
        if len(mode) > pos and mode[pos] == 't':
            self.st_mode |= stat.S_ISVTX

    def read_mode_bits(self, mode):
        '''
        Reads the mode bits from Azure and saves them in pythonic format.
        Returns False if the mode bits could not be read.
        '''
        self.st_mode = 0
        match = self.MODE_RE_OCTAL.match(mode)
        if match:
            self.read_mode_bits_from_octal(match[0])
            return True
        match = self.MODE_RE_STR.match(mode)
        if match:
            self.read_mode_bits_from_str(match[0])
            return True
        return False

class BlobAttrsBatch():
    '''
    Data structure to batch many BlobAttributes together so we can communicate
    more efficiently with the parent process over our dedicated Queue.
    It's more efficient to send the blobs in batches instead of one at a time.
    '''
    MAX_BATCH_SIZE = 100
    def __init__(self):
        '''
        Init.  Call append to add each blob.
        '''
        self.contents = list()

    def append(self, blob_attrs):
        '''
        append a blob_attrs to the batch
        '''
        self.contents.append(blob_attrs)

class BlobCacheTermPill():
    '''
    Termination pill for the blobcache.
    If the parent process receives this over the queue, it knows the blobcache
    has terminated early.
    '''
    def __init__(self, error_msg, error_tb):
        '''
        Init.  Takes a message and an exception traceback.
        '''
        self.error_msg = error_msg
        self.error_tb = error_tb

class BlobCache(multiprocessing.Process):
    '''
    Child process that fetches blobs and puts them in a queue.
    The queue and queue size are controlled by the parent process, and they are passed in as
    a paramter to the constructor.
    '''
    STATS_FREQ_SEC = 30

    def __init__(self,
                 msg_queue,
                 subscription_id,
                 storage_acct,
                 container,
                 credential,
                 manager,
                 prefix=""):
        '''
        Init.
        '''
        super().__init__()
        self.msg_queue = msg_queue
        self.subscription_id = subscription_id
        self.storage_acct = storage_acct
        self.container = container
        self.credential = credential
        self.manager = manager
        self.prefix = prefix

        self.blobs = None

    def blobop_container_bundle_generate(self):
        '''
        Get a BlobOpBundle for the container
        '''
        cn = ContainerName(self.storage_acct, self.container, subscription_id=self.subscription_id)
        blobop = self.manager.blobop_bundle_get(cn, credential=self.credential)
        return blobop

    def start_generator(self):
        '''
        Get a generator for listing blobs.
        '''
        blobop = self.blobop_container_bundle_generate()
        name_starts_with = self.prefix if self.prefix else None
        if blobop.hns_enabled and BlobAttributes.USE_HNS_ATTRIBUTES:
            self.blobs = blobop.filesystemclient.get_paths(path=name_starts_with, recursive=True)
        else:
            self.blobs = blobop.blob_names_iter_get(name_starts_with=name_starts_with, include='metadata')

    def read_blob(self, blob):
        '''
        Read the contents of a blob if it appears to be a symlink.
        A quick study of the lustre source seems to confirm that the max data that may be
        read from a Lustre symlink is PATH_MAX bytes. Therefore, we truncate it as such here and report
        the truncation in BlobAttributes.blob2attrs() when we determine that the number of bytes
        in the blob are greater than PATH_MAX.
        '''
        if BlobAttributes.symlink_hint(blob):
            bn = BlobName(self.storage_acct, self.container, blob.name, subscription_id=self.subscription_id)
            blobop = self.manager.blobop_bundle_get(bn, credential=self.credential)
            blob_stream = blobop.blobclient.download_blob(offset=0, length=BlobAttributes.PATH_MAX)
            return blob_stream.content_as_bytes()
        return None

    def next_blob(self):
        '''
        Return the next blob from the blob list as a BlobAttributes.
        '''
        try:
            blob = next(self.blobs)
            contents = self.read_blob(blob)
            return BlobAttributes(blob, contents)
        except StopIteration:
            return None

    def next_batch(self):
        '''
        Return the next batch of items.
        '''
        batch = BlobAttrsBatch()
        for _ in range(0, batch.MAX_BATCH_SIZE):
            blob_attrs = self.next_blob()
            if not blob_attrs:
                batch.append(None) # Reached the end
                break
            batch.append(blob_attrs)
        assert batch.contents  # Can't return an empty batch
        return batch

    def run(self):
        '''
        Wrapper to main routine to catch exceptions and report them back to the parent.
        If the blobcache throws an unexpected exception, we send the parent process (hydrator.py)
        a termination pill containing the exception information.  If the queue happens to be full
        and remains full after several retries, we eventually just give up.  In this case,
        the parent process is likely experiencing issues too and can't process the queue.
        If the problems clear up in the parent, it will notice that the queue has closed
        and it will terminate with an exception.
        '''
        try:
            self.run_internal()
        except Exception as exc:
            pill = BlobCacheTermPill(repr(exc), traceback.format_exc())
            for _ in range(0, 10):
                try:
                    self.msg_queue.put(pickle.dumps(pill), timeout=5.0)
                    break
                except queue.Full:
                    pass # queue is full, parent process likely experiencing problems as well
            raise exc
        finally:
            self.msg_queue.close()

    def run_internal(self):
        '''
        Main routine for the thread/process.
        Stuff blobs onto the queue until the queue fills up.
        If we run out of blobs, then we're done.
        If the parent process errors out, it will terminate us automatically.
        '''
        self.start_generator()
        while True:
            batch = self.next_batch()
            while True:
                try:
                    # Future: Is it faster to put batches of blob_attrs on the Queue
                    # to reduce internal locking contention within the Queue?
                    self.msg_queue.put(pickle.dumps(batch), timeout=3.0)
                    break
                except queue.Full:
                    pass # parent process likely moving slowly, just retry
            if not batch.contents[-1]:
                break # sent all blobs, we're done

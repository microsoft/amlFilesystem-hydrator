#!/usr/bin/env python3
#
# laaso/hydrator.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Main program to hydrate the Lustre namespace from blob.
'''

import datetime
import multiprocessing
import os
import pickle
import queue
import stat
import sys
import syslog
import threading
import time
import traceback

from azure.core.exceptions import ResourceNotFoundError

import laaso.appmanager
import laaso.azure_tool
from laaso.blobcache import (BlobAttrsBatch,
                             BlobAttributes,
                             BlobCache,
                             BlobCacheTermPill,
                             Ftypes)
import laaso.common
from laaso.exceptions import ApplicationExit
from laaso.hsmimport import (HSMImport,
                             HSMDefaults)
from laaso.hydratorstats import (HydratorStats,
                                 PeriodicStatsPrinter)
import laaso.identity
from laaso.lustre_ctypes import (CLustreFid,
                                 LibLustreApi)
from laaso.output import output_redact
import laaso.util

HYDRATOR_DESCRIPTION = """
Hydrate a Lustre namespace from an Azure storage account.
"""

HYDRATOR_STANDALONE = False

class LemurResults():
    '''
    Lemur results.
    '''
    def __init__(self):
        '''
        Init.
        '''
        self.setxattr_cnt = 0
        self.setxattr_retry = 0
        self.err_msg = None
        self.err_tb = None

class FileImportResults():
    '''
    Results data sent to worker callback after a file is imported.
    '''
    def __init__(self,
                 uid=0,           # effective uid, gid, mode that were used
                 gid=0,
                 mode=0,
                 rc=0,            # rc from lustre hsm_import call
                 fid_out=None,    # CLustreFid result from lustre hsm_import call
                 err_msg=None,    # these two are only used if there was an error
                 err_tb=None):
        '''
        Init.
        '''
        self.uid = uid
        self.gid = gid
        self.mode = mode
        self.rc = rc
        self.fid_out = fid_out if fid_out else CLustreFid()
        self.err_msg = err_msg
        self.err_tb = err_tb

class FileImportWork():
    '''
    A container for the work description and all callback data for a worker process.
    '''
    def __init__(self, lustre_path, blob_attrs, archive_id):
        '''
        Init.
        lustre_path, blob_attrs: parameters for the file import.
        '''
        self.lustre_path = lustre_path
        self.blob_attrs = blob_attrs
        self.archive_id = archive_id
        self.import_results = None  # set to a FileImportResults() by the worker process
        self.lemur_results = None   # set to LemurResults() if lemur setxattrs were ocmpleted

class LemurParams():
    '''
    Container for the lemur params when doing a file import.
    This only gets used when lemur compatibility is enabled.
    '''
    def __init__(self, container):
        self.container = container

class FileImportWorkersBatch():
    '''
    Batch of work to send to worker processes for importing files.
    '''
    def __init__(self):
        '''
        Init.  Call append to add a work item.
        '''
        self.work = list()
        self.start = time.monotonic()
        self.lemur_params = None

    def append(self, more_work):
        '''
        Add an item to the batch.
        '''
        self.work.append(more_work)

class Context():
    '''
    Maintain some context while switching between directories in the tree.
    The goal of tracking the current context is to reduce the overall number of
    ops that we perform on directories.  For example, we only want to set attributes
    on a directoy once.  Also, if we created a directory (vs. it was pre-existing) we know
    that it should not have any children so we can make some performance-enhancing assumptions.
    '''
    def __init__(self, path, created=False, is_root=False):
        '''
        Init.
        '''
        self.path = path        # path to the cwd
        self.created = created  # True if the hydrator created this dir (vs. pre-existing)
        self.is_root = is_root  # True if this is the root of the tree

class Hydrator(laaso.appmanager.ApplicationWithManager):
    '''
    Hydrate a Lustre namespace from an Azure storage account.
    '''
    STATS_FREQ_SEC = 30   # Print stats every this many seconds

    # format for log messages
    LOG_FMT = laaso.common.Application.LOG_FORMAT_TS_LEVEL

    # File name for error reporting (goes in the root of the dest_path by default)
    ERR_FILE_NAME = "azure_hydration_errors.log"

    # header that we put on the error-reporting file (customer sees this)
    ERR_FILE_HEADER = "# This file contains a list of errors encountered by the service while hydrating the Lustre namespace."

    # Max errors before the hydrator gives up
    MAX_ERRORS = 1000

    # The following params are likely the key knobs influencing performance.
    # In the future, it might be good to write code that adjusts these on the fly.
    # - MAX_BLOBCACHE_PREFETCH is the number of blobs that are pre-fetched by the blob listing api.
    # The blob list fetches blobs in pages, which are stored in memory. The main latency comes in to play
    # when it runs out of blobs in the page (in memory) and must make a round trip to the storage account
    # to gather more. Appropriate values for this setting will tend to be at least 2 or 3 times the
    # page size plus some buffer so we can hide the latency of these round trips to the storage account,
    # effectively staying out ahead of it.  If this value is too low, you'll notice that 'qsize' occasionally
    # reaches zero in the stats and 'blobwait' times start to drastically increase, indicating that
    # our thread which reads from the interprocess queue is blocked waiting for work.
    # - MAX_BLOBCACHE_QSIZE is how long the multprocessing.Queue can grow.  For efficiency, we put many
    # blobs in a batch when placing them on the interprocess queue because fewer large messages are
    # more efficient than many small messages, likely to decrease locking overhead.  There is probably
    # no need to adjust this.
    # - The number of IMPORT_WORKERS represents how may in-flight hsm_import requests we make
    # in parallel.  Base this on the latency of hsm_import calls.  If an hsm_import takes 1ms, and
    # we can send one every 100us, then we can likely keep 10 of them busy at once.  Having a few extras
    # threads sitting idle is OK, but testing has revealed that too many extras adds overhead in
    # interprocess communication and has a net effect of slowing things down.
    # - IMPORT_WORKERS_QUEUE_MAX represents how many hsm_import requests we allow to sit idle when
    # all workers are busy.  We want to maintain a healthy backlog of work, while at the same time
    # avoid hogging too many resources when worker processes get slow due to networking or lustre issues.
    # At a minimum, you want this to be several multiples of the IMPORT_WORKERS size as a buffer
    # so we don't leave idle worker processes.
    # - IMPORT_WORKERS_BATCH_SIZE controls how many files are sent to each worker in a batch.
    # The queue mechanism used by a multiprocessing Pool in python gains some efficiency if you send
    # more larger items rather than many small items over the queue.
    MAX_BLOBCACHE_PREFETCH = 12000
    MAX_BLOBCACHE_QSIZE = max(1, int(MAX_BLOBCACHE_PREFETCH / BlobAttrsBatch.MAX_BATCH_SIZE))
    IMPORT_WORKERS = 50
    IMPORT_WORKERS_QUEUE_MAX = int(IMPORT_WORKERS * 4)
    IMPORT_WORKERS_BATCH_SIZE = 20

    def __init__(self,
                 storage_acct,
                 container,
                 credential,
                 keyvault_name=None,
                 managed_identity_client_id=None,
                 keyvault_secret=False,
                 prefix="",
                 dest_path=".",
                 archive_id=HSMDefaults.ARCHIVEID,
                 err_file_name=ERR_FILE_NAME,
                 lemur=False,
                 resume_file_name="",
                 geneva_enable=False,
                 **kwargs):
        '''
        Constructor.
        '''
        kwargs.setdefault('log_fmt', self.LOG_FMT)
        super().__init__(**kwargs)
        self.storage_acct = storage_acct
        self.container = container
        self.credential = credential
        self.keyvault_secret = keyvault_secret
        self.keyvault_name = keyvault_name
        self.managed_identity_client_id_pre = managed_identity_client_id or laaso.scfg.msi_client_id_default
        self.managed_identity_client_id_post = None
        self.lemur = lemur
        self.prefix = prefix
        self.dest_path = dest_path
        self.archive_id = archive_id
        self.last_stats = 0
        self.geneva_enable = geneva_enable
        output_redact('kv_cred_or_item_id', self.credential)

        self.credential_val = None
        self.contexts = []
        self.stats_printer = None
        self.stats = HydratorStats()
        self.manager = None

        # A pointer to our blobcache subprocess and a queue that we will communicate over
        # Note: Also tried a pipe, but it can't hold a large enough backlog
        self.blobcache = None
        self.blobcache_queue = multiprocessing.Queue(maxsize=self.MAX_BLOBCACHE_QSIZE)

        # For managing our worker processes which call hsm_import
        self.import_workers = None
        self.import_workers_lock = threading.Lock()
        self.import_workers_cond = threading.Condition(lock=self.import_workers_lock)
        self.import_workers_reqs = 0
        self.import_workers_batch = FileImportWorkersBatch()  # Initial (empty) batch

        # File in Lustre where errors are logged
        self.err_file = None
        self.err_file_name = os.path.join(dest_path, err_file_name)

        # This data helps us to resume where we left off in case of a failure after a partial hydration.
        # The resume_timeline is an ordered dict of batch start times.
        # Whenever we complete the batch at the head of the ordered dict (oldest active batch), we save the
        # last blob name from the batch as a resume point.
        self.resume_file_name = resume_file_name
        self.resume_timeline = dict()

        # Save umask so we can revert it later
        self.old_umask = None
        self.myuid = os.getuid()
        self.mygid = os.getgid()

    @classmethod
    def main_add_parser_args(cls, ap_parser):
        '''
        Inherited from Application class.  Add parser args.
        '''
        super().main_add_parser_args(ap_parser)
        ap_parser.description = HYDRATOR_DESCRIPTION

        ap_parser.add_argument('storage_acct', type=str, help='storage account name')
        ap_parser.add_argument('container', type=str, help='container name within the storage account')
        ap_parser.add_argument('credential', type=str, help='storage key or SAS token (surround by quotes)')

        lemur_desc = '''
        Set this flag if you intend to use a copytool that is based on the Lustre open source lemur project.
        The flag causes hydrator.py to set extended attributes required by lemur-based copytools.
        This reduces performance of hydrator.py, but is necessary for the copytool.
        '''
        ap_parser.add_argument("-l", "--lemur", action="store_true", help=lemur_desc)
        ap_parser.add_argument("-p", "--prefix", type=str, default='', help='Prefix filter for the ingest.')
        ap_parser.add_argument("-a", "--dest_path", type=str, default='.', help='Import to this lustre directory, example: /mnt/lustre.  Default is cwd.')
        ap_parser.add_argument("-d", "--archive_id", type=int, default=HSMDefaults.ARCHIVEID, help='lustre hsm archive id to use with importing files, default=1')
        ap_parser.add_argument("-e", "--err_file_name", type=str, default=cls.ERR_FILE_NAME, help='Name of file to write errors in dest_path dir')
        ap_parser.add_argument("-r", "--resume_file_name", type=str, default='', help='File that can be used to write status so the hydrator can pick up where it left off in case the node suffers failures during the hydration.  By default this feature is turned off.')
        ap_parser.add_argument("-g", "--geneva_enable", action="store_true", help='push hydrator stats to geneva')

    @classmethod
    def main_handle_parser_args(cls, ap_args):
        '''
        see laaso.common.Application.main_handle_parser_args()
        '''
        super().main_handle_parser_args(ap_args)
        if ap_args.credential:
            output_redact("%s.credential" % cls.__name__, ap_args.credential)

    def clear_umask(self):
        '''
        Clears the umask so the hydrator can properly set permissions.
        '''
        self.old_umask = os.umask(0)

    def restore_umask(self):
        '''
        Restore the umask to the value that it was before we called clear_umask.
        '''
        if self.old_umask is not None:
            os.umask(self.old_umask)
            self.old_umask = None

    def main_execute(self):
        '''
        Main entry point.
        '''
        if sys.version_info <= (3, 7, 0):
            raise ApplicationExit("Python version 3.7 or higher is required to run this program.")
        self.go()
        raise ApplicationExit('Errors occurred during hydration.' if self.stats.general['errors'].get() else 0)

    def blobname2path(self, name):
        '''
        Prepend the lustre mount to the path.
        '''
        return os.path.join(self.dest_path, name)

    def do_chown(self, dbg, lustre_path, blob_attrs, default_uid, default_gid, created=False, force=False):
        '''
        Chown a file if the blob_attrs contain a valid uid or gid, using supplied defaults iff necessary.
        dbg - a debugging string to track the caller
        created - set to True if we created this file before calling the function (allows for perf optimization)
        '''
        if not blob_attrs:
            return
        if not blob_attrs.st_uid_valid and not blob_attrs.st_gid_valid:
            return
        uid = default_uid
        if blob_attrs.st_uid_valid:
            uid = blob_attrs.st_uid
        gid = default_gid
        if blob_attrs.st_gid_valid:
            gid = blob_attrs.st_gid
        if created and uid == self.myuid and gid == self.mygid:
            return  # no need to chown if we created the file and the desired uid and gid match our own
        if uid == default_uid and gid == default_gid and not force:
            return
        self.stats.extended['chown'].inc()
        self.logger.debug("CHOWN(%s): uid=%d gid=%d '%s'", dbg, uid, gid, lustre_path)
        try:
            os.chown(lustre_path, uid, gid, follow_symlinks=False)
        except FileNotFoundError:
            self.print_error(lustre_path, "unable to chown (file not found)")
        except OSError as exc:
            self.print_error(lustre_path, "unknown exception occurred during chown(uid=%d, gid=%d): %r", uid, gid, exc)

    def do_chmod(self, dbg, lustre_path, blob_attrs, check_mode=None):
        '''
        Chmod a file if the blob attrs contain valid mode bits and they don't match check_mode.
        dbg - a debugging string to track the caller
        check_mode - only do the chmod if the existing mode bits don't match these
        '''
        if not blob_attrs or not blob_attrs.st_mode_valid:
            return
        if check_mode and blob_attrs.st_mode == check_mode:
            return
        if blob_attrs.st_type == Ftypes.SYMLINK:
            return  # No chmod on symlnks (not supported)
        self.stats.extended['chmod'].inc()
        self.logger.debug("CHMOD(%s): mode=%s '%s'", dbg, oct(blob_attrs.st_mode), lustre_path)
        try:
            os.chmod(lustre_path, blob_attrs.st_mode)
        except FileNotFoundError:
            self.print_error(lustre_path, "unable to chmod (file not found)")
        except OSError as exc:
            self.print_error(lustre_path, "unknown exception occurred during chmod(mode=%s)': %r",
                             oct(blob_attrs.st_mode), exc)

    @staticmethod
    def do_lemur_xattrs(lustre_path, blob_attrs, container,
                        test=False, test_retry=False, test_fail=False):
        '''
        Set the xattrs for lemur if we are configured to do so.
        The xattrs are applied in parallel using the python threading interface.
        This function is typically called from the worker subprocess, but may also be
        called from the main process when comparing blobs to an existing file system.
        lustre_path        - the full path of the file in the filesystem.
        blob_attrs         - the attributes received from the blob read.
        container          - the container that we are hydrating from
        test*              - testing mode params to aid code coverage
        returns: LemurResults()
        '''
        if blob_attrs.st_type != Ftypes.FILE:
            return None # No xattr on symlinks, dirs, unknown (not supported)

        # Important - the lemur copytool requires the UUID xattr to be set for it to work.
        lemur_results = LemurResults()
        threads = list()
        for key_str, key_bytes, value_bytes in blob_attrs.get_lemur_xattrs(container):
            name = "{path} : {key}".format(path=lustre_path, key=key_str)
            th = threading.Thread(target=Hydrator.do_setxattr,
                                  args=(lustre_path, key_str, key_bytes,
                                        value_bytes, lemur_results, True,
                                        test, test_retry, test_fail,),
                                  name=name)
            th.start()
            threads.append(th)
        for th in threads:
            while True:
                th.join(timeout=60.0)
                if th.is_alive():
                    # Note: We are likely running in a subprocess. While printing to syslog isn't optimal,
                    # it's better than nothing.
                    syslog.syslog("hydrator: setxattr taking a long time: %s" % th.getName())
                else:
                    break
        return lemur_results

    @staticmethod
    def do_setxattr(lustre_path, key_str, key_bytes, value_bytes, lemur_results, create=True,
                    test=False, test_retry=False, test_fail=False):
        '''
        Utility function to set an xattr.
        This function is typically called from the worker subprocess, but may also be
        called from the main process when comparing blobs to an existing file system.
        lustre_path        - the full path of the file in the filesystem.
        key_str            - debugging string to help identify the xattr key being set
        key_bytes          - the bytes to set for the xattr key
        value_bytes        - the bytes to set for the xattr value
        lemur_results      - LemurResults() containing status of the operation
        create             - if true, attempt to create the xattr - otherwise replace.
        test*              - testing mode params to aid code coverage
        '''
        try:
            flag = os.XATTR_CREATE if create else os.XATTR_REPLACE
            if not test:
                # This is the normal path, so putting it first for readability
                os.setxattr(lustre_path, key_bytes, value_bytes, flag, follow_symlinks=False)
            else:
                # This path is used by pytest to help with code coverage.
                if test_retry or test_fail:
                    raise OSError("Exception raised by error injection, retry(%r), fail(%r)" % (test_retry, test_fail))
                print("LEMUR_TEST: setxattr %r:%r:%r, path %r" % (key_bytes, value_bytes, flag, lustre_path))
            lemur_results.setxattr_cnt += 1
        except OSError as exc:
            # The docs give one set of exception cases: https://docs.python.org/3.3/library/os.html#os.XATTR_CREATE
            # This ticket is new, and may or may not change anything: https://bugs.python.org/issue41277
            # We're covering both.
            if create:
                # We failed to create, let's try to replace.
                lemur_results.setxattr_retry += 1
                Hydrator.do_setxattr(lustre_path, key_str, key_bytes, value_bytes, lemur_results, create=False,
                                     test=test, test_retry=False, test_fail=test_fail)
            else:
                lemur_results.err_msg = "xattr(%s) %r" % (key_str, exc)
                lemur_results.err_tb = traceback.format_exc()
        except Exception as exc:
            # Generic exception handler so we can properly report unhandled/unexpected errors.
            # This function runs in a separate thread, so we don't want to miss anything.
            lemur_results.err_msg = "xattr(%s) %r" % (key_str, exc)
            lemur_results.err_tb = traceback.format_exc()

    def lemur_setxattr_results_handler(self, lustre_path, lemur_results):
        '''
        Common results handler for lemur setxattr to properly log errors and register stats.
        '''
        if not lemur_results:
            return
        if lemur_results:
            self.stats.extended['xattr'].add(lemur_results.setxattr_cnt)
            self.stats.extended['xattr_retry'].add(lemur_results.setxattr_retry)
            if lemur_results.err_msg:
                self.print_error(lustre_path,
                                 "File contents may not hydrate properly from the archive, error setting xattrs: %r, traceback:\n%s",
                                 lemur_results.err_msg, lemur_results.err_tb)
            else:
                self.logger.debug("SETXATTR: xattr_cnt(%d) retries(%d): %r",
                                  lemur_results.setxattr_cnt, lemur_results.setxattr_retry, lustre_path)

    @classmethod
    def do_stat(cls, lustre_path, blob_attrs):
        '''
        Common function for calling os.stat.  Returns the results of os.stat() if the file exists.
        Callers should be sure to catch exceptions, such as OSError, that a typical stat call may generate.
        '''
        try:
            if blob_attrs and blob_attrs.st_type == Ftypes.SYMLINK:
                stat_res = os.lstat(lustre_path)
            else:
                stat_res = os.stat(lustre_path)
            return stat_res
        except FileNotFoundError:
            pass
        except PermissionError as exc:
            raise ApplicationExit("Permission error performing stat operation, are you running as root? %r" % lustre_path) from exc
        return None

    def validate_existing(self, lustre_path, blob_attrs):
        '''
        Verify that a file exists and in Lustre and make sure that its attributes in Lustre match those in blob.
        lustre_path - path to the file or dir
        blob_attrs - the attributes that we want the directory to have
        Returns True if the file exists at the Lustre path. False if it does not.
        '''
        stat_res = self.do_stat(lustre_path, blob_attrs)
        if not stat_res:
            return False  # File does not exist.  Return False.
        if not blob_attrs:
            return True  # No attrs passed, so nothing else to check
        assert stat_res
        if not Ftypes.is_matching(blob_attrs.st_type, stat_res):
            # If we are trying to import a dir and there is an existing
            # file in Lustre, we will remove the file and proceed to import the dir.
            # If there is an existing dir in Lustre and we are trying to import a file, then we will
            # flag it as an error instead of attempting to delete the whole tree.
            self.stats.extended['wrong_ftype'].inc()
            if stat.S_ISDIR(stat_res.st_mode):
                self.print_error(lustre_path,
                                 "The path references a directory in Lustre, but a file is specified in the Azure storage account.")
                return True
            try:
                os.remove(lustre_path)
                self.print_error(lustre_path,
                                 "Removed existing file in Lustre and replacing it with a directory from the Azure storage account.")
            except OSError as exc:
                raise ApplicationExit("Error removing a conflicting file when a directory should be present at %r" % lustre_path) from exc
            return False
        if not blob_attrs.st_mode_valid and not blob_attrs.st_uid_valid and not blob_attrs.st_gid_valid:
            # No attrs that we care about were passed
            return True
        dbg = "ex"
        if blob_attrs.st_type == Ftypes.DIR:
            dbg += "d"
            self.stats.extended['stat_existing_dir'].inc()
        elif blob_attrs.st_type == Ftypes.FILE:
            dbg += "f"
            self.stats.extended['stat_existing_file'].inc()
        else:
            assert blob_attrs.st_type == Ftypes.SYMLINK
            dbg += "l"
            self.stats.extended['stat_existing_symlink'].inc()
        self.do_chmod(dbg, lustre_path, blob_attrs, stat_res.st_mode & BlobAttributes.ALL_MODE_BITS)
        self.do_chown(dbg, lustre_path, blob_attrs, stat_res.st_uid, stat_res.st_gid)
        if self.lemur:
            lemur_results = self.do_lemur_xattrs(lustre_path, blob_attrs, self.container)
            self.lemur_setxattr_results_handler(lustre_path, lemur_results)
        return True

    def try_validate_existing(self, lustre_path, blob_attrs):
        '''
        Wrapper validate_existing with a try-except to catch some known errors and
        gracefully return an error status.
        Returns a tuple of bools: (success, exists)
        '''
        exists = False
        try:
            exists = self.validate_existing(lustre_path, blob_attrs)
        except OSError as exc:
            self.print_error(lustre_path, "Error validating file or directory name: %r", exc)
            return False, False
        return True, exists

    def import_a_directory(self, lustre_path, blob_attrs):
        '''
        Create a new directory using the supplied attributes.
        We only set mode bits and uid/gid on directories.
        '''
        created = False
        self.stats.general['dirs'].inc()
        mode = BlobAttributes.DEFAULT_MODE_DIRS
        if blob_attrs and blob_attrs.st_mode_valid:
            mode = blob_attrs.st_mode
        self.logger.debug("MKDIR: mode=%s '%s'", oct(mode), lustre_path)
        dbg = "mkdir"
        try:
            os.makedirs(lustre_path, mode=mode)
            created = True
        except FileExistsError as exc:
            if os.path.isdir(lustre_path):
                # This can hapen if the children were created first using a makedirs and this
                # directory was created incidentally.
                self.stats.extended['mkdir_exists'].inc()
            else:
                raise ApplicationExit("Expected a directory, but found an existing file in Lustre at %r" % lustre_path) from exc
            self.do_chmod(dbg, lustre_path, blob_attrs)
        except OSError as exc:
            # Generic handler for unexpected cases.  Permissions problem?
            # It seems like we should exit if we can't create an entire portion of the tree.
            raise ApplicationExit("Unexpected error while creating directory '%s'" % lustre_path) from exc
        self.do_chown(dbg, lustre_path, blob_attrs, BlobAttributes.DEFAULT_UID, BlobAttributes.DEFAULT_GID, created=created, force=True)
        return created

    def import_a_symlink(self, lustre_path, blob_attrs):
        '''
        Import a symbolic link into the namespace.
        '''
        assert blob_attrs.st_type == Ftypes.SYMLINK
        self.stats.general['symlinks'].inc()
        created = False
        if blob_attrs.contents:
            self.logger.debug("CREATE(lnk): '%s'", lustre_path)
            try:
                os.symlink(blob_attrs.contents, lustre_path)
                created = True
            except FileExistsError:
                self.stats.extended['eexist_symlink'].inc()
                self.print_error(lustre_path, "symlink unexpectedly exists")
                # Future: What to do if the existing file is not a symlink or the link dest does not match?
                # fallthrough: symlink already exists, see if we need to chown it
            except FileNotFoundError:
                self.print_error(lustre_path, "could not import symlink (path not found)")
                return
            except OSError as exc:
                # Generic handler for other exceptions (what else can we expect here?)
                self.print_error(lustre_path, "exception while importing symlink with dest '%s': %r",
                                 blob_attrs.contents, exc)
                return
        else:
            self.print_error(lustre_path, "Could not import symbolic link with no contents")
            return
        dbg = "lnk"
        # No chmod for symlinks. Python doesn't support it and symlink mode bits are ignored anyway.
        self.do_chown(dbg, lustre_path, blob_attrs, BlobAttributes.DEFAULT_UID, BlobAttributes.DEFAULT_GID, created=created, force=True)

    def print_blob_warnings(self, blob_attrs):
        '''
        Print warnings that occurred while listing and reading the metadata from blob.
        '''
        for warning in blob_attrs.warnings:
            self.print_error(blob_attrs.name, "blob processing error: %s", warning)

    def write_to_hydration_errors_file(self, msg):
        '''
        Write an error message to the hydration errors file.
        '''
        try:
            if not self.err_file:
                self.err_file = open(self.err_file_name, 'a')
                if os.path.getsize(self.err_file_name) == 0:
                    self.err_file.write(self.ERR_FILE_HEADER + '\n')
            self.err_file.write(msg + '\n')
        except Exception as exc:
            raise ApplicationExit("Terminating due to exception while logging errors to the hydration errors file %r: %r" % (self.err_file_name, exc)) from exc

    def print_error(self, path, msg, *args):
        '''
        Log an error that occurred during the import process.
        '''
        msg_formatted = msg % args
        err_msg = "\"{path}\": {msg}".format(path=path, msg=msg_formatted)
        self.logger.error(err_msg)
        self.write_to_hydration_errors_file(err_msg)
        self.stats.general['errors'].inc()

    def context_switch(self, lustre_path, blob_attrs=None):
        '''
        Handle a directory [context] change.
        lustre_path - next directory that we intend to operate within
        blob_attrs - make sure the directory attributes match these attributes
        '''
        while True:
            context = self.contexts[-1]
            if context.path == lustre_path:
                # Switching back to a leaf dir that we previously created
                self.logger.debug("PATHUPD(1): '%s'", lustre_path)
                return
            if lustre_path.startswith(context.path):
                # Context is a parent
                break
            # Pop to parent dir
            if context.is_root:
                self.logger.warning("blob path '%s' is outside of root '%s'", lustre_path, context.path)
            assert not context.is_root   # Everything must be a subdir of root
            self.logger.debug("PATHPOP: '%s'", context.path)
            self.contexts.pop()
        context = self.contexts[-1]
        # Check if we need to create a new directory, or if it already exists.
        # If we created the parent directory, then we can skip the exists check.
        created = False
        exists = self.validate_existing(lustre_path, blob_attrs)
        if not exists:
            created = self.import_a_directory(lustre_path, blob_attrs)
        if created:
            self.logger.debug("PATHNEW: '%s'", lustre_path)
        else:
            # Switching back to an internal dir that we previously created
            self.logger.debug("PATHUPD(2): '%s'", lustre_path)
        self.contexts.append(Context(lustre_path, created))
        self.stats.progress['last_dir'].set(lustre_path)

    def try_context_switch(self, lustre_path, blob_attrs=None):
        '''
        Wrapper to context_switch() which catches specific exceptions
        and returns an error status.
        '''
        try:
            self.context_switch(lustre_path, blob_attrs)
        except OSError as exc:
            self.print_error(lustre_path, "Error importing a directory: %r, traceback:\n%s", exc, laaso.util.indent_exc())
            return False
        return True

    @staticmethod
    def get_attrs_to_import(blob_attrs):
        '''
        Return the mode, uid, gid that should be imported for the file based on the blob attributes.
        '''
        mode = blob_attrs.st_mode if blob_attrs.st_mode_valid else BlobAttributes.DEFAULT_MODE_FILES
        uid = blob_attrs.st_uid if blob_attrs.st_uid_valid else BlobAttributes.DEFAULT_UID
        gid = blob_attrs.st_gid if blob_attrs.st_gid_valid else BlobAttributes.DEFAULT_GID
        return mode, uid, gid

    @staticmethod
    def import_workers_batch_process(workers_batch):
        '''
        Main driver for importing files in the worker subprocess.
        Iterate over the batch, calling hsm_import on each file.
        This is called from inside of the worker subprocess.
        '''
        try:
            lemur_params = workers_batch.lemur_params
            for work in workers_batch.work:
                work.import_results = Hydrator.import_a_file(work.lustre_path, work.blob_attrs, work.archive_id)
                if lemur_params:
                    work.lemur_results = Hydrator.do_lemur_xattrs(work.lustre_path, work.blob_attrs,
                                                                  lemur_params.container)
        except Exception as exc:
            # Fill in results for any work that we could not complete
            for work in workers_batch.work:
                if not work.import_results:
                    work.import_results = FileImportResults(err_msg=repr(exc), err_tb=traceback.format_exc())
        return workers_batch

    @staticmethod
    def import_a_file(lustre_path, blob_attrs, archive_id):
        '''
        Import a file into Lustre by calling hsm_import.
        This is called from inside of the worker subprocess.
        '''
        try:
            mode, uid, gid = Hydrator.get_attrs_to_import(blob_attrs)
            hsmimport = HSMImport(abspath=lustre_path, mode=mode, uid=uid, gid=gid,
                                  size=blob_attrs.st_size,
                                  mtime=blob_attrs.st_mtim,
                                  archiveid=archive_id)
            fid_out = CLustreFid()
            rc = hsmimport.do_it(fid_out)
            return FileImportResults(uid=uid, gid=gid, mode=mode, rc=rc, fid_out=fid_out)
        except Exception as exc:
            return FileImportResults(err_msg=repr(exc), err_tb=traceback.format_exc())

    def import_workers_batch_cb(self, workers_batch):
        '''
        Callback executed after an entire batch of files is imported.
        Execute the per-file callback function to process the results for each file.
        '''
        try:
            for work in workers_batch.work:
                self.import_a_file_cb(work)
                self.lemur_setxattr_cb(work)
        except Exception as exc:
            self.print_error("Internal", "Exception occurred while processing import results: %r\n%s",
                             exc, traceback.format_exc())
        finally:
            self.dec_worker_req_count()
            self.remove_from_resume_timeline(workers_batch)
        self.stats.threading['batch_count'].inc()
        self.stats.timing['batch_latency'].add(time.monotonic() - workers_batch.start)

    def import_a_file_cb(self, work):
        '''
        Callback executed for each file in the batch imported by the workers so we can handle status.
        '''
        res = work.import_results
        if res.rc > 0:
            self.print_error(work.lustre_path, "Lustre hsm_import error mode=%s, uid=%d, gid=%d, size=%d rc=%d",
                             oct(res.mode), res.uid, res.gid, work.blob_attrs.st_size, res.rc)
        elif res.err_msg:
            self.print_error(work.lustre_path, "Exception '%s' occurred while importing file:\n%s",
                             res.err_msg, res.err_tb)
        else:
            self.stats.progress['last_file'].set(work.lustre_path)
            self.stats.general['size'].add(work.blob_attrs.st_size)
            self.stats.general['files'].inc()
            self.logger.debug("IMPORT(file): mode=%s uid=%d gid=%d fid=[0x%x:0x%x:0x%x] '%s'",
                              oct(res.mode), res.uid, res.gid,
                              res.fid_out.f_seq, res.fid_out.f_oid, res.fid_out.f_ver,
                              work.lustre_path)

    def lemur_setxattr_cb(self, work):
        '''
        Callback executed for each file in the batch to handle lemur xattr results.
        '''
        self.lemur_setxattr_results_handler(work.lustre_path, work.lemur_results)

    def dec_worker_req_count(self):
        '''
        Decrement the number of outstanding workers.
        '''
        with self.import_workers_cond:
            assert self.import_workers_reqs
            self.import_workers_reqs -= 1
            if self.import_workers_reqs <= self.IMPORT_WORKERS_QUEUE_MAX:
                self.import_workers_cond.notify()
            self.stats.threading['active'].set(self.import_workers_reqs)

    def inc_worker_req_count(self):
        '''
        Increment the request count. May block if we're above the global limit.
        '''
        with self.import_workers_cond:
            self.import_workers_reqs += 1
            self.stats.threading['active'].set(self.import_workers_reqs)
            while self.import_workers_reqs > self.IMPORT_WORKERS_QUEUE_MAX:
                self.stats.threading['throttled'].inc()
                self.import_workers_cond.wait(timeout=5.0)

    def init_blobcache(self):
        '''
        Initialize the blobcache.
        '''
        self.blobcache = BlobCache(self.blobcache_queue,
                                   self.manager.subscription_id,
                                   self.storage_acct,
                                   self.container,
                                   self.credential_val,
                                   self.manager,
                                   prefix=self.prefix)

    def manager_kwargs(self, **kwargs):
        '''
        See laaso.Application.manager_kwargs()
        '''
        ret = super().manager_kwargs()
        if self.managed_identity_client_id_post:
            ret['managed_identity_client_id'] = self.managed_identity_client_id_post
        return ret

    @classmethod
    def init_liblustreapi(cls):
        '''
        Initialize our interface to lustre.
        '''
        LibLustreApi.init_once()

    def init_azure(self):
        '''
        Initialize interactions with Azure
        '''
        bootstrap_mgr = self.MANAGER_CLASS(**self.manager_kwargs())
        self.managed_identity_client_id_post = laaso.identity.client_id_from_uami_str(self.managed_identity_client_id_pre, bootstrap_mgr)
        if not self.managed_identity_client_id_post:
            raise ApplicationExit(f"cannot resolve managed_identity_client_id {self.managed_identity_client_id_pre!r}")
        self.manager = self.MANAGER_CLASS(**self.manager_kwargs())

    def init_creds(self):
        '''
        Initialize our credentials from the keyvault if necessary.
        '''
        if self.keyvault_secret:
            try:
                client_id = self.managed_identity_client_id_post
                self.credential_val = self.manager.keyvault_secret_get(keyvault_name=self.keyvault_name, secret_name=self.credential, client_id=client_id).value
                self.logger.debug("Acquired Managed Identity for client_id %r", self.managed_identity_client_id_post)
            except ResourceNotFoundError as exc:
                raise ApplicationExit("Could not fetch secret '%s' from keyvault %s" % (self.credential, self.keyvault_name)) from exc
            except Exception as exc:
                raise ApplicationExit("Could not fetch secret '%s' from keyvault %s" % (self.credential, self.keyvault_name)) from exc
        else:
            self.credential_val = self.credential

    def init_stats(self):
        '''
        Initialize stats from our resume point, if necessary.
        '''
        self.stats.get_resume_point(self.resume_file_name, self.storage_acct, self.container, self.prefix)

    def get_next_blob_batch(self):
        '''
        Read the next blob from the blobcache queue.
        '''
        obj = None
        while True:
            try:
                start = time.monotonic()
                msg = self.blobcache_queue.get(timeout=3.0)
                end = time.monotonic()
                self.stats.timing['blobcache_latency'].add(end-start)
                obj = pickle.loads(msg)
                break
            except queue.Empty:
                self.stats.threading['blobcache_qempty'].inc()
                if not self.blobcache.is_alive():
                    # This is unexpected.
                    # The blobcache should have at least sent its term pill
                    self.print_error("Internal", "BlobCache terminated unexpectedly (no traceback available)")
                    break
        self.stats.threading['blobcache_qsize'].set(self.blobcache_queue.qsize())
        if isinstance(obj, BlobCacheTermPill):
            # BlobCache hit an exception and terminated
            pill = obj
            self.print_error("Internal", "BlobCache terminated unexpectedly with exception '%s', traceback:\n%s",
                             pill.error_msg, pill.error_tb)
            return None
        assert isinstance(obj, BlobAttrsBatch)
        return obj

    def add_to_resume_timeline(self, workers_batch):
        '''
        Add a batch to our resume timeline.
        '''
        self.resume_timeline[workers_batch.start] = workers_batch

    def remove_from_resume_timeline(self, workers_batch):
        '''
        Remove the batch from the timeline of outstanding batches.
        Call this when we're done processing a batch.
        If this is the oldest batch, it will be at the head of the dict ordering, and we update
        our resume point using this blob name.
        Note: This feature relies on dict() keys maintaining insertion order when you
        iterate over them. This only works with Python3.7 and later.
        Previously, an OrderedDict was required.
        '''
        assert self.resume_timeline.get(workers_batch.start)
        # next(iter(mydict)) seems to be the fastest way to get the first key
        if next(iter(self.resume_timeline)) == workers_batch.start:
            # This is the head/oldest batch.  Use it to record our resume point.
            if workers_batch.work[-1].blob_attrs:
                self.stats.progress['resume_blob'].set(workers_batch.work[-1].blob_attrs.name)
        del self.resume_timeline[workers_batch.start]

    def send_to_workers(self, lustre_path, blob_attrs):
        '''
        Add more work to the current workers_batch so it can be deployed to the workers.
        If the current workers_batch is full, then flush it.
        '''
        self.import_workers_batch.append(FileImportWork(lustre_path, blob_attrs, self.archive_id))
        if len(self.import_workers_batch.work) >= self.IMPORT_WORKERS_BATCH_SIZE:
            self.flush_workers_batch()

    def flush_workers_batch(self):
        '''
        Send the current workers_batch to the workers.
        Reinitialize to prepare for the next workers_batch.
        '''
        workers_batch = self.import_workers_batch
        if not workers_batch.work:
            return # nothing to flush
        self.inc_worker_req_count() # blocks if there is too much work outstanding
        if self.lemur:
            workers_batch.lemur_params = LemurParams(self.container)
        self.add_to_resume_timeline(workers_batch)
        self.import_workers.apply_async(self.import_workers_batch_process,
                                        (workers_batch,),
                                        callback=self.import_workers_batch_cb)
        self.import_workers_batch = FileImportWorkersBatch()  # New empty batch

    def go(self):
        '''
        Initialize the hydration process.
        This is a wrapper around the main routine to make sure we handle initializing
        and shutdown steps properly in case there are exceptions.
        '''
        complete = False
        try:
            self.init_liblustreapi()
            self.init_azure()
            self.init_creds()
            self.init_stats()
            self.clear_umask()

            self.stats_printer = PeriodicStatsPrinter(self.stats, self.logger, self.STATS_FREQ_SEC, self.resume_file_name,
                                                      self.storage_acct, self.container, self.prefix, self.geneva_enable)
            self.stats_printer.start()

            self.stats.timing['start'].set(time.time())
            self.stats.timing['start_mono'].set(time.monotonic())
            if self.stats.progress['resume_blob'].get():
                self.logger.info("Hydrator resuming from blob %r error count %d at %s",
                                 self.stats.progress['resume_blob'].get(),
                                 self.stats.general['errors'].get(),
                                 datetime.datetime.fromtimestamp(self.stats.timing['start'].get()))
            else:
                self.logger.info("Hydrator starting at %s",
                                 datetime.datetime.fromtimestamp(self.stats.timing['start'].get()))
            self.logger.info("Account(%s) Container(%s) Prefix(%s) LustrePath(%s)",
                             self.storage_acct, self.container, self.prefix, self.dest_path)

            self.import_workers = multiprocessing.Pool(self.IMPORT_WORKERS)

            self.init_blobcache()
            self.blobcache.start()

            self.go_internal()  # Start main routine
            complete = True
        finally:
            # Shutdown steps.  Try to unwind them in the opposite order as above.
            if self.blobcache:
                if self.blobcache.is_alive():
                    self.blobcache.terminate()
                self.blobcache.join()

            if self.import_workers:
                self.import_workers.close()
                self.import_workers.join()  # Note: No timeout param available, if workers are stuck this could get stuck here

            # Our resume timeline should be flushed/empty if we completed our walk through the blob list
            if complete:
                assert not self.resume_timeline

            self.stats.timing['end'].set(time.time())
            if self.stats_printer:
                self.stats_printer.stop()
                self.stats_printer.print_now()
            now = time.monotonic()
            self.logger.info("Hydration complete at %s, elapsed: %.2fs, %d errors.",
                             datetime.datetime.fromtimestamp(self.stats.timing['end'].get()),
                             now - self.stats.timing['start_mono'].get(),
                             self.stats.general['errors'].get())

            if self.resume_file_name and os.path.exists(self.resume_file_name):
                try:
                    os.remove(self.resume_file_name)
                except OSError as exc:
                    self.logger.error("Hydration complete, but there was an error deleting resume file %r: %r",
                                      self.resume_file_name, exc)
            if self.err_file:
                self.err_file.close()
                self.err_file = None
            self.restore_umask()

    def go_internal(self):
        '''
        Main routine for running the import process.
        Loop over blobs, create corresponding files and dirs in Lustre.
        '''
        # Create and setup the root directory context
        context = Context(self.dest_path)
        context.is_root = True
        if self.dest_path:
            exists = os.path.isdir(self.dest_path)
            if not exists:
                context.created = True
                try:
                    os.makedirs(self.dest_path, mode=BlobAttributes.DEFAULT_MODE_DIRS)
                except OSError as exc:
                    raise ApplicationExit("Error creating destination path %r: %r" % (self.dest_path, exc)) from exc
        self.contexts.append(context)

        # Main loop for looping over the blobs and importing them
        done = False
        while not done:
            context = self.contexts[-1]
            # Get the next blob, deal with any warnings
            blob_batch = self.get_next_blob_batch()
            if not blob_batch:
                break  # done, blobcache hit an error
            for blob_attrs in blob_batch.contents:
                if not blob_attrs:
                    done = True
                    break # processed all blobs
                self.stats.general['blobs'].inc()
                lustre_path = self.blobname2path(blob_attrs.name)
                if len(lustre_path) > BlobAttributes.PATH_MAX:
                    self.print_error(lustre_path, "cannot import blob since it will exceed PATH_MAX(%d)", BlobAttributes.PATH_MAX)
                    continue
                dirpath = os.path.dirname(lustre_path)
                if blob_attrs.warnings:
                    self.print_blob_warnings(blob_attrs)
                # Handle directory, file, or symlink
                if blob_attrs.st_type == Ftypes.DIR:
                    self.try_context_switch(lustre_path, blob_attrs)
                    continue
                assert blob_attrs.st_type in (Ftypes.FILE, Ftypes.SYMLINK)
                if dirpath != context.path:
                    if not self.try_context_switch(dirpath):
                        continue
                    context = self.contexts[-1]
                if not context.created:
                    success, exists = self.try_validate_existing(lustre_path, blob_attrs)
                    if not success:
                        continue
                    if exists:
                        continue
                if blob_attrs.st_type == Ftypes.SYMLINK:
                    self.import_a_symlink(lustre_path, blob_attrs)
                else:
                    assert blob_attrs.st_type == Ftypes.FILE
                    self.send_to_workers(lustre_path, blob_attrs)
            # Check if this batch sent us over the max errors
            if self.stats.general['errors'].get() > self.MAX_ERRORS:
                raise ApplicationExit("Hydration terminating due to too many errors(%d), see '%s' for more details." %
                                      (self.MAX_ERRORS, self.err_file_name))
        self.flush_workers_batch() # flush any outstanding work

if __name__ == "__main__":
    Hydrator.main(sys.argv[1:])
    raise SystemExit(1)

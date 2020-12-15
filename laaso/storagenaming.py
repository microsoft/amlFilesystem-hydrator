#
# laaso/storagenaming.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Support for naming "things" in Azure storage.
'''
import functools
import re
import urllib.parse
import uuid

from laaso.azresourceid import RE_STORAGE_ACCOUNT_ABS
from laaso.exceptions import ContainerNameInvalidException
from laaso.util import RE_UUID_ABS

@functools.total_ordering
class StorageAccountName():
    '''
    Logical storage account name .
    Carries an optional subscription_id.
    String representations:
        SUBSCRIPTION_ID:storage_account
        storage_account

    Be careful about using StorageAccountName as a set member or a dict key.
    Changing the subscription_id changes the equality relationship
    and hash value.
    '''
    def __init__(self, storage_account_name, subscription_id=None):
        if isinstance(storage_account_name, str):
            tmp = storage_account_name.split(':')
            if len(tmp) == 1:
                self._subscription_id = subscription_id
                self._storage_account_name = storage_account_name
            elif len(tmp) == 2:
                if tmp[0]:
                    if subscription_id and (tmp[0] != subscription_id):
                        raise ValueError("%s() inconsistent subscription_id" % type(self).__name__)
                    self._subscription_id = tmp[0]
                else:
                    raise ValueError("%s() cannot parse %r" % (type(self).__name__, storage_account_name))
                self._storage_account_name = tmp[1]
            else:
                raise ValueError("%s() cannot parse %r" % (type(self).__name__, storage_account_name))
        elif isinstance(storage_account_name, type(self)):
            if storage_account_name.subscription_id:
                if subscription_id and (subscription_id != storage_account_name.subscription_id):
                    raise ValueError("%s() inconsistent subscription_id" % type(self).__name__)
                self._subscription_id = storage_account_name.subscription_id
            else:
                self._subscription_id = subscription_id
            self._storage_account_name = storage_account_name.storage_account_name
        else:
            raise TypeError("%s(): storage_account_name has unexpected type %s" % (type(self).__name__, type(storage_account_name)))

        if not isinstance(self._subscription_id, (type(None), str)):
            raise TypeError("%s() subscription_id type %s is not str or None" % (type(self).__name__, type(self._subscription_id)))
        if self._subscription_id:
            if not RE_UUID_ABS.search(self._subscription_id):
                raise ValueError("subscription_id %r is not a UUID" % self._subscription_id)
            self._subscription_id = self._subscription_id.lower()
        else:
            # No empty str
            self._subscription_id = None

        if not isinstance(self._storage_account_name, str):
            raise TypeError("storage_account_name must be str, not %s" % type(self._storage_account_name))
        if not RE_STORAGE_ACCOUNT_ABS.search(self._storage_account_name):
            raise ValueError("storage_account_name %r" % self._storage_account_name)

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, self.__str__())

    def __str__(self):
        tmp = self._subscription_id
        if tmp:
            return tmp + ':' + self._storage_account_name
        return self._storage_account_name

    def _subscription_id_eq(self, other):
        '''
        Perform type-independent equality for subscription_id.
        '''
        if self._subscription_id:
            if not other.subscription_id:
                return False
            return self._subscription_id == other.subscription_id
        return not bool(other.subscription_id)

    def _subscription_id_lt(self, other):
        '''
        Perform type-independent less-than for subscription_id.
        '''
        if self._subscription_id:
            if not other.subscription_id:
                return False
            return self._subscription_id < other.subscription_id
        return bool(other.subscription_id)

    def _subscription_id_gt(self, other):
        '''
        Perform type-independent greater-than for subscription_id.
        '''
        if self._subscription_id:
            if not other.subscription_id:
                return True
            return self._subscription_id > other.subscription_id
        return False

    def _eq(self, other):
        '''
        Perform type-independent equality checks. Do not call this
        directly; only call it through the data model compare ops.
        The caller is responsible for type checks.
        '''
        if not self._subscription_id_eq(other):
            return False
        return self._storage_account_name == other.storage_account_name

    def _lt(self, other):
        '''
        Perform type-independent less-than checks. Do not call this
        directly; only call it through the data model compare ops.
        The caller is responsible for type checks.
        '''
        if self._subscription_id_lt(other):
            return True
        return self._storage_account_name < other.storage_account_name

    def _gt(self, other):
        '''
        Perform type-independent greater-than checks. Do not call this
        directly; only call it through the data model compare ops.
        The caller is responsible for type checks.
        '''
        if self._subscription_id_gt(other):
            return True
        return self._storage_account_name > other.storage_account_name

    def __eq__(self, other):
        if not isinstance(other, StorageAccountName): # not type(self) - checking here if we are part of the correct hierarchy
            return NotImplemented
        if not self._eq(other):
            return False
        if not (isinstance(self, type(other)) and isinstance(other, type(self))):
            return False
        return self._eq(other)

    def __lt__(self, other):
        if not isinstance(other, StorageAccountName): # not type(self) - checking here if we are part of the correct hierarchy
            return NotImplemented
        if self._lt(other):
            return True
        if self._gt(other):
            return False
        if isinstance(self, type(other)):
            # We are the same class as other or a subclass
            if isinstance(other, type(self)):
                # same class as other - we are equal
                return False
            # We are strictly a subclass of other
            return False
        # other is a superclass of us
        return True

    def __gt__(self, other):
        if not isinstance(other, StorageAccountName): # not type(self) - checking here if we are part of the correct hierarchy
            return NotImplemented
        if self._gt(other):
            return True
        if self._lt(other):
            return False
        if isinstance(self, type(other)):
            # We are the same class as other or a subclass
            if isinstance(other, type(self)):
                # same class as other - we are equal
                return False
            # We are strictly a subclass of other
            return True
        # other is a superclass of us
        return False

    def __hash__(self):
        return hash(str(self))

    @property
    def subscription_id(self):
        '''
        Getter
        '''
        tmp = self._subscription_id
        if not tmp:
            return None
        return tmp

    @subscription_id.setter
    def subscription_id(self, value):
        '''
        Setter for subscription_id. Be careful - this changes the hash value
        and equality relationship.
        '''
        if not isinstance(value, (type(None), str, uuid.UUID)):
            raise TypeError("subscription_id must be None, str, or UUID, not %s" % type(value))
        if not value:
            self._subscription_id = None
            return
        m = RE_UUID_ABS.search(str(value))
        if not m:
            raise ValueError("invalid subscription_id %r" % value)
        self._subscription_id = m.group(0).lower()

    @property
    def storage_account_name(self):
        '''
        Getter
        '''
        return self._storage_account_name

@functools.total_ordering
class ContainerName(StorageAccountName):
    '''
    Logical container name - storage_account, container tuple.
    Carries an optional subscription_id.
    String representations:
        SUBSCRIPTION_ID:storage_account/container
        storage_account/container

    Be careful about using ContainerName as a set member or a dict key.
    Changing the subscription_id changes the equality relationship
    and hash value.
    '''
    def __init__(self, *args, subscription_id=None):
        if not args:
            raise TypeError("%s() missing required positional argument(s)" % type(self).__name__)
        if len(args) == 1:
            if isinstance(args[0], str):
                arg = args[0]
                tmp = arg.split('/')
                if len(tmp) != 2:
                    raise ValueError("%s() cannot parse %r" % (type(self).__name__, arg))
                super().__init__(tmp[0], subscription_id=subscription_id)
                self._container_name = tmp[1]
                args = tmp
            elif isinstance(args[0], type(self)):
                other = args[0]
                super().__init__(other, subscription_id=subscription_id)
                self._container_name = other._container_name
            else:
                raise TypeError("%s: cannot be constructed from %s" % (type(self).__name__, type(args[0])))
        elif len(args) == 2:
            super().__init__(args[0], subscription_id=subscription_id)
            self._container_name = args[1]
        else:
            raise TypeError("%s() takes 1 or 2 positional arguments but %d were given" % (type(self).__name__, len(args)))

        if not isinstance(self._container_name, str):
            raise TypeError("container_name must be str, not %s" % type(self._container_name))
        if not self.CN_RE.search(self._container_name):
            # https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules#microsoftstorage
            raise ContainerNameInvalidException("container_name (invalid) (%r)" % self._container_name)
        if self._container_name.find('--') >= 0:
            raise ContainerNameInvalidException('container_name (contains --)')

    # CN_RE is not global because it is necessary but not sufficient
    CN_RE = re.compile(r'^[a-z0-9][a-z0-9-]{2,62}$')

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, self.__str__())

    def __str__(self):
        tmp = self._subscription_id
        if tmp:
            return tmp + ':' + self._storage_account_name + '/' + self._container_name
        return self._storage_account_name + '/' + self._container_name

    def _eq(self, other):
        '''
        See StorageAccountName._eq
        '''
        if not super()._eq(other):
            return False
        try:
            return self._container_name == other.container_name
        except AttributeError:
            return False

    def _lt(self, other):
        '''
        See StorageAccountName._lt
        '''
        if super()._lt(other):
            return True
        if super()._gt(other):
            return False
        try:
            return self._container_name < other.container_name
        except AttributeError:
            return False

    def _gt(self, other):
        '''
        See StorageAccountName._gt
        '''
        if super()._gt(other):
            return True
        if super()._lt(other):
            return False
        try:
            return self._container_name > other.container_name
        except AttributeError:
            return True

    @property
    def container_name(self):
        '''
        Getter
        '''
        return self._container_name

@functools.total_ordering
class BlobName(ContainerName):
    '''
    Logical blob name - storage_account, container, blob tuple.
    Carries an optional subscription_id.
    String representations:
        SUBSCRIPTION_ID:storage_account/container/blob_name
        storage_account/container/blob_name

    Be careful about using BlobName as a set member or a dict key.
    Changing the subscription_id changes the equality relationship
    and hash value.
    '''
    def __init__(self, *args, subscription_id=None):
        if not args:
            raise TypeError("%s() missing required positional argument(s)" % type(self).__name__)
        if len(args) == 1:
            if isinstance(args[0], str):
                tmp = args[0].split('/')
                if len(tmp) < 3:
                    raise ValueError("%s() cannot parse %r" % (type(self).__name__, args[0]))
                super().__init__(tmp[0], tmp[1], subscription_id=subscription_id)
                self._blob_name = '/'.join(tmp[2:])
            elif isinstance(args[0], type(self)):
                other = args[0]
                super().__init__(other, subscription_id=subscription_id)
                self._blob_name = other.blob_name
            else:
                raise TypeError("%s: cannot be constructed from %s" % (type(self).__name__, type(args[0])))
        elif len(args) == 3:
            super().__init__(args[0], args[1], subscription_id=subscription_id)
            self._blob_name = args[2]
        else:
            raise TypeError("%s() takes 1 or 3 positional arguments but %d were given" % (type(self).__name__, len(args)))

        if not isinstance(self._blob_name, str):
            raise TypeError("blob_name must be str, not %s" % type(self._blob_name))
        if not self._blob_name:
            raise ValueError('blob_name (empty)')
        if len(self.blob_name_quoted) > 1024:
            raise ValueError('blob_name (too long)')

    def __str__(self):
        tmp = self._subscription_id
        if tmp:
            return tmp + ':' + self._storage_account_name + '/' + self._container_name + '/' + self._blob_name
        return self._storage_account_name + '/' + self._container_name + '/' + self._blob_name

    def _eq(self, other):
        '''
        See StorageAccountName._eq
        '''
        if not super()._eq(other):
            return False
        try:
            return self._blob_name == other.blob_name
        except AttributeError:
            return False

    def _lt(self, other):
        '''
        See StorageAccountName._lt
        '''
        if super()._lt(other):
            return True
        if super()._gt(other):
            return False
        try:
            return self._blob_name < other.blob_name
        except AttributeError:
            return False

    def _gt(self, other):
        '''
        See StorageAccountName._gt
        '''
        if super()._lt(other):
            return False
        if super()._gt(other):
            return True
        try:
            return self._blob_name > other.blob_name
        except AttributeError:
            return True

    @property
    def blob_name(self):
        '''
        Getter
        '''
        return self._blob_name

    @property
    def blob_name_quoted(self):
        '''
        Getter
        '''
        return urllib.parse.quote(self._blob_name)

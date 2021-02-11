#
# laaso/dev_users.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Define properties of development users.
Never install this anywhere.
'''
import re
import threading
import uuid

import laaso
from laaso.base_defaults import EXC_VALUE_DEFAULT
from laaso.btypes import ReadOnlyDict
from laaso.exceptions import DevUserUnknownException

class DevUser():
    '''
    Represents a LaaSO development user.
    Application and managed identities are not here.
    '''
    def __init__(self,
                 build_agent_admin=False,
                 jumphost=False,
                 jumphost_root=False,
                 kv_admin_cert=False,
                 kv_admin_key=False,
                 kv_admin_secret=False,
                 mocked=False,
                 rg_add_users=False,
                 vm_devel_admin=False,
                 exc_value=EXC_VALUE_DEFAULT,
                 **kwargs):
        for k in ('name', 'uid'):
            if k not in kwargs:
                raise exc_value(f"{k!r} not specified")
        self._build_agent_admin = build_agent_admin
        self._jumphost = jumphost
        self._jumphost_root = jumphost_root
        self._mocked = mocked # for testing
        self._kv_admin_cert = kv_admin_cert
        self._kv_admin_key = kv_admin_key
        self._kv_admin_secret = kv_admin_secret
        self._name = kwargs.pop('name')
        self._rbac = kwargs.pop('rbac', list()) # not fully validated here
        self._rg_add_users = rg_add_users
        self._uid = kwargs.pop('uid')
        self._vm_devel_admin = vm_devel_admin

        ck = set(self._RO_ATTRS)
        ck.remove('ad_user')
        ck.remove('kv_user')
        ck.remove('owner_allowed')

        try:
            val = kwargs.pop('kv_user')
            if not isinstance(val, bool):
                raise exc_value("'kv_user' expected bool, not %s" % type(val))
            self._kv_user = val
        except KeyError:
            self._kv_user = bool(jumphost) or bool(rg_add_users)

        # integers
        # check uid first because gid is derived from uid
        for k in ('uid', 'gid',):
            val = getattr(self, k)
            if not isinstance(val, int):
                raise exc_value("%r expected int, not %s" % (k, type(val)))
            ck.remove(k)

        # strings
        for k in ('name',):
            val = getattr(self, k)
            if not isinstance(val, str):
                raise exc_value("%r expected str, not %s" % (k, type(val)))
            ck.remove(k)

        # lists
        for k in ('rbac',):
            val = getattr(self, k)
            if not isinstance(val, list):
                raise exc_value("%r expected list, not %s" % (k, type(val)))
            ck.remove(k)

        # everything else is bool
        for k in ck:
            val = getattr(self, k)
            if not isinstance(val, bool):
                raise exc_value("%r expected bool, not %s" % (k, type(val)))

        if self.uid < 0:
            raise exc_value("invalid uid=%r for %r" % (self.uid, self))

        if not self.NAME_RE.search(self._name):
            raise exc_value(f"invalid {type(self).__name__} name {self._name!r}")
        for name in self.NAMES_RESERVED:
            if self._name.lower() == name.lower():
                raise exc_value(f"may not use reserved {type(self).__name__} name {self._name!r}")

        if 'ad_user' in kwargs:
            ad_user = kwargs.pop('ad_user')
            if ad_user is None:
                self._ad_user = None
            elif isinstance(ad_user, str):
                toks = ad_user.split('@')
                if (len(toks) != 2) or (not all(toks)):
                    raise exc_value("invalid ad_user %r for %r" % (ad_user, self))
                self._ad_user = ad_user
            else:
                raise exc_value("unexpected type %s for %r" % (type(ad_user), self))
        else:
            self._ad_user = self.name + '@microsoft.com'

        # Active Directory users are always allowed to be owners.
        # If a valid active directory user is set - allow it to be
        # owner.
        if 'owner_allowed' in kwargs:
            owner_allowed = kwargs.pop('owner_allowed')
            if not isinstance(owner_allowed, bool):
                raise exc_value("'owner_allowed' expected bool, not %s" % type(owner_allowed))
            self._owner_allowed = owner_allowed
        else:
            self._owner_allowed = self._ad_user is not None

        if kwargs:
            raise TypeError("unexpected keyword arguments %s" % ','.join(kwargs.keys()))

    NAME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9-]{0,23}$')

    NAMES_RESERVED = ('example', # to avoid problems with src/config/example.yaml
                      'create_sampler', # to avoid problems with src/config/create_sampler.yaml
                      'testing_subscriptions', # to avoid problems with src/config/testing_subscriptions.yaml
                     )

    _RO_ATTRS = frozenset(('ad_user',
                           'build_agent_admin',
                           'gid',
                           'jumphost',
                           'jumphost_root',
                           'kv_admin_cert',
                           'kv_admin_key',
                           'kv_admin_secret',
                           'kv_user',
                           'mocked',
                           'name',
                           'owner_allowed',
                           'rbac',
                           'rg_add_users',
                           'uid',
                           'vm_devel_admin',
                          ))

    def __repr__(self):
        return f'<{type(self).__module__}.{type(self).__name__},{self._uid},{self._name!r}>'

    def __getattr__(self, name):
        if name in self._RO_ATTRS:
            return getattr(self, '_'+name)
        raise AttributeError("%s has no such attribute %r" % (type(self).__name__, name))

    def __setattr__(self, name, value):
        if name in self._RO_ATTRS:
            raise AttributeError("%s does not support setting %r" % (type(self).__name__, name))
        super().__setattr__(name, value)

    def __getitem__(self, name):
        '''
        Implement subscripting for compatibility with previous API
        '''
        if name in self._RO_ATTRS:
            return getattr(self, name)
        raise KeyError(name)

    def __contains__(self, name):
        return name in self._RO_ATTRS

    @property
    def gid(self):
        '''
        Getter for GID (Group ID).
        '''
        # At this time, GID is always the same as UID.
        return self._uid

    _devusers_lock = threading.RLock()
    _devusers_data = None # tuple of DevUser
    _devusers_byname = None # becomes a readonly dict of name.lower() -> DevUser
    _devusers_names = None # becomes sorted tuple of str

    @classmethod
    def reset(cls):
        '''
        Discard cached data. Useful for unit testing.
        '''
        with cls._devusers_lock:
            cls._devusers_data = None
            cls._devusers_byname = None
            cls._devusers_names = None

    @classmethod
    def _load_iff_necessary(cls, exc_value=EXC_VALUE_DEFAULT):
        '''
        Load data iff not already loaded
        '''
        with cls._devusers_lock:
            if cls._devusers_data is None:
                try:
                    cls._load_and_index(laaso.paths.subscription_config_filename, laaso.paths.subscription_config_data, exc_value=exc_value)
                    assert cls._devusers_data is not None
                    assert cls._devusers_byname is not None
                    assert cls._devusers_names is not None
                except BaseException:
                    cls.reset()
                    raise

    @staticmethod
    def _load_hook_for_testing(loaded):
        '''
        Hook called from _load_and_index() on the loaded data.
        To simplify things for testing, this is a staticmethod.
        '''
        # default: do nothing

    @classmethod
    def _load_and_index(cls, filename, data, exc_value=EXC_VALUE_DEFAULT):
        '''
        Load data unconditionally.
        '''
        with cls._devusers_lock:
            cls.reset()
            if cls._devusers_data is None:
                loaded = cls.load_data(filename, data)
                cls._load_hook_for_testing(loaded)
                uids = dict()
                users = dict()
                for idx, dev_user in enumerate(loaded):
                    dup = uids.get(dev_user.uid, None)
                    if dup:
                        raise exc_value(f"in config file {filename} user index {idx} {dev_user!r} uid duplicates previous user {dup!r}")
                    uids[dev_user.uid] = dev_user

                    dup = users.get(dev_user.name.lower(), None)
                    if dup:
                        raise exc_value(f"in config file {filename} user index {idx} {dev_user!r} name duplicates previous user {dup!r}")
                    users[dev_user.name.lower()] = dev_user
                cls._devusers_data = tuple(loaded)
                cls._devusers_byname = ReadOnlyDict(users)
                cls._devusers_names = tuple(sorted([x.name for x in loaded]))

    @classmethod
    def load_data(cls, filename, data, exc_value=EXC_VALUE_DEFAULT):
        '''
        Load dev_users from config file and return parsed data as a list.
        Validates each user, but does not validate things like collisions.
        '''
        class LocalValueError(ValueError):
            '''
            Used for exc_value in outcalls to intercept errors.
            Defined within this method specifically so that this
            does not match LocalValueError from any other method.
            '''
            # No specialization here.

        data_users = laaso.paths.subscription_config_list_from_data(filename, data, 'users')
        loaded = list()
        for idx, data_user in enumerate(data_users):
            try:
                dev_user = DevUser(**data_user, exc_value=LocalValueError)
            except LocalValueError as exc:
                raise exc_value(f"in config file {filename} user index {idx} error: {exc}") from exc
            loaded.append(dev_user)
        loaded = [cls(**data_user, exc_value=exc_value) for data_user in data_users]
        return loaded

    @classmethod
    def dev_users_all(cls, exc_value=EXC_VALUE_DEFAULT) -> tuple:
        '''
        Get all users (tuple of items of this class).
        :rtype: tuple
        '''
        with cls._devusers_lock:
            cls._load_iff_necessary(exc_value=exc_value)
            # the extra tuple->tuple conversion is to placate pylint, which ignores the return type hint
            return tuple(cls._devusers_data)

    @classmethod
    def all_names(cls, exc_value=EXC_VALUE_DEFAULT) -> tuple:
        '''
        Return a sorted tuple of all names (str)
        '''
        with cls._devusers_lock:
            cls._load_iff_necessary(exc_value=exc_value)
            # the extra tuple->tuple conversion is to placate pylint, which ignores the return type hint
            return tuple(cls._devusers_names)

    @classmethod
    def dev_user_get(cls, name, exc_value=EXC_VALUE_DEFAULT, raise_on_notfound=True):
        '''
        Return corresponding DevUser.
        Raises DevUserUnknownException if name is not known.
        name matching is case-insensitive.
        '''
        with cls._devusers_lock:
            cls._load_iff_necessary(exc_value=exc_value)
            ret = cls._devusers_byname.get(name.lower(), None)
            if (not ret) and raise_on_notfound:
                raise DevUserUnknownException(f"unknown dev user {name!r}", name)
            return ret

    def to_dict(self) -> dict:
        '''
        Return a dict representation of self
        '''
        return {k : getattr(self, k) for k in self._RO_ATTRS}

laaso.reset_hooks.append(DevUser.reset)

class DevServicePrincipal():
    '''
    Service principal used in development
    '''
    def __init__(self, display_name, object_id, additional_info=None):
        self._display_name = display_name
        self._object_id = str(uuid.UUID(object_id)) # validates UUID
        self._additional_info = dict()
        if additional_info:
            self._additional_info.update(additional_info)
        self._additional_info = ReadOnlyDict(self._additional_info)

    def __repr__(self):
        return "%s(%r, %r, additional_info=%r)" % (type(self).__name__, self.display_name, self.object_id, self._additional_info)

    def __getattr__(self, name):
        return self._additional_info.get(name, '')

    @property
    def display_name(self):
        '''
        Getter
        '''
        return self._display_name

    @property
    def object_id(self):
        '''
        Getter
        '''
        return self._object_id

    @property
    def kv_team_ro(self):
        '''
        Getter
        '''
        return self._additional_info.get('kv_team_ro', False)

    _principals_lock = threading.RLock()
    _principals_data = None

    @classmethod
    def reset(cls):
        '''
        Discard cached data. Useful for unit testing.
        '''
        cls._principals_data = None

    @classmethod
    def load_data(cls, filename, data, exc_value=EXC_VALUE_DEFAULT):
        '''
        load service principals from config file
        '''
        ret = list()
        assert isinstance(data, dict)
        sp_data = laaso.paths.subscription_config_list_from_data(filename, data, 'service_principals', exc_value=exc_value)
        for idx, user_desc in enumerate(sp_data):
            if not isinstance(user_desc, dict):
                raise exc_value(f"service principal config {filename} data index {idx} is {type(user_desc)}; expected dict")
            user_desc = dict(user_desc)
            try:
                display_name = user_desc.pop('display_name')
            except KeyError as exc:
                raise exc_value(f"service principal config {filename} data index {idx} missing display_name") from exc
            try:
                object_id = user_desc.pop('object_id')
            except KeyError as exc:
                raise exc_value(f"service principal config {filename} data index {idx} missing object_id") from exc
            try:
                uuid.UUID(object_id)
            except ValueError as exc:
                raise exc_value(f"service principal config {filename} data index {idx} display_name={display_name!r} has invalid object_id") from exc
            ret.append(cls(display_name, object_id, additional_info=user_desc))
        return tuple(ret)

    @classmethod
    def get_all(cls):
        '''
        Get configured service principals
        '''
        with cls._principals_lock:
            if cls._principals_data is None:
                cls._principals_data = cls.load_data(laaso.paths.subscription_config_filename, laaso.paths.subscription_config_data)
            return tuple(cls._principals_data)

    @classmethod
    def get_by_display_name(cls, name):
        '''
        Given a display_name (name), return the corresponding entry or None
        '''
        for dsp in cls.get_all():
            if dsp.display_name == name:
                return dsp
        return None

    @classmethod
    def get_by_display_name_or_id(cls, name):
        '''
        Given a display_name (name), return the corresponding entry or None
        '''
        for dsp in cls.get_all():
            if dsp.object_id.lower() == name.lower():
                return dsp
            if dsp.display_name == name:
                return dsp
        return None

laaso.reset_hooks.append(DevServicePrincipal.reset)

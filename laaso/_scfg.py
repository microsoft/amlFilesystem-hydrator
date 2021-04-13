#
# laaso/_scfg.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
"scfg" is roughly "subscription configuration".
Selection critieria: (a) unique, (b) short, (c) easy to remember
This manages misc settings read from the subscription config file.
'''
import threading

import laaso._paths
from laaso.base_defaults import EXC_VALUE_DEFAULT
from laaso.btypes import ReadOnlyDict
import laaso.util

class _Scfg():
    '''
    Manage scfg values
    '''
    def __init__(self):
        '''
        data may be passed at construction time to support unit testing
        '''
        self._vlock = threading.RLock()
        self._vfilename = None
        self._vdata = None

        # Hook for unit testing. Do not use this in production.
        self.test_values = dict()

    def reset(self):
        '''
        Discard cached data. Useful for unit testing.
        '''
        with self._vlock:
            self._vfilename = None
            self._vdata = None
            self.test_values = dict()

    def _load_iff_necessary(self, exc_value=EXC_VALUE_DEFAULT):
        '''
        Load data iff not already loaded
        '''
        with self._vlock:
            if self._vdata is None:
                filename = laaso.paths.subscription_config_filename
                data = laaso._paths.paths.subscription_config_dict_from_data(filename, # pylint: disable=protected-access
                                                                             laaso.paths.subscription_config_data,
                                                                             'defaults',
                                                                             exc_value=exc_value)
                required = set(self._REQUIRED)
                vdata = self._data_validate(data, required=required, exc_value=exc_value)
                if required:
                    raise exc_value("%s missing value(s): %s" % (filename, ','.join(required)))
                self._vdata = vdata
                self._vfilename = filename

    _REQUIRED = {'defaults[tenant_id_default]',
                }

    def _data_validate(self, data, hnamestack='_dh', unamestack='defaults', required=None, exc_value=EXC_VALUE_DEFAULT):
        '''
        data is a dict as loaded from the config
        validate the contents and return them.
        Validation is allowed to update the contents.

        Here's what's happening: we iterate through the dict recursively.
        Each time we find a value, we look to see if we have a
        custom handler defined. If so, we invoke that custom handler
        to perform the validation. If not, then we perform some default
        handling.

        Default handling for builtin types like bool, int, str is to accept them as-is.

        Default handling for dict and list is to recursively call ourselves.
        For naming purposes, we have two namestacks: hnamestack and unamestack.
        unamestack is user-facing. It is something like: defaults[somedict][someotherdict].
        hnamestack is the handler name - something like: _dh__somedict__someotherdict.
        For lists, that looks like:
            defaults[somedict][0], defaults[somelist][1], ...
            _dh__somelist__contents
        '''
        if required:
            required.discard(unamestack)
        handler = getattr(self, hnamestack, None)
        if handler:
            return handler(data, hnamestack, unamestack, required, exc_value)
        if isinstance(data, (bool, int, str)):
            return data
        if isinstance(data, dict):
            return ReadOnlyDict({kk : self._data_validate(vv, unamestack=f'{unamestack}[{kk}]', hnamestack=f'{hnamestack}__{kk}', required=required, exc_value=exc_value) for kk, vv in data.items()})
        if isinstance(data, list):
            return tuple(self._data_validate(vv, unamestack=f'{unamestack}[{idx}]', hnamestack=f'{hnamestack}__contents', required=required, exc_value=exc_value) for idx, vv in enumerate(data))
        raise exc_value("%s has unexpected type %s" % (unamestack, type(data)))

    @staticmethod
    def _dh__tenant_id_default(value, hnamestack, unamestack, required, exc_value): # pylint: disable=unused-argument
        '''
        Validate tenant_id_default as a UUID
        '''
        return laaso.util.uuid_normalize(value, key=unamestack, exc_value=exc_value)

    @staticmethod
    def _key_valid(name):
        '''
        Return whether the given name is valid as a oonfig key
        '''
        if not isinstance(name, str):
            return False
        if not name:
            return False
        if name.startswith('_'):
            return False
        return True

    def __getattr__(self, name):
        if not self._key_valid(name):
            raise AttributeError("%r object has no attribute %r; check configuration file %s" % (type(self).__name__, name, self._vfilename))
        with self._vlock:
            if name in self.test_values:
                return self.test_values[name]
            self._load_iff_necessary()
            if name in self._vdata:
                return self._vdata[name]
            raise AttributeError("%r object has no attribute %r; check configuration file %s" % (type(self).__name__, name, self._vfilename))

    def to_dict(self) -> dict:
        '''
        Return scfg contents in dict form
        '''
        with self._vlock:
            self._load_iff_necessary()
            return dict(self._vdata)

    # These are the keys that are copied into the onbox laaso_config
    _SCFG_CONTENTS = ('admin_username',
                      'lustre_client_mount',
                      'lustre_oss_client_mount',
                      'msi_client_id_default',
                      'pubkey_keyvault_client_id',
                      'pubkey_keyvault_name',
                      'resource_groups_keep',
                      'tenant_id_default',
                     )

    def to_scfg_dict(self,
                     subscription_default='',
                     **kwargs) -> dict:
        '''
        Return scfg contents in dict form
        '''
        with self._vlock:
            self._load_iff_necessary()
            ret = dict()
            for k in self._SCFG_CONTENTS:
                try:
                    ret[k] = getattr(self, k)
                except AttributeError:
                    pass
            if subscription_default:
                ret['subscription_default'] = subscription_default
                ret['subscription_main'] = subscription_default
            ret.update(**kwargs)
            return {'defaults' : ret}

    def get(self, name, defaultvalue):
        '''
        If name is set in the config, return the corresponding value.
        If name is not set in the config, return defaultvalue.
        If name is not valid, just returns defaultvalue.
        '''
        if not self._key_valid(name):
            return defaultvalue
        with self._vlock:
            try:
                return self.test_values[name]
            except KeyError:
                pass
            self._load_iff_necessary()
            return self._vdata.get(name, defaultvalue)

    def tget(self, key, dtype, exc_value=EXC_VALUE_DEFAULT):
        '''
        key is a key in scfg (dict)
        dtype is a type
        If key is not in subscription_config_data, returns dtype().
        If key is in subscription_config_data and the value is an instance of dtype, returns the value.
        Otherwise raises an error about value not matching dtype.
        '''
        if not self._key_valid(key):
            return dtype()
        with self._vlock:
            try:
                return self.test_values[key]
            except KeyError:
                pass
            self._load_iff_necessary()
            try:
                ret = self._vdata[key]
            except KeyError:
                return dtype()
            if not isinstance(ret, dtype):
                raise exc_value(f"{self._vfilename!r}[{key!r}] has unexpected type {type(ret)}")
            return ret

scfg = _Scfg()

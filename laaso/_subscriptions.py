#
# laaso/_subscriptions.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Objects and operations related to subscription defaults.
Does not include operations that manipulate subscriptions.
'''
import copy
import re
import threading
import uuid

import laaso._paths
import laaso.base_defaults
from laaso.btypes import ReadOnlyDict
import laaso.util

class SubscriptionInfoDict(ReadOnlyDict):
    '''
    Result from subscription_info_get(). This is a subclass of dict, so
    all dict accessors work. This is read-only. There are additional
    access methods.
    '''
    # The value returned from a single location from location_defaults
    # when no values is set for that key.
    LOCATION_INFO_DEFAULT = ''

    def __missing__(self, key):
        if key == 'location_default':
            return laaso.base_defaults.LOCATION_DEFAULT_FALLBACK
        return super().__missing__(key)

    def location_info_value(self, location, key):
        '''
        Fetch a location-specific default value
        '''
        location = location or self.location_default
        return self['location_defaults'][location][key]

    @property
    def location_default(self):
        '''
        Getter for default location for this subscription
        '''
        return self['location_default']

    def name_substitutions_get(self, location=''):
        '''
        Return a dict of name_substitutions useful for Jinja templating.
        '''
        name_subs = self.get('_name_substitutions', dict())
        # Do it this way so _name_substitutions can be read-only
        ret = laaso.util.deep_update(dict(), name_subs)
        if location:
            location_defaults = self['location_defaults']
            location_data = location_defaults.get(location, dict())
            ret = laaso.util.deep_update(ret, location_data.get('name_substitutions', dict()))
        return ret

class _SubscriptionMapper():
    '''
    Manage mapping logical names to subscription IDs
    '''
    def __init__(self):
        self._data_lock = threading.RLock()
        self._map_dict_data = None # key=alias.lower() value=(alias, subscription_id)
        self._defaults_data = None # becomes tuple of SubscriptionInfoDict

    def reset(self):
        '''
        Discard cached data.
        Useful for unit tests.
        '''
        with self._data_lock:
            self._map_dict_data = None
            self._defaults_data = None

    ALIAS_RES = (re.compile(r'^[a-zA-Z0-9]$'),
                 re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\.\-_\s]*[a-zA-Z0-9]$'),
                )

    def subscription_alias_add(self, subscription_id, alias, exc_value=laaso.base_defaults.EXC_VALUE_DEFAULT):
        '''
        Add a single alias pointing to the given subscription_id.
        '''
        if not laaso.util.search_regexps(self.ALIAS_RES, alias):
            raise exc_value(f"invalid alias {alias!r}")
        normalized_id = laaso.util.uuid_normalize(subscription_id, key='subscription_id', exc_value=None)
        if not normalized_id:
            raise exc_value(f"invalid subscription_id mapping {alias!r} to {subscription_id!r} (subscription_id not valid)")
        with self._data_lock:
            map_dict = self.map_dict # Forces loading iff necessary
            key = alias.lower()
            prev = map_dict.setdefault(key, (alias, normalized_id))
            if (prev[0].lower() != key) or (prev[1] != normalized_id):
                raise exc_value(f"subscription alias conflict {alias!r}:{normalized_id} vs {prev[0]!r}:{prev[1]}")

    @staticmethod
    def _all_defaults_get() -> list:
        '''
        Return a list of all configured defaults.
        This is raw from the config file.
        '''
        # subscription_defaults is separate from subscriptions
        # to enable setting defaults for unmanaged subscriptions.
        return laaso._paths.paths.subscription_config_list_from_default_data('subscription_defaults') # pylint: disable=protected-access

    @staticmethod
    def name_substitutions_bcommon_get() -> dict:
        '''
        Return a dict of name substitutions common to all subscriptions.
        These may be overridden by per-subscription or per-location values.
        '''
        return laaso._paths.paths.subscription_config_dict_from_default_data('subscription_name_substitutions') # pylint: disable=protected-access

    @property
    def map_dict(self):
        '''
        Getter for a dict that maps logical names to subscription_ids (UUIDs)
        '''
        with self._data_lock:
            if self._map_dict_data is None:
                self._map_dict_data = dict()
                si_datas = self._all_defaults_get()
                for idx, si in enumerate(si_datas):
                    if not isinstance(si, dict):
                        raise ValueError(f"subscription_defaults[{idx}] has unexpected non-dict type {type(si)}")
                    subscription_id = si['subscription_id']
                    aliases = si.get('aliases', list())
                    for alias in aliases:
                        self.subscription_alias_add(subscription_id, alias)
            return self._map_dict_data

    def _defaults_get(self) -> list:
        '''
        Return a list of SubscriptionInfoDict
        '''
        ret = list()
        for idx, si in enumerate(self._all_defaults_get()):
            if 'subscription_id' not in si:
                raise ValueError(f"subscription_defaults[{idx}] missing 'subscription_id'")
            subscription_id = laaso.util.uuid_normalize(si['subscription_id'], key='subscription_id', exc_value=None)
            if not subscription_id:
                raise ValueError(f"subscription_defaults[{idx}] invalid 'subscription_id' {si['subscription_id']!r}")
            si = dict(si)
            si['subscription_id'] = subscription_id
            if 'location_defaults' in si:
                location_defaults = dict()
                for location, ldict in si['location_defaults'].items():
                    location_defaults[location] = ReadOnlyDict(ldict)
                    location_defaults[location].default_value = ''
                si['location_defaults'] = ReadOnlyDict(location_defaults)
                si['location_defaults'].default_value = location_default_generate()
            else:
                si['location_defaults'] = location_defaults_generate()
            name_subs = copy.deepcopy(self.name_substitutions_bcommon_get())
            ns_key = 'name_substitutions'
            ns_sub = si.pop(ns_key, dict())
            if not isinstance(ns_sub, dict):
                raise ValueError(f"subscription_defaults[{idx}][{ns_key!r}] ({subscription_id}) is not a dict")
            name_subs = laaso.util.deep_update(name_subs, ns_sub)
            si['_'+ns_key] = ReadOnlyDict(name_subs)
            ret.append(SubscriptionInfoDict(si))
        return ret

    @property
    def defaults(self) -> tuple:
        '''
        Getter for tuple of SubscriptionInfoDict
        '''
        with self._data_lock:
            if self._defaults_data is None:
                self._defaults_data = tuple(self._defaults_get())
            return self._defaults_data

    def effective(self, txt):
        '''
        When possible, translate txt to the canonical form
        of a subscription ID (lower case str that is a uuid).
        When not translatable, leave it alone; never raises
        an exception.
        '''
        if not txt:
            return ''
        if not isinstance(txt, str):
            return txt
        _, ret = self.map_dict.get(txt.lower(), (txt, txt))
        try:
            return str(uuid.UUID(txt)).lower()
        except Exception:
            return ret

subscription_mapper = _SubscriptionMapper()

def location_default_generate():
    '''
    Generate and return per-location defaults for a single location within location_defaults
    '''
    ret = ReadOnlyDict()
    ret.default_value = SubscriptionInfoDict.LOCATION_INFO_DEFAULT
    return ret

def location_defaults_generate():
    '''
    Generate and return empty location_defaults for a single subscription
    '''
    ret = ReadOnlyDict()
    ret.default_value = location_default_generate()
    return ret

def subscription_info_default_generate(subscription_id):
    '''
    Generate and return default subscription info for the given subscription_id
    '''
    ret = {'subscription_id' : subscription_id.lower(),
           'location_defaults' : location_defaults_generate(),
          }
    if subscription_id == laaso.util.UUID_ZERO:
        # Special case: UUID_ZERO gets no additional name substitutions.
        # This is useful for apps such as the shepherd that bootstrap the
        # subscription config.
        ret['_name_substitutions'] = dict()
    else:
        ret['_name_substitutions'] = subscription_mapper.name_substitutions_bcommon_get()
    return SubscriptionInfoDict(ret)

def subscription_info_get(subscription_id, return_default=True):
    '''
    Return the subscription descriptor for the given subscription_id.
    If not found, return a default if return_default, otherwise raise KeyError.
    '''
    if subscription_id == laaso.util.UUID_ZERO:
        return subscription_info_default_generate(laaso.util.UUID_ZERO)
    subscription_id_effective = subscription_mapper.effective(subscription_id)
    for si in subscription_mapper.defaults:
        if si['subscription_id'].lower() == subscription_id_effective:
            return si
    if return_default:
        return subscription_info_default_generate(subscription_id_effective)
    raise KeyError("unknown subscription %r" % subscription_id)

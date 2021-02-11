#
# laaso/azresourceid.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Support for manipulating Azure Resource IDs.

This module also contains regexps for resource IDs. Those predate
the introduction of AzResourceId.

Some docs:
naming rules: https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules
'''
import functools
import random
import re
import string
import uuid

import laaso._subscriptions
from laaso.base_defaults import EXC_VALUE_DEFAULT
from laaso.util import (getframename,
                        re_abs,
                        uuid_normalize,
                       )

# regexp conventions:
# X_TXT: The regexp in text form, to be found anywhere within the string.
# X_RE: compiled(X_TXT)
# X_ARE: compiled(re_abs(X_TXT))
#
# This naming schema ensures that a grep for any one of these things does
# not return the others, while a grep for X returns all of them.
#
# Always define X_TXT. Defining the others is optional; if no one needs it, that's okay.
# If you find you need one of the others and it is not present, please put it here
# so we avoid recompiling the same regexp in a dozen different places.

# https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules#microsoftresources
DEPLOYMENT_NAME_LEN_MAX = 64
RE_DEPLOYMENT_NAME_TXT = r'^[-\w\._\(\)]{1,64}$'
RE_DEPLOYMENT_NAME_RE = re.compile(RE_DEPLOYMENT_NAME_TXT)
RE_DEPLOYMENT_NAME_ABS = re.compile(re_abs(RE_DEPLOYMENT_NAME_TXT))

RE_GALLERY_NAME_TXT = r'(([a-zA-Z0-9])|([a-zA-Z0-9][a-zA-Z0-9\.]{0,78}[a-zA-Z0-9]))'
RE_GALLERY_NAME_ABS = re.compile(re_abs(RE_GALLERY_NAME_TXT))

# This is intentionally slightly more restrictive than the rules defined in:
#   https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules#microsoftresources
# Here, we are more restrictive about what characters are allowed.
# The docs claim a max length of 90, but the SDK seems to enforce 79. Here, we enforce 78.
RE_RESOURCE_GROUP_TXT = r'([a-zA-Z0-9][a-zA-Z0-9\-\._]{0,78}[a-zA-Z0-9]{0,1})'
RE_RESOURCE_GROUP_RE = re.compile(RE_RESOURCE_GROUP_TXT)
RE_RESOURCE_GROUP_ABS = re.compile(re_abs(RE_RESOURCE_GROUP_TXT))

# image name (not id)
#   https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules#microsoftcompute
RE_IMAGE_NAME_TXT = r'(([a-zA-Z0-9])|([a-zA-Z0-9][a-zA-Z0-9_\-\.]{0,78}[a-zA-Z0-9_]))'
RE_IMAGE_NAME_ABS = re.compile(re_abs(RE_IMAGE_NAME_TXT))

# network secuity group
#   https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules#microsoftnetwork
#   /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/infra-rg/providers/Microsoft.Network/networkSecurityGroups/some-nsg
# 1 subscription_id
# 2 resource_group_name
# 3 network security group name
NETWORK_SECURITY_GROUP_NAME_LEN_MAX = 80
RE_NETWORK_SECURITY_GROUP_NAME_TXT = r'(([a-zA-Z])|([a-zA-Z][a-zA-Z0-9_\.\-]{0,' + str(NETWORK_SECURITY_GROUP_NAME_LEN_MAX-2) + r'}[a-zA-Z_]))'

RE_STORAGE_ACCOUNT_TXT = r'([a-z0-9]{3,24})'
RE_STORAGE_ACCOUNT_ABS = re.compile(re_abs(RE_STORAGE_ACCOUNT_TXT))

RE_TAG_KEY_TXT = r'([^<>%\&\\\?/]{1,512})'
RE_TAG_KEY_ABS = re.compile(re_abs(RE_TAG_KEY_TXT))

RE_TAG_VALUE_TXT = r'(.{1,256})'
RE_TAG_VALUE_ABS = re.compile(re_abs(RE_TAG_VALUE_TXT))

EXC_DESC_DEFAULT = 'resource_id'

def check_slots(text, toks, expect_slots, exc_desc=EXC_DESC_DEFAULT, exc_value=EXC_VALUE_DEFAULT):
    '''
    toks is a list of strings
    expect_slots is tuples of (index, value)
    expect each corresponding toks[index].lower() == value.lower()
    '''
    for idx, expect_val in expect_slots:
        try:
            tok = toks[idx]
        except IndexError as exc:
            raise exc_value("invalid %s %r (missing token[%d])" % (exc_desc, text, idx)) from exc
        if tok.lower() != expect_val.lower():
            raise exc_value("invalid %s %r (invalid token[%d] (%r))" % (exc_desc, text, idx, tok))

class AzAnyResourceId():
    '''
    Base class for resource ID representation
    '''
    def __init__(self, exc_value=EXC_VALUE_DEFAULT):
        # Unlike most classes, this family normalizes self._exc_value to ValueError
        # at the end of construction. We have nothing else to do here in the
        # base class, so we go straight there.
        assert issubclass(exc_value, Exception)
        self._exc_value = ValueError

    @property
    def subscription_id(self):
        '''
        Getter for subscription_id.
        Here in the base class, there is no subscription_id, so always
        evaluate to None. This is a convenience to callers, who otherwise
        must do getattr(azrid, 'subscription_id', None) everywhere.
        subscription_id is, of course, not settable here.
        '''
        return None

    @property
    def subscription_scope(self):
        '''
        Getter for the scope of subscription_id.
        '''
        return '/'

    @staticmethod
    def fmt_vars():
        '''
        Return a dict of vars suitable for str.format
        '''
        return dict()

    @staticmethod
    def _repr_args_str():
        '''
        Helper for __repr__ that returns the positional args portion
        '''
        return ''

    def __repr__(self):
        ret = "%s(%s)" % (type(self).__name__, self._repr_args_str())
        return ret.format(**self.fmt_vars())

    @staticmethod
    def _str_fmt():
        '''
        Format basis for __str__
        '''
        return "/"

    def __str__(self):
        return self._str_fmt().format(**self.fmt_vars())

    def __lt__(self, other):
        # Explicitly identify AzAnyResourceId here rather than type(self) to DTRT with subclasses.
        if not isinstance(other, AzAnyResourceId):
            return NotImplemented
        return str(self).lower() < str(other).lower()

    def __eq__(self, other):
        # Explicitly identify AzAnyResourceId here rather than type(self) to DTRT with subclasses.
        if not isinstance(other, AzAnyResourceId):
            return NotImplemented
        return str(self).lower() == str(other).lower()

    def __hash__(self):
        return hash(str(self).lower())

    ARGS_FROM_TEXT_TOKENS = 2

    @staticmethod
    def _args_from_text(text, toks, exc_desc=EXC_DESC_DEFAULT, exc_value=EXC_VALUE_DEFAULT):
        '''
        Given toks as an array of strings with length ARGS_FROM_TEXT_TOKENS,
        parse it and return args for constructing an item of this type.
        '''
        expect_slots = ((0, ''), (1, ''))
        check_slots(text, toks, expect_slots, exc_desc=exc_desc, exc_value=exc_value)
        return list()

    def check_values_empty(self, values, exc_value):
        '''
        Expect values to be consumed
        '''
        if values:
            raise exc_value(f"{type(self).__name__}: unexpected values content {','.join(values.keys())}")

    def values_sanity(self, values, exc_value=EXC_VALUE_DEFAULT):
        '''
        Expect values to be consumed
        '''
        for k, v in values.items():
            if not hasattr(self, k):
                rr = exc_value or EXC_VALUE_DEFAULT
                raise rr(f"{type(self).__name__} has no attribute {k!r} to check")
            o = getattr(self, k)
            if o.lower() != v.lower():
                if exc_value:
                    raise exc_value(f"{k} {o!r} does not match {v!r}")
                return False
        return True

    @staticmethod
    def values_check(text, ret, exc_value=EXC_VALUE_DEFAULT):
        '''
        ret is a ResourceId object derived from text.
        Check ret values against kwargs.
        '''
        # Nothing to do here in the base class

    def values_normalize(self, **kwargs):
        '''
        Invoked during from_text() so that the result case-matches caller-provided values
        kwargs ignored so callers may pass restrictions to azresourceid_from_text()
        that do not necessarily apply to all types.
        '''
        # Nothing to do here in the base class

    @classmethod
    def _from_text_toks(cls, text, exc_desc=EXC_DESC_DEFAULT, exc_value=EXC_VALUE_DEFAULT):
        '''
        Helper for from_text(). Tokenizes string text and returns the tokens.
        '''
        if not isinstance(text, str):
            raise TypeError("%s.from_text(): text must be str, not %s" % (cls.__name__, type(text).__name__))
        toks = text.split('/')
        if len(toks) != cls.ARGS_FROM_TEXT_TOKENS:
            raise exc_value("invalid %s %r" % (exc_desc, text))
        return toks

    @classmethod
    def from_text(cls,
                  text,
                  exc_desc=EXC_DESC_DEFAULT,
                  exc_value=EXC_VALUE_DEFAULT,
                  **kwargs):
        '''
        Given an Azure resource ID as a string in text, construct an item
        of this type and return it.
        '''
        class LocalValueError(ValueError):
            '''
            Used for exc_value in outcalls to intercept errors.
            Defined within this method specifically so that this
            does not match LocalValueError from any other method.
            '''
            # No specialization here.

        if exc_value is None:
            exc_value = LocalValueError

        try:
            toks = cls._from_text_toks(text, exc_desc=exc_desc, exc_value=exc_value)
            kls_args = cls._args_from_text(text, toks, exc_desc=exc_desc, exc_value=exc_value)
            ret = cls(*kls_args, exc_value=exc_value)
            cls.values_check(text, ret, exc_value=exc_value, **kwargs)
            ret.values_normalize(**kwargs)
            return ret
        except LocalValueError:
            return None

    def values_match(self, **kwargs):
        '''
        Return whether the values provided in kwargs match those in the resource_id
        '''
        assert 'exc_value' not in kwargs

        class Mismatch(Exception):
            '''
            Error class used locally for mismatches to distinguish versus other errors.
            '''
            # No specialization needed

        try:
            self.values_check(str(self), self, exc_value=Mismatch, **kwargs)
        except Mismatch:
            return False

        return True

    def matches(self, other_id):
        '''
        Return whether other_id matches self
        '''
        if not isinstance(other_id, str):
            raise TypeError("other_id is %s; expected str" % type(other_id))
        return str(self).lower() == other_id.lower()

class AzProviderId(AzAnyResourceId):
    '''
    Example:
        /providers/Microsoft.Authorization
    '''
    def __init__(self,
                 provider_name,
                 exc_value=EXC_VALUE_DEFAULT,
                 **kwargs):
        super().__init__(exc_value=exc_value, **kwargs)
        self._exc_value = exc_value
        self.provider_name = provider_name
        self._exc_value = ValueError

    def fmt_vars(self):
        '''
        Return a dict of vars suitable for str.format
        '''
        ret = super().fmt_vars()
        ret['provider_name'] = self.provider_name
        return ret

    @staticmethod
    def _repr_args_str():
        '''
        Helper for __repr__ that returns the positional args portion
        '''
        return 'provider_name={provider_name!r}'

    @staticmethod
    def _str_fmt():
        '''
        Format basis for __str__
        '''
        return "/providers/{provider_name}"

    ARGS_FROM_TEXT_TOKENS = 3

    @staticmethod
    def _args_from_text(text, toks, exc_desc=EXC_DESC_DEFAULT, exc_value=EXC_VALUE_DEFAULT):
        '''
        Given toks as an array of strings with length ARGS_FROM_TEXT_TOKENS,
        parse it and return args for constructing an item of this type.
        '''
        expect_slots = ((0, ''), (1, 'providers'))
        check_slots(text, toks, expect_slots, exc_desc=exc_desc, exc_value=exc_value)
        return [toks[2]]

    @classmethod
    def values_check(cls, text, ret, provider_name=None, exc_value=EXC_VALUE_DEFAULT, **kwargs): # pylint: disable=arguments-differ
        '''
        ret is a ResourceId object derived from text.
        Check ret values against kwargs.
        '''
        super().values_check(text, ret, exc_value=exc_value, **kwargs)
        if provider_name and (provider_name.lower() != ret.provider_name.lower()):
            raise exc_value("unexpected provider_name=%r != %r" % (ret.provider_name, provider_name))

    def values_normalize(self, provider_name=None, **kwargs): # pylint: disable=arguments-differ
        '''
        Invoked during from_text() so that the result case-matches caller-provided values
        '''
        super().values_normalize(**kwargs)
        if provider_name:
            self.provider_name = provider_name

class AzProviderResourceId(AzProviderId):
    '''
    Example:
        /providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111
    '''
    def __init__(self,
                 provider_name,
                 resource_type,
                 resource_name,
                 exc_value=EXC_VALUE_DEFAULT,
                 **kwargs):
        super().__init__(provider_name, exc_value=exc_value, **kwargs)
        self._exc_value = exc_value
        self.resource_type = resource_type
        self.resource_name = resource_name
        self._exc_value = ValueError

    @classmethod
    def build(cls, resource_name, values, exc_value=EXC_VALUE_DEFAULT, **kwargs):
        '''
        Create an object of this type with the given parameters.
        '''
        values = dict(values)
        ret = cls(values.pop('provider_name'),
                  values.pop('resource_type'),
                  resource_name,
                  **kwargs)
        ret.check_values_empty(values, exc_value=exc_value)
        return ret

    def fmt_vars(self):
        '''
        Return a dict of vars suitable for str.format
        '''
        ret = super().fmt_vars()
        ret['resource_type'] = self.resource_type
        ret['resource_name'] = self.resource_name
        return ret

    @classmethod
    def _repr_args_str(cls):
        '''
        Helper for __repr__ that returns the positional args portion
        '''
        ret = super()._repr_args_str()
        ret += ', resource_type={resource_type!r}, resource_name={resource_name!r}'
        return ret

    @staticmethod
    def _str_fmt():
        '''
        Format basis for __str__
        '''
        return "/providers/{provider_name}/{resource_type}/{resource_name}"

    ARGS_FROM_TEXT_TOKENS = 5

    @staticmethod
    def _args_from_text(text, toks, exc_desc=EXC_DESC_DEFAULT, exc_value=EXC_VALUE_DEFAULT):
        '''
        Given toks as an array of strings with length ARGS_FROM_TEXT_TOKENS,
        parse it and return args for constructing an item of this type.
        '''
        expect_slots = ((0, ''), (1, 'providers'))
        check_slots(text, toks, expect_slots, exc_desc=exc_desc, exc_value=exc_value)
        return [toks[2], toks[3], toks[4]]

    @classmethod
    def values_check(cls, text, ret, resource_type=None, exc_value=EXC_VALUE_DEFAULT, **kwargs): # pylint: disable=arguments-differ
        '''
        ret is a ResourceId object derived from text.
        Check ret values against kwargs.
        '''
        super().values_check(text, ret, exc_value=exc_value, **kwargs)
        if resource_type and (resource_type.lower() != ret.resource_type.lower()):
            raise exc_value("unexpected resource_type=%r != %r" % (ret.resource_type, resource_type))

    def values_normalize(self, resource_type=None, **kwargs): # pylint: disable=arguments-differ
        '''
        Invoked during from_text() so that the result case-matches caller-provided values
        '''
        super().values_normalize(**kwargs)
        if resource_type:
            self.resource_type = resource_type

@functools.total_ordering
class AzSubscriptionResourceId(AzAnyResourceId):
    '''
    Resource ID of an Azure subscription
    Example:
      /subscriptions/11111111-1111-1111-1111-111111111111
    '''
    def __init__(self,
                 subscription_id,
                 exc_value=EXC_VALUE_DEFAULT,
                 **kwargs):
        super().__init__(exc_value=exc_value, **kwargs)
        self._exc_value = exc_value
        self.subscription_id = subscription_id
        self._exc_value = ValueError

    @classmethod
    def build(cls, subscription_id, values, exc_value=EXC_VALUE_DEFAULT, **kwargs):
        '''
        Create an object of this type with the given parameters.
        '''
        ret = cls(subscription_id,
                  **kwargs)
        ret.check_values_empty(values, exc_value=exc_value)
        return ret

    @property
    def subscription_id(self):
        '''
        Getter
        '''
        return self._subscription_id

    @subscription_id.setter
    def subscription_id(self, subscription_id):
        '''
        Setter. Canonizes subscription_id.
        '''
        if not isinstance(subscription_id, str):
            raise TypeError("subscription_id must be str, not %s" % type(subscription_id).__name__)
        effective = laaso._subscriptions.subscription_mapper.effective(subscription_id) # pylint: disable=protected-access
        try:
            effective = str(uuid.UUID(effective))
        except ValueError as exc:
            raise self._exc_value("subscription_id is not a UUID") from exc
        # Canonize subscription_id as lower-case.
        # For other values, we are case-preserving.
        self._subscription_id = effective.lower()

    @property
    def subscription_scope(self):
        '''
        Getter for the scope of subscription_id.
        '''
        return f"/subscriptions/{self.subscription_id}"

    def fmt_vars(self):
        '''
        Return a dict of vars suitable for str.format
        '''
        ret = super().fmt_vars()
        ret['subscription_id'] = self.subscription_id
        return ret

    @staticmethod
    def _repr_args_str():
        '''
        Helper for __repr__ that returns the positional args portion
        '''
        return 'subscription_id={subscription_id!r}'

    @staticmethod
    def _str_fmt():
        '''
        Format basis for __str__
        '''
        return "/subscriptions/{subscription_id}"

    ARGS_FROM_TEXT_TOKENS = 3

    @staticmethod
    def _args_from_text(text, toks, exc_desc=EXC_DESC_DEFAULT, exc_value=EXC_VALUE_DEFAULT):
        '''
        Given toks as an array of strings with length ARGS_FROM_TEXT_TOKENS,
        parse it and return args for constructing an item of this type.
        '''
        expect_slots = ((0, ''), (1, 'subscriptions'))
        check_slots(text, toks, expect_slots, exc_desc=exc_desc, exc_value=exc_value)
        return [toks[2]]

    @classmethod
    def values_check(cls, text, ret, subscription_id=None, exc_value=EXC_VALUE_DEFAULT, **kwargs): # pylint: disable=arguments-differ
        '''
        ret is a ResourceId object derived from text.
        Check ret values against kwargs.
        '''
        super().values_check(text, ret, exc_value=exc_value, **kwargs)
        if subscription_id and (subscription_id.lower() != ret.subscription_id):
            raise exc_value("subscription_id mismatch %r vs %r" % (subscription_id, text))

    def values_normalize(self, **kwargs):
        '''
        Invoked during from_text() so that the result case-matches caller-provided values
        '''
        super().values_normalize(**kwargs)
        self.subscription_id = uuid_normalize(self.subscription_id, key='subscription_id')

@functools.total_ordering
class AzSubscriptionProviderId(AzSubscriptionResourceId):
    '''
    Example:
      /subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Authorization
    '''
    def __init__(self,
                 subscription_id,
                 provider_name,
                 exc_value=EXC_VALUE_DEFAULT,
                 **kwargs):
        super().__init__(subscription_id, exc_value=exc_value, **kwargs)
        self._exc_value = exc_value
        self.provider_name = provider_name
        self._exc_value = ValueError

    @classmethod
    def build(cls, subscription_id, values, exc_value=EXC_VALUE_DEFAULT, **kwargs):
        '''
        Create an object of this type with the given parameters.
        '''
        values = dict(values)
        ret = cls(subscription_id,
                  values.pop('provider_name'),
                  **kwargs)
        ret.check_values_empty(values, exc_value=exc_value)
        return ret

    @property
    def provider_name(self):
        '''
        Getter
        '''
        return self._provider_name

    @provider_name.setter
    def provider_name(self, provider_name):
        '''
        Setter
        '''
        if not isinstance(provider_name, str):
            raise TypeError("provider_name must be str, not %s" % type(provider_name).__name__)
        if not provider_name:
            raise self._exc_value('invalid provider_name')
        self._provider_name = provider_name

    def fmt_vars(self):
        '''
        Return a dict of vars suitable for str.format
        '''
        ret = super().fmt_vars()
        ret['provider_name'] = self._provider_name
        return ret

    @classmethod
    def _repr_args_str(cls):
        '''
        Helper for __repr__ that returns the positional args portion
        '''
        ret = super()._repr_args_str()
        ret += ', provider_name={provider_name!r}'
        return ret

    @staticmethod
    def _str_fmt():
        '''
        Format basis for __str__
        '''
        return "/subscriptions/{subscription_id}/providers/{provider_name}"

    ARGS_FROM_TEXT_TOKENS = 5

    @staticmethod
    def _args_from_text(text, toks, exc_desc=EXC_DESC_DEFAULT, exc_value=EXC_VALUE_DEFAULT):
        '''
        Given toks as an array of strings with length ARGS_FROM_TEXT_TOKENS,
        parse it and return args for constructing an item of this type.
        '''
        expect_slots = ((0, ''), (1, 'subscriptions'), (3, 'providers'))
        check_slots(text, toks, expect_slots, exc_desc=exc_desc, exc_value=exc_value)
        return [toks[2], toks[4]]

    @classmethod
    def values_check(cls, text, ret, provider_name=None, exc_value=EXC_VALUE_DEFAULT, **kwargs): # pylint: disable=arguments-differ
        '''
        ret is a ResourceId object derived from text.
        Check ret values against kwargs.
        '''
        super().values_check(text, ret, exc_value=exc_value, **kwargs)
        if provider_name and (provider_name.lower() != ret.provider_name.lower()):
            raise exc_value("unexpected provider_name=%r != %r" % (ret.provider_name, provider_name))

    def values_normalize(self, provider_name=None, **kwargs): # pylint: disable=arguments-differ
        '''
        Invoked during from_text() so that the result case-matches caller-provided values
        '''
        super().values_normalize(**kwargs)
        if provider_name:
            self.provider_name = provider_name

@functools.total_ordering
class AzSubscriptionProviderResourceId(AzSubscriptionProviderId):
    '''
    Example:
      /subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Authorization/roleDefinitions/22222222-2222-2222-2222-222222222222
    '''
    def __init__(self,
                 subscription_id,
                 provider_name,
                 resource_type,
                 resource_name,
                 exc_value=EXC_VALUE_DEFAULT,
                 **kwargs):
        super().__init__(subscription_id, provider_name, exc_value=exc_value, **kwargs)
        self._exc_value = exc_value
        self.resource_type = resource_type
        self.resource_name = resource_name
        self._exc_value = ValueError

    @classmethod
    def build(cls, subscription_id, resource_name, values, exc_value=EXC_VALUE_DEFAULT, **kwargs): # pylint: disable=arguments-differ
        '''
        Create an object of this type with the given parameters.
        '''
        values = dict(values)
        ret = cls(subscription_id,
                  values.pop('provider_name'),
                  values.pop('resource_type'),
                  resource_name,
                  **kwargs)
        ret.check_values_empty(values, exc_value=exc_value)
        return ret

    @property
    def resource_type(self):
        '''
        Getter
        '''
        return self._resource_type

    @resource_type.setter
    def resource_type(self, resource_type):
        '''
        Setter
        '''
        if not isinstance(resource_type, str):
            raise TypeError("resource_type must be str, not %s" % type(resource_type).__name__)
        if not resource_type:
            raise self._exc_value('invalid resource_type (empty string)')
        self._resource_type = resource_type

    @property
    def resource_name(self):
        '''
        Getter
        '''
        return self._resource_name

    @resource_name.setter
    def resource_name(self, resource_name):
        '''
        Setter
        '''
        if not isinstance(resource_name, str):
            raise TypeError("resource_name must be str, not %s" % type(resource_name).__name__)
        if not resource_name:
            raise self._exc_value('invalid resource_name')
        self._resource_name = resource_name

    def fmt_vars(self):
        '''
        Return a dict of vars suitable for str.format
        '''
        ret = super().fmt_vars()
        ret['resource_type'] = self._resource_type
        ret['resource_name'] = self._resource_name
        return ret

    @classmethod
    def _repr_args_str(cls):
        '''
        Helper for __repr__ that returns the positional args portion
        '''
        ret = super()._repr_args_str()
        ret += ', resource_type={resource_type!r}, resource_name={resource_name!r}'
        return ret

    @staticmethod
    def _str_fmt():
        '''
        Format basis for __str__
        '''
        return "/subscriptions/{subscription_id}/providers/{provider_name}/{resource_type}/{resource_name}"

    ARGS_FROM_TEXT_TOKENS = 7

    @staticmethod
    def _args_from_text(text, toks, exc_desc=EXC_DESC_DEFAULT, exc_value=EXC_VALUE_DEFAULT):
        '''
        Given toks as an array of strings with length ARGS_FROM_TEXT_TOKENS,
        parse it and return args for constructing an item of this type.
        '''
        expect_slots = ((0, ''), (3, 'providers'))
        check_slots(text, toks, expect_slots, exc_desc=exc_desc, exc_value=exc_value)
        return [toks[2], toks[4], toks[5], toks[6]]

    @classmethod
    def values_check(cls, text, ret, resource_type=None, exc_value=EXC_VALUE_DEFAULT, **kwargs): # pylint: disable=arguments-differ
        '''
        ret is a ResourceId object derived from text.
        Check ret values against kwargs.
        '''
        super().values_check(text, ret, exc_value=exc_value, **kwargs)
        if resource_type and (resource_type.lower() != ret.resource_type.lower()):
            raise exc_value("unexpected resource_type=%r != %r" % (ret.resource_type, resource_type))

    def values_normalize(self, resource_type=None, **kwargs): # pylint: disable=arguments-differ
        '''
        Invoked during from_text() so that the result case-matches caller-provided values
        '''
        super().values_normalize(**kwargs)
        if resource_type:
            self.resource_type = resource_type

@functools.total_ordering
class AzRGResourceId(AzSubscriptionResourceId):
    '''
    Resource group ID in Azure
    Example:
      /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/some-rg
    '''
    def __init__(self,
                 subscription_id,
                 resource_group_name,
                 exc_value=EXC_VALUE_DEFAULT,
                 **kwargs):
        super().__init__(subscription_id, exc_value=exc_value, **kwargs)
        self._exc_value = exc_value
        self.resource_group_name = resource_group_name
        self._exc_value = ValueError

    @classmethod
    def build(cls, subscription_id, resource_group_name, values, exc_value=EXC_VALUE_DEFAULT, **kwargs): # pylint: disable=arguments-differ
        '''
        Create an object of this type with the given parameters.
        '''
        ret = cls(subscription_id,
                  resource_group_name,
                  **kwargs)
        ret.check_values_empty(values, exc_value=exc_value)
        return ret

    @property
    def resource_group_name(self):
        '''
        Getter
        '''
        return self._resource_group_name

    @resource_group_name.setter
    def resource_group_name(self, resource_group_name):
        '''
        Setter
        '''
        if not isinstance(resource_group_name, str):
            raise TypeError("resource_group_name must be str, not %s" % type(resource_group_name).__name__)
        if not RE_RESOURCE_GROUP_ABS.search(resource_group_name):
            raise self._exc_value('invalid resource_group_name')
        self._resource_group_name = resource_group_name

    def fmt_vars(self):
        '''
        Return a dict of vars suitable for str.format
        '''
        ret = super().fmt_vars()
        ret['resource_group_name'] = self.resource_group_name
        return ret

    @classmethod
    def _repr_args_str(cls):
        '''
        Helper for __repr__ that returns the positional args portion
        '''
        ret = super()._repr_args_str()
        ret += ', resource_group_name={resource_group_name!r}'
        return ret

    @staticmethod
    def _str_fmt():
        '''
        Format basis for __str__
        '''
        return "/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}"

    ARGS_FROM_TEXT_TOKENS = 5

    @staticmethod
    def _args_from_text(text, toks, exc_desc=EXC_DESC_DEFAULT, exc_value=EXC_VALUE_DEFAULT):
        '''
        Given toks as an array of strings with length ARGS_FROM_TEXT_TOKENS,
        parse it and return args for constructing an item of this type.
        '''
        expect_slots = ((0, ''), (1, 'subscriptions'), (3, 'resourcegroups'))
        check_slots(text, toks, expect_slots, exc_desc=exc_desc, exc_value=exc_value)
        return [toks[2], toks[4]]

@functools.total_ordering
class AzResourceId(AzRGResourceId):
    '''
    Resource ID in Azure
    Examples:
      /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-for-image/providers/Microsoft.Compute/images/some-image-name
      /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-for-identity/providers/Microsoft.ManagedIdentity/userAssignedIdentities/some-managed-identity
    '''
    def __init__(self,
                 subscription_id,
                 resource_group_name,
                 provider_name,
                 resource_type,
                 resource_name,
                 exc_value=EXC_VALUE_DEFAULT,
                 **kwargs):
        super().__init__(subscription_id, resource_group_name, exc_value=exc_value, **kwargs)
        self._exc_value = exc_value
        self.provider_name = provider_name
        self.resource_type = resource_type
        self.resource_name = resource_name
        self._exc_value = ValueError

    @classmethod
    def build(cls, subscription_id, resource_group_name, resource_name, values, exc_value=EXC_VALUE_DEFAULT, **kwargs): # pylint: disable=arguments-differ
        '''
        Create an object of this type with the given parameters.
        '''
        values = dict(values)
        ret = cls(subscription_id,
                  resource_group_name,
                  values.pop('provider_name'),
                  values.pop('resource_type'),
                  resource_name,
                  **kwargs)
        ret.check_values_empty(values, exc_value=exc_value)
        return ret

    @property
    def provider_name(self):
        '''
        Getter
        '''
        return self._provider_name

    @provider_name.setter
    def provider_name(self, provider_name):
        '''
        Setter
        '''
        if not isinstance(provider_name, str):
            raise TypeError("provider_name must be str, not %s" % type(provider_name).__name__)
        if not provider_name:
            raise self._exc_value('invalid provider_name')
        self._provider_name = provider_name

    @property
    def resource_type(self):
        '''
        Getter
        '''
        return self._resource_type

    @resource_type.setter
    def resource_type(self, resource_type):
        '''
        Setter
        '''
        if not isinstance(resource_type, str):
            raise TypeError("resource_type must be str, not %s" % type(resource_type).__name__)
        if not resource_type:
            raise self._exc_value('invalid resource_type (empty string)')
        self._resource_type = resource_type

    @property
    def resource_name(self):
        '''
        Getter
        '''
        return self._resource_name

    @resource_name.setter
    def resource_name(self, resource_name):
        '''
        Setter
        '''
        if not isinstance(resource_name, str):
            raise TypeError("resource_name must be str, not %s" % type(resource_name).__name__)
        if not resource_name:
            raise self._exc_value('invalid resource_name')
        self._resource_name = resource_name

    def fmt_vars(self):
        '''
        Return a dict of vars suitable for str.format
        '''
        ret = super().fmt_vars()
        ret['provider_name'] = self._provider_name
        ret['resource_type'] = self._resource_type
        ret['resource_name'] = self._resource_name
        return ret

    @classmethod
    def _repr_args_str(cls):
        '''
        Helper for __repr__ that returns the positional args portion
        '''
        ret = super()._repr_args_str()
        ret += ', provider_name={provider_name!r}, resource_type={resource_type!r}, resource_name={resource_name!r}'
        return ret

    @staticmethod
    def _str_fmt():
        '''
        Format basis for __str__
        '''
        return "/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{provider_name}/{resource_type}/{resource_name}"

    ARGS_FROM_TEXT_TOKENS = 9

    @staticmethod
    def _args_from_text(text, toks, exc_desc=EXC_DESC_DEFAULT, exc_value=EXC_VALUE_DEFAULT):
        '''
        Given toks as an array of strings with length ARGS_FROM_TEXT_TOKENS,
        parse it and return args for constructing an item of this type.
        '''
        expect_slots = ((0, ''), (1, 'subscriptions'), (3, 'resourcegroups'), (5, 'providers'))
        check_slots(text, toks, expect_slots, exc_desc=exc_desc, exc_value=exc_value)
        return [toks[2], toks[4], toks[6], toks[7], toks[8]]

    @classmethod
    def values_check(cls, text, ret, provider_name=None, resource_type=None, exc_value=EXC_VALUE_DEFAULT, **kwargs): # pylint: disable=arguments-differ
        '''
        ret is a ResourceId object derived from text.
        Check ret values against kwargs.
        '''
        super().values_check(text, ret, exc_value=exc_value, **kwargs)
        if provider_name and (provider_name.lower() != ret.provider_name.lower()):
            raise exc_value("unexpected provider_name=%r != %r" % (ret.provider_name, provider_name))
        if resource_type and (resource_type.lower() != ret.resource_type.lower()):
            raise exc_value("unexpected resource_type=%r != %r" % (ret.resource_type, resource_type))

    def values_normalize(self, provider_name=None, resource_type=None, **kwargs): # pylint: disable=arguments-differ
        '''
        Invoked during from_text() so that the result case-matches caller-provided values
        '''
        super().values_normalize(**kwargs)
        if provider_name:
            self.provider_name = provider_name
        if resource_type:
            self.resource_type = resource_type

@functools.total_ordering
class AzSubResourceId(AzResourceId):
    '''
    SubResource in Azure
    Examples:
      /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/some-rg/providers/Microsoft.Network/virtualNetworks/some-vnet/virtualNetworkPeerings/some-vnet-peering
      /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/some-rg/providers/Microsoft.Network/virtualNetworks/some-vnet/subnets/some-subnet
    '''
    def __init__(self,
                 subscription_id,
                 resource_group_name,
                 provider_name,
                 resource_type,
                 resource_name,
                 subresource_type,
                 subresource_name,
                 exc_value=EXC_VALUE_DEFAULT,
                 **kwargs):
        super().__init__(subscription_id, resource_group_name, provider_name, resource_type, resource_name, exc_value=exc_value, **kwargs)
        self._exc_value = exc_value
        self.subresource_type = subresource_type
        self.subresource_name = subresource_name
        self._exc_value = ValueError

    @classmethod
    def build(cls, subscription_id, resource_group_name, resource_name, subresource_name, values, exc_value=EXC_VALUE_DEFAULT, **kwargs): # pylint: disable=arguments-differ
        '''
        Create an object of this type with the given parameters.
        '''
        values = dict(values)
        ret = cls(subscription_id,
                  resource_group_name,
                  values.pop('provider_name'),
                  values.pop('resource_type'),
                  resource_name,
                  values.pop('subresource_type'),
                  subresource_name,
                  **kwargs)
        ret.check_values_empty(values, exc_value=exc_value)
        return ret

    @property
    def subresource_type(self):
        '''
        Getter
        '''
        return self._subresource_type

    @subresource_type.setter
    def subresource_type(self, subresource_type):
        '''
        Setter
        '''
        if not isinstance(subresource_type, str):
            raise TypeError("subresource_type must be str, not %s" % type(subresource_type).__name__)
        if not subresource_type:
            raise self._exc_value('invalid subresource_type')
        self._subresource_type = subresource_type

    @property
    def subresource_name(self):
        '''
        Getter
        '''
        return self._subresource_name

    @subresource_name.setter
    def subresource_name(self, subresource_name):
        '''
        Setter
        '''
        if not isinstance(subresource_name, str):
            raise TypeError("subresource_name must be str, not %s" % type(subresource_name).__name__)
        if not subresource_name:
            raise self._exc_value('invalid subresource_name')
        self._subresource_name = subresource_name

    def fmt_vars(self):
        '''
        Return a dict of vars suitable for str.format
        '''
        ret = super().fmt_vars()
        ret['subresource_type'] = self.subresource_type
        ret['subresource_name'] = self.subresource_name
        return ret

    @classmethod
    def _repr_args_str(cls):
        '''
        Helper for __repr__ that returns the positional args portion
        '''
        ret = super()._repr_args_str()
        ret += ', subresource_type={subresource_type!r}, subresource_name={subresource_name!r}'
        return ret

    @classmethod
    def _str_fmt(cls):
        '''
        Format basis for __str__
        '''
        ret = super()._str_fmt()
        return ret + '/{subresource_type}/{subresource_name}'

    ARGS_FROM_TEXT_TOKENS = 11

    @classmethod
    def _args_from_text(cls, text, toks, exc_desc=EXC_DESC_DEFAULT, exc_value=EXC_VALUE_DEFAULT):
        '''
        Given toks as an array of strings with length ARGS_FROM_TEXT_TOKENS,
        parse it and return args for constructing an item of this type.
        '''
        ret = super()._args_from_text(text, toks[:super().ARGS_FROM_TEXT_TOKENS], exc_desc=exc_desc, exc_value=exc_value)
        ret.extend(toks[super().ARGS_FROM_TEXT_TOKENS:])
        return ret

    @classmethod
    def values_check(cls, text, ret, subresource_type=None, exc_value=EXC_VALUE_DEFAULT, **kwargs): # pylint: disable=arguments-differ
        '''
        ret is a ResourceId object derived from text.
        Check ret values against kwargs.
        '''
        super().values_check(text, ret, exc_value=exc_value, **kwargs)
        if subresource_type and (subresource_type.lower() != ret.subresource_type.lower()):
            raise exc_value("unexpected subresource_type=%r != %r" % (ret.subresource_type, subresource_type))

    def values_normalize(self, subresource_type=None, **kwargs): # pylint: disable=arguments-differ
        '''
        Invoked during from_text() so that the result case-matches caller-provided values
        '''
        super().values_normalize(**kwargs)
        if subresource_type:
            self.subresource_type = subresource_type

@functools.total_ordering
class AzSub2ResourceId(AzSubResourceId):
    '''
    Logically, AzSubSubResourceId, but this is a little more readable.
    Example:
      /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/some-rg/providers/Microsoft.Compute/galleries/some.gallery}/images/some-image/versions/1.2.3
    '''
    def __init__(self,
                 subscription_id,
                 resource_group_name,
                 provider_name,
                 resource_type,
                 resource_name,
                 subresource_type,
                 subresource_name,
                 sub2resource_type,
                 sub2resource_name,
                 exc_value=EXC_VALUE_DEFAULT,
                 **kwargs):
        super().__init__(subscription_id, resource_group_name, provider_name, resource_type, resource_name, subresource_type, subresource_name, exc_value=exc_value, **kwargs)
        self._exc_value = exc_value
        self.sub2resource_type = sub2resource_type
        self.sub2resource_name = sub2resource_name
        self._exc_value = ValueError

    @classmethod
    def build(cls, subscription_id, resource_group_name, resource_name, subresource_name, sub2resource_name, values, exc_value=EXC_VALUE_DEFAULT, **kwargs): # pylint: disable=arguments-differ
        '''
        Create an object of this type with the given parameters.
        '''
        values = dict(values)
        ret = cls(subscription_id,
                  resource_group_name,
                  values.pop('provider_name'),
                  values.pop('resource_type'),
                  resource_name,
                  values.pop('subresource_type'),
                  subresource_name,
                  values.pop('sub2resource_type'),
                  sub2resource_name,
                  **kwargs)
        ret.check_values_empty(values, exc_value=exc_value)
        return ret

    @property
    def sub2resource_type(self):
        '''
        Getter
        '''
        return self._sub2resource_type

    @sub2resource_type.setter
    def sub2resource_type(self, value):
        '''
        Setter
        '''
        if not isinstance(value, str):
            raise TypeError("%s must be str, not %s" % (getframename(0), type(value).__name__))
        if not value:
            raise self._exc_value("invalid %s" % getframename(0))
        self._sub2resource_type = value

    @property
    def sub2resource_name(self):
        '''
        Getter
        '''
        return self._sub2resource_name

    @sub2resource_name.setter
    def sub2resource_name(self, value):
        '''
        Setter
        '''
        if not isinstance(value, str):
            raise TypeError("%s must be str, not %s" % (getframename(0), type(value).__name__))
        if not value:
            raise self._exc_value("invalid %s" % getframename(0))
        self._sub2resource_name = value

    def fmt_vars(self):
        '''
        Return a dict of vars suitable for str.format
        '''
        ret = super().fmt_vars()
        ret['sub2resource_type'] = self.sub2resource_type
        ret['sub2resource_name'] = self.sub2resource_name
        return ret

    @classmethod
    def _repr_args_str(cls):
        '''
        Helper for __repr__ that returns the positional args portion
        '''
        ret = super()._repr_args_str()
        ret += ', sub2resource_type={sub2resource_type!r}, sub2resource_name={sub2resource_name!r}'
        return ret

    @classmethod
    def _str_fmt(cls):
        '''
        Format basis for __str__
        '''
        ret = super()._str_fmt()
        return ret + '/{sub2resource_type}/{sub2resource_name}'

    ARGS_FROM_TEXT_TOKENS = 13

    @classmethod
    def _args_from_text(cls, text, toks, exc_desc=EXC_DESC_DEFAULT, exc_value=EXC_VALUE_DEFAULT):
        '''
        Given toks as an array of strings with length ARGS_FROM_TEXT_TOKENS,
        parse it and return args for constructing an item of this type.
        This looks just like super()._args_from_text(), but we cannot just inherit
        that because super() there is different.
        '''
        ret = super()._args_from_text(text, toks[:super().ARGS_FROM_TEXT_TOKENS], exc_desc=exc_desc, exc_value=exc_value)
        ret.extend(toks[super().ARGS_FROM_TEXT_TOKENS:])
        return ret

    @classmethod
    def values_check(cls, text, ret, sub2resource_type=None, exc_value=EXC_VALUE_DEFAULT, **kwargs): # pylint: disable=arguments-differ
        '''
        ret is a ResourceId object derived from text.
        Check ret values against kwargs.
        '''
        super().values_check(text, ret, exc_value=exc_value, **kwargs)
        if sub2resource_type and (sub2resource_type.lower() != ret.sub2resource_type.lower()):
            raise exc_value("unexpected sub2resource_type=%r != %r" % (ret.sub2resource_type, sub2resource_type))

    def values_normalize(self, sub2resource_type=None, **kwargs): # pylint: disable=arguments-differ
        '''
        Invoked during from_text() so that the result case-matches caller-provided values
        '''
        super().values_normalize(**kwargs)
        if sub2resource_type:
            self.sub2resource_type = sub2resource_type

RESOURCE_ID_CLASSES = (AzAnyResourceId,
                       AzProviderId,
                       AzProviderResourceId,
                       AzSubscriptionResourceId,
                       AzSubscriptionProviderId,
                       AzSubscriptionProviderResourceId,
                       AzRGResourceId,
                       AzResourceId,
                       AzSubResourceId,
                       AzSub2ResourceId,
                      )

def azresourceid_from_text(resource_id, exc_desc=EXC_DESC_DEFAULT, exc_value=EXC_VALUE_DEFAULT, **kwargs):
    '''
    Given a resource ID, convert it to an appropriate ResourceId object.
    If exc_value is None, returns None if there is no valid conversion.
    Otherwise, raises exc_value.
    '''
    class InvalidConversion(Exception):
        '''
        Error class used locally for invalid conversions to
        distinguish versus other errors.
        '''
        # No specialization needed

    azrid = None
    for rid_class in RESOURCE_ID_CLASSES:
        try:
            # Do not pass kwargs through here so we can distinguish between
            # a malformed/non-matching format versus non-matching values.
            azrid = rid_class.from_text(resource_id, exc_desc=exc_desc, exc_value=InvalidConversion)
            break
        except InvalidConversion:
            continue
    if not azrid:
        if exc_value:
            raise exc_value("cannot parse %r as an Azure resource ID" % resource_id)
        return None

    # azrid is parsed as a resource ID. Now confirm that it contains the correct values.
    if exc_value:
        azrid.values_check(resource_id, azrid, exc_value=exc_value, **kwargs)
    else:
        try:
            azrid.values_check(resource_id, azrid, exc_value=InvalidConversion, **kwargs)
        except InvalidConversion:
            return None

    # Now that values checks are complete, perform normalization.
    with laaso.util.AttributeExcursion(azrid, exc_value=exc_value):
        azrid.values_normalize(exc_value=exc_value, **kwargs)

    return azrid

def azresourceid_or_none_from_text(resource_id, **kwargs):
    '''
    Like azresourceid_from_text(), except that on any parsing error, return None rather than raising.
    '''
    class LocalValueError(ValueError):
        '''
        Used for exc_value in outcalls to intercept errors.
        Defined within this method specifically so that this
        does not match LocalValueError from any other method.
        '''
        # No specialization here.

    try:
        ret = azresourceid_from_text(resource_id, exc_value=LocalValueError, **kwargs)
    except (LocalValueError, TypeError):
        return None

    assert isinstance(ret, AzAnyResourceId)
    return ret

def azrid_normalize(resource_id, azrid_type, azrid_values, exc_value=EXC_VALUE_DEFAULT):
    '''
    Given resource_id, return it in the form of an object with type azrid_type.
    Match values in azrid_values.
    '''
    assert issubclass(azrid_type, AzAnyResourceId)
    assert exc_value
    assert issubclass(exc_value, Exception)
    if isinstance(resource_id, azrid_type):
        # This assert will trip if resource_id is subresource of azrid_type
        resource_id.values_sanity(azrid_values, exc_value=exc_value)
        if resource_id.ARGS_FROM_TEXT_TOKENS != azrid_type.ARGS_FROM_TEXT_TOKENS:
            raise exc_value(f"resource_id type {type(resource_id).__name__} is not {azrid_type.__name__}")
        azrid = resource_id
    else:
        azrid = azrid_type.from_text(resource_id, **azrid_values, exc_value=exc_value)
    return azrid

def azrid_normalize_or_none(resource_id, azrid_type, azrid_values):
    '''
    Like azrid_normalize(), except that on any parsing error, return None rather than raising.
    '''
    class LocalValueError(ValueError):
        '''
        Used for exc_value in outcalls to intercept errors.
        Defined within this method specifically so that this
        does not match LocalValueError from any other method.
        '''
        # No specialization here.

    try:
        ret = azrid_normalize(resource_id, azrid_type, azrid_values, exc_value=LocalValueError)
    except (LocalValueError, TypeError):
        return None

    assert isinstance(ret, AzAnyResourceId)
    return ret

def azrid_is(azrid, azrid_kls, **kwargs):
    '''
    Return whether azrid matches the given class (azrid_kls)
    and the parameters (given as kwargs).
    '''
    if not isinstance(azrid, AzAnyResourceId):
        raise TypeError(f"{getframename(0)} expected AzAnyResourceId for azrid but got {type(azrid)}")
    if not issubclass(azrid_kls, AzAnyResourceId):
        raise TypeError(f"{getframename(0)} expected AzAnyResourceId for azrid_kls but got {azrid_kls}")
    if not isinstance(azrid, azrid_kls):
        return False
    if azrid.ARGS_FROM_TEXT_TOKENS != azrid_kls.ARGS_FROM_TEXT_TOKENS:
        # azrid is an instance of azrid_kls but has a different token count.
        # This can happen with a non-matching azrid or with a matching
        # subresource.
        return False
    return azrid.values_match(**kwargs)

RE_SUB_PREFIX = re.compile(r'^/subscriptions/([^/]+)(/.*$|$)', flags=re.IGNORECASE)

def azresourceid_normalize_subscription_only(val):
    '''
    val is a string
    If val represents a subscription ID, or a resource ID that begins with a subscription_id,
    map and normalize it.
    '''
    m = RE_SUB_PREFIX.search(val)
    if m:
        return f"/subscriptions/{laaso._subscriptions.subscription_mapper.effective(m.group(1))}{m.group(2)}" # pylint: disable=protected-access
    return laaso._subscriptions.subscription_mapper.effective(val) # pylint: disable=protected-access

######################################################################
# Specialized naming operations

KEY_VAULT_NAME_LEN_MIN = 3
KEY_VAULT_NAME_LEN_MAX = 24
# Matching this regexp is necessary but not sufficient. External
# callers must use keyvault_name_valid().
_RE_KEY_VAULT_NAME_ABS = re.compile(r'^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$')

def keyvault_name_valid(name):
    '''
    Return whether name is valid for a keyvault
    '''
    if not isinstance(name, str):
        return False
    if (len(name) < KEY_VAULT_NAME_LEN_MIN) or (len(name) > KEY_VAULT_NAME_LEN_MAX):
        return False
    if '--' in name:
        return False
    if not _RE_KEY_VAULT_NAME_ABS.search(name):
        return False
    return True

def keyvault_name_generate():
    '''
    Generate a name to use for a keyvault.
    See https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules#microsoftkeyvault
    '''
    while True:
        candidates = string.ascii_lowercase + string.digits + '-'
        ret = random.choice(string.ascii_lowercase) # start with a letter
        ret += ''.join([random.choice(candidates) for _ in range(random.randint(1, 22))]) # alphanumerics and hyphens
        ret += random.choice(string.ascii_lowercase + string.digits) # end with a letter or digit
        if not keyvault_name_valid(ret):
            continue
        return ret

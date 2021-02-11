#
# laaso/btypes.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Basic types. No dependencies within the repo but outside this file other than laaso.base_defaults.
'''
import enum

from laaso.base_defaults import EXC_VALUE_DEFAULT

class EnumMixin():
    '''
    Mixin for enums that extends them with additional operations.
    Use this rather than subclassing the enum classes to avoid
    confusing pylint.
    '''
    @classmethod
    def values(cls, sort=True):
        '''
        Return a list of valid values for this enum.
        Default sort to true for UI elements.
        '''
        ret = [x.value for x in cls]
        if sort:
            ret.sort()
        return ret

    @classmethod
    def revmap(cls):
        '''
        Return a dict mapping {value : key}
        '''
        return {x.value : x for x in cls}

    @classmethod
    def _ordering(cls):
        '''
        Return the correct ordering of the values of this enum based on declaration order.
        This is used for ordering comparisons.
        Subclasses may overload this to produce custom orderings.
        '''
        return [x.value for x in cls]

    def _indices(self, other):
        '''
        Compute the correct ordering for this enum.
        Return the indices within this ordering for other and self.
        '''
        other = type(self)(other)
        ordering = self._ordering()
        return (ordering.index(self.value), ordering.index(other.value))

    def __lt__(self, other):
        a, b = self._indices(other)
        return a < b

    def __le__(self, other):
        a, b = self._indices(other)
        return a <= b

    def __ge__(self, other):
        a, b = self._indices(other)
        return a >= b

    def __gt__(self, other):
        a, b = self._indices(other)
        return a > b

    @classmethod
    def coerce(cls, value, exc_value=EXC_VALUE_DEFAULT, prefix=''):
        '''
        Return value coerced to this type.
        Raises exc_value with a human-friendly error on failure.
        '''
        try:
            return cls(value)
        except ValueError as exc:
            if prefix:
                raise exc_value(f"{prefix}: {exc}") from exc
            raise exc_value(str(exc)) from exc

class ReadOnlyDict(dict):
    '''
    dict that does not allow updates
    Set attribute default_value on an instance to give it a default a la DefaultDict
    '''
    ro_error_class = TypeError
    ro_error_str = 'attempt to modify read-only dict'

    def _error_readonly(self, *args, **kwargs):
        '''
        This is used to replace methods of this object
        that would otherwise modify it.
        '''
        raise self.ro_error_class(self.ro_error_str)

    __delitem__ = _error_readonly
    __setitem__ = _error_readonly
    clear = _error_readonly
    pop = _error_readonly
    popitem = _error_readonly
    setdefault = _error_readonly
    update = _error_readonly

    def __missing__(self, key):
        try:
            return self.default_value
        except AttributeError as exc:
            raise KeyError(key) from exc

    def __contains__(self, item):
        if super().__contains__(item):
            return True
        return hasattr(self, 'default_value')

class AvailabilityZoneMode(EnumMixin, enum.Enum):
    '''
    Modes for handling availability zones for VMs as in deploy_cluster.
    '''
    # ANY: Let compute pick the availability zones.
    ANY = 'any'

    # UNIFORM: Pick one availability zone for all VMs with this purpose.
    # If no vm_size satisfies that, fail.
    UNIFORM = 'uniform'

    # SAME_AS_SERVER: Only valid for clients in deploy_cluster.
    # Further restrict the server zones to satisfy the clients as well.
    # If server is UNIFORM, pick a single zone that satisfies
    # both servers and client. If no common zone exists, fail.
    SAME_AS_SERVER = 'same_as_server'

class ExtensionType(EnumMixin, enum.Enum):
    '''
    Dictionary of VM extension-type/properties key/value pairs
    These strings are the official names for these VM extensions
    as seen in ARM templates.
    '''
    KEYVAULT = 'KeyVaultForLinux'
    OMSAGENT = 'OMSAgentForLinux'

class LogTo(EnumMixin, enum.Enum):
    '''
    Logging destinations for Application
    '''
    STDERR = 'stderr'
    STDOUT = 'stdout'

class StorageAccountType(EnumMixin, enum.Enum):
    '''
    Azure storage account types. Values here are the Azure-facing strings.
    '''
    PREMIUM_LRS = 'Premium_LRS'
    STANDARD_LRS = 'Standard_LRS'
    PREMIUM_ZRS = 'Premium_ZRS'
IMAGE_STORAGE_ACCOUNT_TYPE_DEFAULT = StorageAccountType.PREMIUM_LRS
VM_OS_DISK_STORAGE_ACCOUNT_TYPE_DEFAULT = StorageAccountType.PREMIUM_LRS

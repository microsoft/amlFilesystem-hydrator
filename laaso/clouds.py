#
# laaso/clouds.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Wrappers to manage fetching msrestazure.azure_cloud.Cloud objects
'''
import inspect

import msrestazure.azure_cloud

import laaso.base_defaults

_CLOUDS = {tup[1].name : tup[1] for tup in inspect.getmembers(msrestazure.azure_cloud) if isinstance(tup[1], msrestazure.azure_cloud.Cloud)}

# We get AzurePublicCloud back from the metadata service as azEnvironment
_CLOUDS['AzurePublicCloud'] = msrestazure.azure_cloud.AZURE_PUBLIC_CLOUD

_CLOUDS_LOWER = {k.lower() : v for k, v in _CLOUDS.items()}

def cloud_get(name, exc_value=laaso.base_defaults.EXC_VALUE_DEFAULT):
    '''
    Return the named cloud object
    '''
    try:
        return _CLOUDS_LOWER[name.lower()]
    except KeyError as exc:
        raise exc_value("unknown cloud %r" % name) from exc

#
# laaso/identity.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Generic identity-handling
'''
import uuid

import laaso
from laaso.azresourceid import AzResourceId
import laaso.util

def uami_azrid_from_str(val, az_mgr):
    '''
    Given val as a string, convert it to the ARM resource ID of a user-assigned managed identity.
    Return None if it cannot be converted.
    az_mgr is laaso.azure_tool.Manager.
    '''
    class LocalValueError(ValueError):
        '''
        Used for exc_value in outcalls to intercept errors.
        Defined within this method specifically so that this
        does not match LocalValueError from any other method.
        '''
        # No specialization here.

    if not (isinstance(val, str) and val):
        return None

    # Fully-qualified ID?
    try:
        return AzResourceId.from_text(val, provider_name='Microsoft.ManagedIdentity', resource_type='userAssignedIdentities', exc_value=LocalValueError)
    except LocalValueError:
        pass

    # val is not an ARM resource ID.
    # It might be subscription_id/resource_group/name or resource_group/name or name.

    toks = val.split('/')
    if not all(toks):
        return None

    if len(toks) == 1:
        # We only have a name. See if we can infer it from the subscription setup.

        # Ideally, this would be something like:
        #   ssapp = SubscriptionSetupApplication(**laaso.paths.subscription_config_data)
        #   for subapp in ssapp.subscriptions:
        #       for uami_app in subapp.uamis:
        #           if uami_app.resource_name == toks[0]:
        #               return uami_app.resource_azrid
        #   return None
        # Unfortunately, SubscriptionSetupApplication and its dependencies
        # need to make this call, so instead we do some minimal parsing here.

        try:
            subs_data = laaso.paths.subscription_config_list_from_default_data('subscriptions', exc_value=LocalValueError)
        except LocalValueError:
            return None
        for sub_data in subs_data:
            if not isinstance(sub_data, dict):
                continue
            subscription_id = laaso.util.uuid_normalize(sub_data.get('subscription_id', None), exc_value=None)
            if not subscription_id:
                continue
            uamis_data = sub_data.get('uamis', None)
            if not isinstance(uamis_data, list):
                continue
            for uami_data in uamis_data:
                if not isinstance(uami_data, dict):
                    continue
                uami_name = uami_data.get('name', '')
                if uami_name != toks[0]:
                    continue
                resource_group = uami_data.get('resource_group', '')
                if not resource_group:
                    continue
                return AzResourceId(subscription_id,
                                    resource_group,
                                    'Microsoft.ManagedIdentity',
                                    'userAssignedIdentities',
                                    uami_name,
                                    exc_value=LocalValueError)
        return None

    if len(toks) == 2:
        # Assume that this is resource_group/name in the az_mgr subscription
        try:
            return AzResourceId(az_mgr.subscription_id,
                                toks[0],
                                'Microsoft.ManagedIdentity',
                                'userAssignedIdentities',
                                toks[1],
                                exc_value=LocalValueError)
        except LocalValueError:
            return None

    if len(toks) == 3:
        # Assume that this is subscription_id/resource_group/name.
        # Handle exceptions in case of malformed subscription_id.
        try:
            return AzResourceId(toks[0],
                                toks[1],
                                'Microsoft.ManagedIdentity',
                                'userAssignedIdentities',
                                toks[2],
                                exc_value=LocalValueError)
        except LocalValueError:
            return None

    return None

def identity_from_uami_str(val, az_mgr):
    '''
    val is an arbitrary string.
    az_mgr is laaso.azure_tool.Manager.
    Return azure.mgmt.msi.models.Identity or None
    '''
    azrid = uami_azrid_from_str(val, az_mgr)
    if not azrid:
        return ''

    uami = az_mgr.user_assigned_identity_get(subscription_id=azrid.subscription_id,
                                             resource_group=azrid.resource_group_name,
                                             name=azrid.resource_name)
    return uami

def client_id_from_verify_client_id_in_config(val):
    '''
    Find the corresponding UAMI in the default config.
    Return it.
    Return empty str for not found.
    '''
    res = laaso.util.uuid_normalize(val, exc_value=None)
    if res:
        return res
    possible = list()
    for subscription_data in laaso.paths.subscription_config_list_from_default_data('subscriptions'):
        if isinstance(subscription_data, dict) and isinstance(subscription_data.get('uamis', None), list):
            for uami_data in [x for x in subscription_data['uamis'] if isinstance(x, dict)]:
                if uami_data.get('name', '').lower() == val.lower():
                    possible.append(laaso.util.uuid_normalize(uami_data.get('verify_client_id', ''), exc_value=None))
    if len(possible) == 1:
        return possible[0]
    # Ambiguous: more than one UAMI with the same name
    return ''

def client_id_from_uami_str(val, az_mgr, resolve_using_azmgr=True):
    '''
    val is an arbitrary string.
    az_mgr is laaso.azure_tool.Manager.
    Convert val to a UUID as string.
    Return empty string if it cannot be converted.
    resolve_using_azmgr is used to catch calls coming from az_mgr.
    In that case, we fall back to attempting to use the value cached in the config.
    '''
    res = laaso.util.uuid_normalize(val, exc_value=None)
    if res:
        return res
    if not resolve_using_azmgr:
        return client_id_from_verify_client_id_in_config(val)
    uami = identity_from_uami_str(val, az_mgr)
    if uami:
        return laaso.util.uuid_normalize(uami.client_id, exc_value=None) or ''
    return ''

def principal_id_from_uami_str(val, az_mgr):
    '''
    val is an arbitrary string.
    az_mgr is laaso.azure_tool.Manager.
    Convert val to a UUID as string.
    Return empty string if it cannot be converted.
    '''
    res = laaso.util.uuid_normalize(val, exc_value=None)
    if res:
        return res
    uami = identity_from_uami_str(val, az_mgr)
    if uami:
        return laaso.util.uuid_normalize(uami.principal_id, exc_value=None) or ''
    return ''

def principal_id_from_dev_service_principal_display_name(val):
    '''
    Given a display_name, return the matching service_principal principal_id (object_id).
    '''
    dsp = laaso.dev_users.DevServicePrincipal.get_by_display_name(val)
    if dsp and dsp.object_id:
        return dsp.object_id
    return ''

def principal_id_from_str(val, az_mgr):
    '''
    val is an arbitrary string.
    az_mgr is laaso.azure_tool.Manager.
    Convert val to a UUID as string.
    Return empty string if it cannot be converted.
    '''
    if not (isinstance(val, str) and val):
        return ''
    # Check if val is already a UUID.
    try:
        return str(uuid.UUID(val.strip()))
    except ValueError:
        pass
    if '@' in val:
        # Check AAD user.
        adu = az_mgr.ad_user_get(val)
        if adu:
            return adu.object_id
    else:
        # Check if val is a service principal that we know about.
        dsp = laaso.dev_users.DevServicePrincipal.get_by_display_name(val)
        if dsp:
            return dsp.object_id
        # Check if val is a user-assigned managed identity.
        ret = principal_id_from_uami_str(val, az_mgr)
        if ret:
            return ret
    return ''

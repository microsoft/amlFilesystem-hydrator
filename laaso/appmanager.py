#
# laaso/appmanager.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Module that provides application classes that depend on laaso.azure_tool.
'''
import laaso.azure_tool
import laaso.common
import laaso.identity
import laaso.util

class ManagerMixin():
    '''
    Mixin class used to add common Manager functionality
    to Application classes.
    '''

    # Handy hook for unit testing
    MANAGER_CLASS = laaso.azure_tool.Manager

    def subscription_defaults_generate(self, az_mgr=None):
        '''
        Generate a pared-down subscription_defaults.
        Returns empty dict if there is no default defined.
        '''
        az_mgr = az_mgr or self.MANAGER_CLASS(**self.manager_kwargs())
        try:
            si = laaso.subscription_info_get(az_mgr.subscription_id, return_default=False)
        except KeyError:
            return dict()
        ret = dict(si)
        location_defaults = ret.get('location_defaults', dict())
        location_data = location_defaults.get(az_mgr.location, dict())
        if location_data:
            ret['location_default'] = az_mgr.location
            ret['location_defaults'] = {az_mgr.location : location_data}
        else:
            ret.pop('location_default', None)
            ret.pop('location_defaults', None)
        return {'subscription_defaults' : [ret]}

    def scfg_dict_generate(self, az_mgr=None, **kwargs):
        '''
        Generate a new scfg dict for this application.
        This specifically resolves MSI client IDs.
        '''
        az_mgr = az_mgr or self.MANAGER_CLASS(**self.manager_kwargs())

        try:
            kwargs.setdefault('subscription_default', self.subscription_id)
        except AttributeError:
            pass

        ret = laaso.scfg.to_scfg_dict(**kwargs)

        for key in ('msi_client_id_default',
                    'pubkey_keyvault_client_id',
                   ):
            try:
                val_pre = ret['defaults'][key]
            except KeyError:
                val_pre = laaso.scfg.get(key, '')
            if val_pre:
                val_post = laaso.identity.client_id_from_uami_str(val_pre, az_mgr)
                if val_post:
                    ret['defaults'][key] = val_post
                else:
                    self.logger.warning("%s.%s cannot convert key=%r val_pre=%r so not including it",
                                        type(self).__name__, laaso.util.getframename(0),
                                        key, val_pre)
                    ret['defaults'].pop(key, None)

        return ret

class ApplicationWithManager(laaso.common.Application, ManagerMixin):
    '''
    Application that uses laaso.azure_tool.Manager
    '''
    # No specialization here

class ApplicationWithSubscriptionManager(laaso.common.ApplicationWithSubscription, ManagerMixin):
    '''
    ApplicationWithSubscription that uses laaso.azure_tool.Manager
    '''
    # No specialization here

class ApplicationWithResourceGroupManager(laaso.common.ApplicationWithResourceGroup, ManagerMixin):
    '''
    ApplicationWithResourceGroup that uses laaso.azure_tool.Manager
    '''
    # No specialization here

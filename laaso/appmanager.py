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

    # az_mgr_discard() checks these attributes.
    # subclasses may overload this.
    AZ_MGR_DISCARD_ATTRS = {'_az_mgr',
                            'az_mgr',
                           }

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
        ret.pop('location_default', None)
        ld_popped = ret.pop('location_defaults', dict())
        if az_mgr.location:
            ret['location_default'] = az_mgr.location
            values = ld_popped.get(az_mgr.location, dict())
            ldv = self.jinja_filter_data(values)
            name_substitutions = self.name_substitutions_resolve(ldv.pop('name_substitutions', dict()))
            if name_substitutions:
                ldv['name_substitutions'] = name_substitutions
            if ldv:
                ret['location_defaults'] = {az_mgr.location :  ldv}
        name_substitutions = ret.pop('_name_substitutions', dict())
        name_substitutions = self.name_substitutions_resolve(name_substitutions)
        if name_substitutions:
            ret['name_substitutions'] = name_substitutions
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
        si = laaso.subscription_info_get(az_mgr.subscription_id)

        for key in ('msi_client_id_default',
                    'pubkey_keyvault_client_id',
                   ):
            try:
                val_pre = si[key]
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

    def vm_image_exists_for_preflight(self, image_id, az_mgr=None):
        '''
        Return whether the given image_id exists. Used during preflighting.
        Exists as a separate method to allow orchestrating apps
        to replace this check logic.
        '''
        az_mgr = az_mgr or self.az_mgr_generate()
        image_obj = az_mgr.vm_image_get_by_id(image_id)
        if not image_obj:
            self.logger.debug("%s image_id %r does not exist", self.mth(), image_id)
            return False
        return True

    def az_mgr_generate(self, **kwargs):
        '''
        Generate and return a new Manager (MANAGER_CLASS)
        '''
        kg = getattr(self, 'manager_kwargs', None)
        if callable(kg):
            mk = kg() # pylint: disable=not-callable
        else:
            mk = dict()
            for k in ('logger', 'subscription_id', 'tenant_id'):
                try:
                    mk[k] = getattr(self, k)
                except AttributeError:
                    continue
        mk.update(kwargs)
        ret = self.MANAGER_CLASS(**mk)
        return ret

    def az_mgr_discard(self):
        '''
        Discard references to Manager-like objects.
        This allows reclaiming of unshared connection pools in SDK client classes.
        Check attrs defined by AZ_MGR_DISCARD_ATTRS.
        If they are instances of laaso.azure_tool.Manager or MANAGER_CLASS,
        set them to None
        '''
        for attr in self.AZ_MGR_DISCARD_ATTRS:
            curval = getattr(self, attr, None)
            if isinstance(curval, (laaso.azure_tool.Manager, self.MANAGER_CLASS)):
                setattr(self, attr, None)

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

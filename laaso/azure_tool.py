#!/usr/bin/env python3
#
# laaso/azure_tool.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Scripted management for laaso server VMs for testing
'''
import base64
import configparser
import copy
import enum
import http.client
import inspect
import io
import json
import logging
import os
import pprint
import random
import re
import sys
import threading
import time
import traceback
import urllib.parse
import uuid
import yaml

from defusedxml import ElementTree
from tabulate import tabulate

import OpenSSL.crypto
import azure.common.client_factory
import azure.common.credentials
import azure.core.exceptions
import azure.core.pipeline
from azure.graphrbac import GraphRbacManagementClient
import azure.identity
import azure.identity._credentials
import azure.keyvault.certificates
import azure.keyvault.keys
import azure.keyvault.secrets
import azure.kusto.data
from azure.mgmt.authorization import AuthorizationManagementClient
import azure.mgmt.authorization.models
import azure.mgmt.authorization.v2018_01_01_preview.models
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import ResourceIdentityType
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.mgmt.msi import ManagedServiceIdentityClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
import azure.mgmt.resource.resources.models
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.subscription import SubscriptionClient
import azure.storage.blob
from azure.storage.blob import (BlobClient,
                                BlobServiceClient,
                                BlobType,
                                ContainerClient,
                               )
from azure.storage.filedatalake import (DataLakeDirectoryClient,
                                        DataLakeServiceClient,
                                        FileSystemClient,
                                       )
import azure.mgmt.subscription
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.serialization.pkcs12
import knack.util
import msrest
import msrest.service_client
import msrestazure.polling.arm_polling
import requests
import urllib3

import laaso
import laaso.azresourceid
from laaso.azresourceid import (AzAnyResourceId,
                                AzProviderResourceId,
                                AzResourceId,
                                AzSub2ResourceId,
                                AzSubResourceId,
                                AzSubscriptionProviderResourceId,
                                AzSubscriptionResourceId,
                                RE_GALLERY_NAME_ABS,
                                RE_RESOURCE_GROUP_ABS,
                                azresourceid_from_text,
                                azresourceid_or_none_from_text,
                                azrid_is,
                                azrid_normalize,
                                azrid_normalize_or_none,
                               )
import laaso.base_defaults
from laaso.base_defaults import EXC_VALUE_DEFAULT
from laaso.btypes import (EnumMixin,
                          ReadOnlyDict,
                          VM_OS_DISK_STORAGE_ACCOUNT_TYPE_DEFAULT,
                         )
from laaso.cacher import CacheIndexer
import laaso.clouds
from laaso.command import Command
import laaso.common
from laaso.data_disks import (DATA_DISK_DESCS,
                              DataDiskType,
                             )
from laaso.exceptions import (ApplicationException,
                              ApplicationExit,
                              ResourceGroupMayNotBeDeleted,
                             )
import laaso.identity
import laaso.msapicall
from laaso.msapicall import (armpolling_obj_for_operations,
                             msapicall,
                             msapiwrap,
                            )
from laaso.semantic_version import SemanticVersion
from laaso.output import output_redact
from laaso.storagenaming import (BlobName,
                                 ContainerName,
                                 StorageAccountName,
                                )
import laaso.util
from laaso.util import (PF,
                        RE_UUID_ABS,
                        RE_UUID_RE,
                        elapsed,
                        expand_item,
                        expand_item_pformat,
                        getframe,
                        getframename,
                        indent_simple,
                       )

# https://docs.microsoft.com/en-us/azure/virtual-machines/custom-data
VM_CUSTOM_DATA_LEN_MAX = 65536

# Classes that are not usually interesting to expand
# when expanding Azure SDK types.
AZURE_NOEXPAND_TYPES = (azure.common.credentials._CliCredentials, # pylint: disable=protected-access
                        azure.core.pipeline.Pipeline,
                        azure.core.pipeline.PipelineContext,
                        azure.core.pipeline.PipelineRequest,
                        azure.core.pipeline.PipelineResponse,
                        configparser.ConfigParser,
                        http.client.HTTPResponse,
                        msrest.pipeline.Pipeline,
                        msrest.pipeline.requests.PipelineRequestsHTTPSender,
                        msrest.pipeline.universal.HTTPLogger,
                        msrest.pipeline.universal.UserAgentPolicy,
                        msrest.serialization.Deserializer,
                        msrest.universal_http.requests.RequestsClientResponse,
                        requests.adapters.HTTPAdapter,
                        requests.cookies.RequestsCookieJar,
                        requests.models.Response,
                        urllib3.connectionpool.HTTPSConnectionPool,
                        urllib3.util.retry.Retry,
                       )
# If azure.cli.core is present, we include
# some if its types in AZURE_NOEXPAND_TYPES. That presence is determined
# soley by the dependencies of the packages that we import.
# This code (including the pylint disables) is structured so it DTRT
# whether or not azure.cli.core is present.
#
try:
    import azure.cli.core._profile # pylint: disable=import-error,no-name-in-module,ungrouped-imports,useless-suppression
    AZURE_NOEXPAND_TYPES = AZURE_NOEXPAND_TYPES + (azure.cli.core._profile.Profile,) # pylint: disable=c-extension-no-member,protected-access,useless-suppression
except ModuleNotFoundError:
    pass
try:
    import azure.cli.core.adal_authentication # pylint: disable=import-error,no-name-in-module,ungrouped-imports,useless-suppression
    AZURE_NOEXPAND_TYPES = AZURE_NOEXPAND_TYPES + (azure.cli.core.adal_authentication.AdalAuthentication,) # pylint: disable=c-extension-no-member,useless-suppression
except ModuleNotFoundError:
    pass

# These are REST API versions that we use as either starting points
# or fallbacks. At some time, they have been
# tested and are known to work. We have no control over when RPs,
# including the metadata service, might drop support for a version,
# so these can go stale. Code that talks directly to endpoints
# without going through the SDKs must be prepared for version changes.
REST_API_VERSIONS = ReadOnlyDict({'metadata_service' : '2020-06-01', # https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service
                                 })

# Unless otherwise specified, use these REST API versions
# for these client classes in place of the SDK default.
API_VERSIONS_DEFAULT = ((AuthorizationManagementClient, '2018-01-01-preview'),
                       )

class AzCred(EnumMixin, enum.Enum):
    '''
    Magic values that may be placed in a client_id list to indicate
    things that are not UAMI client_ids. In addition to these
    magic values, None is like login, but it is always appended.
    '''
    LOGIN = 'login'
    SYSTEM_ASSIGNED = 'system-assigned'

class ToolException(ApplicationException):
    '''
    Generic exception generated by this tool
    '''
    # No specialization

class SkuCapabilityMissingException(ToolException):
    '''
    The given sku (ResourceSku) is missing the named capability
    '''
    def __init__(self, capability_name):
        super().__init__(capability_name)
        self.capability_name = capability_name

def _unhandled_capability(sku, capability, logger, extra=''):
    '''
    Error for unhandled capability
    '''
    logger.error("sku:\n%s", expand_item_pformat(sku))
    logger.error("capability:\n%s", expand_item_pformat(capability))
    if extra:
        logger.error("unhandled capability (%s)", extra)
    else:
        logger.error("unhandled capability")
    raise ApplicationExit(1)

def _sku_capability_bool(sku, capability, logger):
    '''
    Convert ResourceSkuCapability to a bool
    '''
    if isinstance(capability.value, bool):
        return capability.value
    if isinstance(capability.value, str):
        if capability.value.lower() in ['false', 'no']:
            return False
        if capability.value.lower() in ['true', 'yes']:
            return True
        _unhandled_capability(sku, capability, logger, extra="unhandled capability.value %s %s" % (type(capability.value), capability.value))
    _unhandled_capability(sku, capability, logger, extra="unhandled capability.value type %s" % type(capability.value))
    return None

def sku_has_capability(sku, capability_name, capabilities, logger):
    '''
    Return whether the sku (ResourceSku) supports the named capability. None means
    nothing explicit one way or the other, while False is explicit.
    '''
    any_true = False
    any_false = False
    for capability in capabilities:
        if capability.name != capability_name:
            continue
        val = _sku_capability_bool(sku, capability, logger)
        if val:
            any_true = True
        else:
            any_false = True
    if capabilities is sku.capabilities:
        # we only check location_info if we're not already recursing
        for loc in sku.location_info:
            for zone_detail in loc.zone_details:
                tmp = sku_has_capability(sku, capability_name, zone_detail.capabilities, logger)
                if tmp:
                    any_true = True
                elif tmp is False: # tmp could be None
                    any_false = True
    if any_true and any_false:
        _unhandled_sku(sku, logger, "contradictory capability availability for %s" % capability_name)
    if any_true or any_false:
        return any_true
    return None

def sku_supports_data_disk_type(sku, data_disk_type, logger):
    '''
    Given sku (ResourceSku), return whether it is a VM that
    supports the given data_disk_type.
    '''
    data_disk_type = DataDiskType(data_disk_type)
    if sku.resource_type != 'virtualMachines':
        return False
    if data_disk_type in (DataDiskType.PREMIUM, DataDiskType.STANDARD):
        # All VMs support premium and standard
        return True
    if data_disk_type == DataDiskType.ULTRA:
        return sku_has_capability(sku, 'UltraSSDAvailable', sku.capabilities, logger)
    if data_disk_type == DataDiskType.NVME:
        # This is super-annoying; the ResourceSku does not include
        # any capability or restriction that says this.
        # instead, we just match on the name.
        return bool(re.search(r'Standard_L[1-9]+', sku.name))
    return False

def sku_location_info_get(sku, location):
    '''
    Given sku (ResourceSku), find and return the location info (ResourceSkuLocationInfo)
    for the given location. Returns None if not found.
    '''
    if sku.location_info:
        for li in sku.location_info:
            if li.location.lower() == location.lower():
                if sku.restrictions:
                    # Apply restrictions so the caller sees zones
                    # as the ones that are truly available.
                    restrict_zones = set()
                    restricted = False
                    for restriction in sku.restrictions:
                        if location.lower() not in [x.lower() for x in restriction.restriction_info.locations]:
                            # This restriction does not apply to this location
                            continue
                        if restriction.type.lower() == 'location':
                            # This location is not available at all for this resource.
                            # This can be something like an EUAP location for a non-EUAP subscription.
                            return None
                        if (restriction.type.lower() == 'zone') and restriction.restriction_info.zones:
                            # This resource is not available in this zone for this subscription.
                            restricted = True
                            restrict_zones.update(restriction.restriction_info.zones)
                    zones = set(li.zones)
                    zones -= restrict_zones
                    if restricted and (not zones):
                        # After restrictions there are no zones left.
                        # Treat this resource as not-really-there.
                        return None
                    li = copy.deepcopy(li)
                    li.zones = availability_zones_normalize(zones)
                return li
    return None

def availability_zones_normalize(zones):
    '''
    Return availability zones as a sorted list of strings.
    When possible, sorting is by zone value rather than lexical
    (though that really only matters if/when we have locations
    with double-digit availability zones).
    '''
    try:
        zones = [int(x) for x in zones]
        zones.sort()
        return [str(x) for x in zones]
    except ValueError:
        pass
    zones = [str(x) for x in zones]
    zones.sort()
    return zones

@staticmethod
def _unhandled_sku(sku, logger, extra=''):
    '''
    Error for unhandled sku
    '''
    logger.error("sku:\n%s", expand_item_pformat(sku))
    if extra:
        logger.error("unhandled sku (%s)", extra)
    else:
        logger.error("unhandled sku")
    raise ApplicationExit(1)

command = Command()

class VMDesc():
    '''
    Describe a VM
    '''
    def __init__(self, name, vm_size, nic_name=None, accelerated_networking=None, custom_data=None, public_ip_id=None, admin_username=None):
        self.vm_name = name
        self.vm_size = vm_size
        self.accelerated_networking = accelerated_networking
        self.custom_data = custom_data
        self.public_ip_id = public_ip_id or None
        self.admin_username = admin_username or None

        if nic_name:
            self.nic_name = nic_name
            self.nic_name_provided = True
        else:
            self.nic_name = self.vm_name + '-nic'
            self.nic_name_provided = False

        self.boot_diag_enable = True
        self.boot_diag_use_storage_account_iff_available = True

        self.vm_create_op = None
        self.vm_create_res = None
        self.osdisk_name = self.vm_name + '-osdisk'
        self.nic_create_op = None
        self.nic_obj = None
        self.nic_private_ip = None

    def __repr__(self):
        return "%s(%r, %r, accelerated_networking=%r)" % (type(self).__name__, self.vm_name, self.vm_size, self.accelerated_networking)

    def nic_create_op_wait(self, logger):
        '''
        Wait for self.nic_create_op to complete
        '''
        if self.nic_create_op and (not self.nic_obj):
            logger.info("NIC create %s wait", self.nic_name)
            self.nic_create_op.wait()
            self.nic_obj = self.nic_create_op.result()
        self.nic_private_ip = self.nic_obj.ip_configurations[0].private_ip_address
        logger.info("NIC create %s result:\n%s", self.nic_name, expand_item_pformat(self.nic_obj))

    def log_ip_str(self):
        '''
        String used by log_ip()
        '''
        return "%s %s" % (self.vm_name, self.nic_private_ip)

class BlobOpBundle():
    '''
    Container of stuff useful for operating on a blob
    '''
    def __init__(self,
                 name,
                 manager=None,
                 subscription_id=None,
                 storage_account_resource_group_name=None,
                 blobserviceclient=None,
                 containerclient=None,
                 blobclient=None,
                 datalakeserviceclient=None,
                 filesystemclient=None,
                 directoryclient=None,
                 storage_account_key=None,
                 sas_token=None,
                 credential=None,
                 warn_missing=True):
        '''
        manager is a hint; it is not used if the subscription_id does not match
        '''
        self._name = self.name_normalize(name, subscription_id=subscription_id)
        self._manager = manager_for(self._name, manager=manager, update_thing=True)
        self.storage_account_resource_group_name = storage_account_resource_group_name or None
        self._lock = threading.RLock()
        self._blobserviceclient = blobserviceclient
        self._containerclient = containerclient
        self._blobclient = blobclient
        self._datalakeserviceclient = None
        self._filesystemclient = None
        self._directoryclient = None
        self._storage_account_key = storage_account_key
        self._sas_token = sas_token
        self._credential = credential
        self.warn_missing = warn_missing
        self._hns_enabled = None

        if not isinstance(self._blobserviceclient, (type(None), BlobServiceClient)):
            raise TypeError("bad blobserviceclient type %s" % type(self._blobserviceclient))
        if not isinstance(self._containerclient, (type(None), ContainerClient)):
            raise TypeError("bad containerclient type %s" % type(self._containerclient))
        if not isinstance(self._blobclient, (type(None), BlobClient)):
            raise TypeError("bad blobclient type %s" % type(self._blobclient))

        self.datalakeserviceclient = datalakeserviceclient
        self.filesystemclient = filesystemclient
        self.directoryclient = directoryclient

        if not isinstance(self._name, BlobClient):
            assert self._blobclient is None
        if not isinstance(self._name, ContainerClient):
            assert self._containerclient is None

    @property
    def cloud(self):
        '''
        Getter - cloud descriptor object
        '''
        return self._manager.cloud

    @property
    def name(self):
        '''
        Getter - name object (eg BlobName, ContainerName, ...)
        '''
        return self._name

    @staticmethod
    def name_normalize(name, subscription_id=None, subscription_id_default=None):
        '''
        Given a name, convert it to the most precise of BlobName/ContainerName/StorageAccountName.
        '''
        if isinstance(name, StorageAccountName):
            tmp = name.subscription_id
            if subscription_id:
                if tmp and (tmp != subscription_id):
                    raise ValueError('inconsistent subscription_id')
            elif tmp:
                subscription_id = tmp
            else:
                subscription_id = None
        elif isinstance(name, str):
            subscription_id = subscription_id or None
        else:
            raise TypeError("unexpected subscription_id type %s" % type(subscription_id))
        assert (isinstance(subscription_id, str) and subscription_id) or (subscription_id is None)
        ret = None
        try:
            ret = BlobName(name, subscription_id=subscription_id)
        except (TypeError, ValueError):
            pass
        if ret is None:
            try:
                ret = ContainerName(name, subscription_id=subscription_id)
            except (TypeError, ValueError):
                pass
        if ret is None:
            try:
                ret = StorageAccountName(name, subscription_id=subscription_id)
            except (TypeError, ValueError):
                pass
        if ret is None:
            raise ValueError("cannot parse name %r" % name)
        if not ret.subscription_id:
            ret.subscription_id = subscription_id_default or None
        return ret

    @classmethod
    def mth(cls):
        '''
        Return a string of the form "Blah.x" where Blah is the name of this class
        and x is the frame name of the caller.
        '''
        return "%s.%s" % (cls.__name__, getframename(1))

    @property
    def logger(self):
        '''
        Getter for a logger
        '''
        return self._manager.logger

    @property
    def blobserviceclient(self):
        '''
        Return BlobServiceClient, creating iff necessary
        '''
        with self._lock:
            if not self._blobserviceclient:
                self.populate_blobserviceclient()
            return self._blobserviceclient

    @blobserviceclient.setter
    def blobserviceclient(self, value):
        '''
        Use value as self.blobserviceclient
        '''
        if not isinstance(value, (type(None), BlobServiceClient)):
            raise TypeError("unexpected type %s" % type(value))
        with self._lock:
            self._blobserviceclient = value

    @property
    def containerclient(self):
        '''
        Return ContainerClient, creating iff necessary
        '''
        with self._lock:
            if not self._containerclient:
                self.populate_containerclient()
            return self._containerclient

    @containerclient.setter
    def containerclient(self, value):
        '''
        Use value as self.containerclient
        '''
        if not isinstance(value, (type(None), ContainerClient)):
            raise TypeError("unexpected type %s" % type(value))
        assert isinstance(self._name, ContainerName)
        with self._lock:
            self._containerclient = value

    @property
    def blobclient(self):
        '''
        Return BlobClient, creating iff necessary
        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blobclient?view=azure-python
        '''
        with self._lock:
            if not self._blobclient:
                self.populate_blobclient()
            return self._blobclient

    @blobclient.setter
    def blobclient(self, value):
        '''
        Use value as self.blobclient
        '''
        if not isinstance(value, (type(None), BlobClient)):
            raise TypeError("unexpected type %s" % type(value))
        assert isinstance(self._name, BlobName)
        with self._lock:
            self._blobclient = value

    @property
    def datalakeserviceclient(self):
        '''
        Return azure.storage.filedatalake.DataLakeServiceClient, creating iff necessary
        '''
        with self._lock:
            if not self._datalakeserviceclient:
                self.populate_datalakeserviceclient()
            return self._datalakeserviceclient

    @datalakeserviceclient.setter
    def datalakeserviceclient(self, value):
        '''
        Use value as self.datalakeserviceclient
        '''
        if not isinstance(value, (type(None), DataLakeServiceClient)):
            raise TypeError("unexpected type %s" % type(value))
        if value:
            assert isinstance(self._name, ContainerName)
        with self._lock:
            self._datalakeserviceclient = value
            self._hns_enabled = None

    @property
    def filesystemclient(self):
        '''
        Return Filesystemclient, creating iff necessary
        '''
        with self._lock:
            if not self._filesystemclient:
                self.populate_filesystemclient()
            return self._filesystemclient

    @filesystemclient.setter
    def filesystemclient(self, value):
        '''
        Use value as self.filesystemclient
        '''
        if not isinstance(value, (type(None), FileSystemClient)):
            raise TypeError("unexpected type %s" % type(value))
        if value:
            assert isinstance(self._name, ContainerName)
        with self._lock:
            self._filesystemclient = value
            self._hns_enabled = None

    @property
    def directoryclient(self):
        '''
        Return DataLakeDirectoryClient, creating iff necessary
        '''
        with self._lock:
            if not self._directoryclient:
                self.populate_directoryclient()
            return self._directoryclient

    @directoryclient.setter
    def directoryclient(self, value):
        '''
        Use value as self.directoryclient
        '''
        if not isinstance(value, (type(None), DataLakeDirectoryClient)):
            raise TypeError("unexpected type %s" % type(value))
        if value:
            assert isinstance(self._name, ContainerName)
        with self._lock:
            self._directoryclient = value
            self._hns_enabled = None

    def populate_storage_account_resource_group_name(self):
        '''
        Generate and remember storage_account_resource_group_name
        '''
        with self._lock:
            self.storage_account_resource_group_name = self._manager.storage_account_resource_group_name_get(storage_account_name=self._name.storage_account_name)
            if (not self.storage_account_resource_group_name) and self.warn_missing:
                self.logger.warning("%s.%s cannot get storage_account_resource_group_name for %r", type(self).__name__, getframe(0), self._name)

    def populate_storage_account_key(self):
        '''
        Generate and remember storage_account_key
        '''
        with self._lock:
            # storage_account_keys_get will fetch storage_account_resource_group_name if it is not provided.
            # may as well fetch and cache it here.
            if not self.storage_account_resource_group_name:
                self.populate_storage_account_resource_group_name()
            key = None
            keys = self._manager.storage_account_keys_get(storage_account_name=self._name.storage_account_name, storage_account_resource_group_name=self.storage_account_resource_group_name)
            if keys:
                for idx, k in enumerate(keys):
                    if k:
                        keyname = "storage_account_key[%s][%d]" % (self._name.storage_account_name, idx)
                        output_redact(keyname, k)
                        if not key:
                            key = k
                if not key:
                    if self.warn_missing:
                        self.logger.warning("%s.%s storage_account_keys_get did not return a valid key for %r", type(self).__name__, getframe(0), self._name)
            self._storage_account_key = key
            if (not self._storage_account_key) and self.warn_missing:
                self.logger.warning("%s.%s cannot get storage_account_keys for %r", type(self).__name__, getframe(0), self._name)

    @property
    def storage_account_key(self):
        '''
        Return the first valid storage account key as a str
        '''
        with self._lock:
            if not self._storage_account_key:
                self.populate_storage_account_key()
            return self._storage_account_key

    def populate_blobserviceclient(self):
        '''
        Generate and remember blobserviceclient.
        '''
        with self._lock:
            assert isinstance(self._name, StorageAccountName)
            if not (self._storage_account_key or self._sas_token or self._credential):
                self.populate_storage_account_key()
            self._blobserviceclient = self._manager.blobserviceclient_get(storage_account_name=self._name.storage_account_name,
                                                                          storage_account_resource_group_name=self.storage_account_resource_group_name,
                                                                          storage_account_key=self._storage_account_key,
                                                                          sas_token=self._sas_token,
                                                                          credential=self._credential)
            if (not self._blobserviceclient) and self.warn_missing:
                self.logger.warning("%s.%s cannot generate BlobServiceClient for %r", type(self).__name__, getframe(0), self._name)

    def populate_containerclient(self):
        '''
        Generate and remember containerclient.
        '''
        with self._lock:
            if not isinstance(self._name, ContainerName):
                raise ApplicationException("may not %s for %r" % (self.mth(), self._name))
            bsc = self.blobserviceclient
            if bsc:
                try:
                    self._containerclient = msapicall(self.logger, bsc.get_container_client, self._name.container_name)
                except Exception as exc:
                    caught = laaso.msapicall.Caught(exc)
                    if caught.is_missing():
                        self._containerclient = None
                    else:
                        raise
            else:
                self._containerclient = None
            if (not self._containerclient) and self.warn_missing:
                self.logger.warning("%s.%s cannot generate ContainerClient for %r", type(self).__name__, getframe(0), self._name)

    def populate_blobclient(self):
        '''
        Generate and remember blobclient.
        '''
        with self._lock:
            if not isinstance(self._name, BlobName):
                raise ApplicationException("may not %s for %r" % (self.mth(), self._name))
            cc = self.containerclient
            if cc:
                blob_name = urllib.parse.quote(self._name.blob_name)
                try:
                    self._blobclient = msapicall(self.logger, cc.get_blob_client, blob_name)
                except Exception as exc:
                    caught = laaso.msapicall.Caught(exc)
                    if caught.is_missing():
                        self._blobclient = None
                    else:
                        raise
            else:
                self._blobclient = None
            if (not self._blobclient) and self.warn_missing:
                self.logger.warning("%s.%s cannot generate BlobClient for %r", type(self).__name__, getframe(0), self._name)

    def populate_datalakeserviceclient(self, credential=None):
        '''
        Generate and remember datalakeserviceclient.
        '''
        credential = credential or self._credential or self._sas_token
        if not credential:
            credential = self._manager.azure_credential_generate(caller_tag='DataLakeServiceClient')
        account_url = "https://{name}.dfs.{storage_endpoint}/".format(name=self._name.storage_account_name, storage_endpoint=self.cloud.suffixes.storage_endpoint)
        with self._lock:
            self._hns_enabled = None
            self._datalakeserviceclient = msapicall(self.logger, DataLakeServiceClient, account_url, credential=credential)
            if (not self._datalakeserviceclient) and self.warn_missing:
                self.logger.warning("%s cannot generate DataLakeServiceClient for %r", self.mth(), self._name)

    def populate_filesystemclient(self, credential=None):
        '''
        Generate and remember filesystemclient.
        '''
        credential = credential if credential is not None else self._credential
        if not isinstance(self._name, ContainerName):
            raise ApplicationException("may not %s for %r" % (self.mth(), self._name))
        with self._lock:
            dsc = self.datalakeserviceclient
            self._filesystemclient = msapicall(self.logger, dsc.get_file_system_client, self._name.container_name)
            if (not self._filesystemclient) and self.warn_missing:
                self.logger.warning("%s cannot generate FileSystemClient for %r", self.mth(), self._name)

    @staticmethod
    def _test_hns_enabled(directory_client):
        '''
        Use the given directory_client (DataLakeDirectoryClient) to determine if HNS (Hierarchical NameSpace) is enabled.
        Per LaaSO HSM spec, use get_access_control() call to verify HNS enabled.
        '''
        assert isinstance(directory_client, DataLakeDirectoryClient)
        try:
            directory_client.get_access_control()
        except laaso.msapicall.AZURE_SDK_EXCEPTIONS as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_hns_not_enabled():
                return False
            raise
        return True

    def directoryclient_create(self, path, test_hns_enabled=False):
        '''
        Return DataLakeDirectoryClient for the given path
        '''
        if not isinstance(self._name, ContainerName):
            raise ApplicationException("may not %s for %r" % (self.mth(), self._name))
        dsc = self.datalakeserviceclient
        directory_client = msapicall(self.logger, dsc.get_directory_client, self._name.container_name, path)
        if test_hns_enabled and (not self._test_hns_enabled(directory_client)):
            return None
        return directory_client

    @property
    def hns_enabled(self):
        '''
        Return whether or not HNS (Hierarchical NameSpace) is enabled
        '''
        if not isinstance(self._name, ContainerName):
            raise ApplicationException("may not %s for %s" % (self.mth(), self._name))
        with self._lock:
            if self._hns_enabled is None:
                directory_client = self.directoryclient
                self._hns_enabled = self._test_hns_enabled(directory_client)
            assert isinstance(self._hns_enabled, bool)
            return self._hns_enabled

    def populate_directoryclient(self):
        '''
        Generate and remember directoryclient.
        '''
        if not isinstance(self._name, ContainerName):
            raise ApplicationException("may not %s for %r" % (self.mth(), self._name))
        with self._lock:
            self._hns_enabled = None
            self._directoryclient = self.directoryclient_create('/')
            if (not self._directoryclient) and self.warn_missing:
                self.logger.warning("%s.%s cannot generate DataLakeDirectoryClient for %r", type(self).__name__, getframe(0), self._name)

    def blob_properties_get(self):
        '''
        Retrieve properties of the target blob
        '''
        bc = self.blobclient
        if not bc:
            # already warned iff necessary
            return None
        try:
            return bc.get_blob_properties()
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def container_properties_get(self):
        '''
        Retrieve properties of the target container.
        Returns azure.storage.blob.ContainerProperties.
        '''
        cc = self.containerclient
        if not cc:
            # already warned iff necessary
            return None
        try:
            return cc.get_container_properties()
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def storage_account_get(self):
        '''
        Retrieve attributes of the target storage account
        '''
        bsc = self.blobserviceclient
        if not bsc:
            # already warned iff necessary
            return None
        try:
            return bsc.get_account_information()
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def blob_write(self, data, blob_type=BlobType.BlockBlob, tags=None, overwrite=True, length=None):
        '''
        Write the given data to the target blob
        '''
        if not isinstance(self._name, BlobName):
            raise ApplicationException("may not %s for %r" % (self.mth(), self._name))
        tags = self._manager.tags_get(tags)
        bc = self.blobclient
        if not bc:
            raise ApplicationException("%s cannot get blobclient for %r" % (self.mth(), self._name))
        return bc.upload_blob(data, blob_type=blob_type, metadata=tags, overwrite=overwrite, length=length)

    def blob_names_iter_get(self, **kwargs):
        '''
        Return an iterator that walks blob names in the container
        '''
        if not isinstance(self._name, ContainerName):
            raise ApplicationException("may not %s for %r" % (self.mth(), self._name))
        cc = self.containerclient
        if not cc:
            return list()
        try:
            # https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.containerclient?view=azure-python#list-blobs-name-starts-with-none--include-none----kwargs-
            return cc.list_blobs(**kwargs)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return iter(list())
            raise

    def blob_names_list(self, blob_type=BlobType.BlockBlob, **kwargs):
        '''
        Return a list of BlobName objects. This is a hard fetch
        and consumes memory.
        '''
        ng = self.blob_names_iter_get(**kwargs)
        # ng is a generator that yields BlobProperties
        # pull it the painful way so we can trap exceptions properly and not discard the whole list
        ret = list()
        while True:
            try:
                b = next(ng)
            except StopIteration:
                break
            except Exception as exc:
                caught = laaso.msapicall.Caught(exc)
                if caught.is_missing():
                    break
                raise
            if (blob_type is not None) and (b.blob_type != blob_type):
                continue
            ret.append(BlobName(self._name.storage_account_name, b.container, b.name, subscription_id=self._name.subscription_id))
        return ret

    def container_names_list(self, **kwargs):
        '''
        Return a list of ContainerName objects. This is a hard fetch
        and consumes memory.
        '''
        bsc = self.blobserviceclient
        if not bsc:
            return list()
        try:
            # https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blobserviceclient?view=azure-python#list-containers-name-starts-with-none--include-metadata-false----kwargs-
            ng = bsc.list_containers(**kwargs)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return list()
            raise
        # ng is a generator that yields ContainerProperties
        # pull it the painful way so we can trap exceptions properly and not discard the whole list
        ret = list()
        while True:
            try:
                c = next(ng)
            except StopIteration:
                break
            except Exception as exc:
                caught = laaso.msapicall.Caught(exc)
                if caught.is_missing():
                    break
                raise
            ret.append(ContainerName(self._name.storage_account_name, c.name, subscription_id=self._name.subscription_id))
        return ret

    def blob_get_data(self, **kwargs):
        '''
        Return the blob contents as bytes.
        '''
        if not isinstance(self._name, BlobName):
            raise ApplicationException("may not %s for %r" % (self.mth(), self._name))
        bc = self.blobclient
        if not bc:
            return None
        downloader = bc.download_blob()
        # https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.storagestreamdownloader?view=azure-python#readall--
        # but the docs are generated from an incorrect comment in _download.py, so do
        # not believe the stuff about rtype. You get bytes. You cannot get anything
        # other than bytes.
        return downloader.readall(**kwargs)

class ResourceWrapper():
    '''
    Wrapper around a generic Azure SDK resource object.
    Provides some common attributes and methods to abstract
    away differences across resources.
    '''
    def __init__(self, resource, logger):
        self._resource = resource
        self.logger = logger
        try:
            self._id = self._resource.id
        except AttributeError as exc:
            raise ValueError("resource %r does not appear to be a standard Azure resource object (no id)" % self._resource) from exc
        if not isinstance(self._id, str):
            raise ValueError("resource %r does not appear to be a standard Azure resource object (id not str)" % self._resource)
        toks = self._id.split('/')
        self._toks = toks
        self._id_is_standard = not (toks[0] or (toks[1].lower() != 'subscriptions') or (toks[3].lower() != 'resourcegroups') or (toks[5].lower() != 'providers'))

    def __repr__(self):
        return "<%s,%r>" % (type(self).__name__, self._resource)

    @property
    def resource(self):
        '''
        Getter
        '''
        return self._resource

    @property
    def id(self):
        '''
        Getter
        '''
        return self._id

    @property
    def id_toks(self):
        '''
        Getter
        '''
        return self._toks

    @property
    def id_is_standard(self):
        '''
        Getter
        '''
        return self._id_is_standard

    @property
    def tags(self):
        '''
        Getter for tags. Always returns a dict.
        If there are no tags, the returned dict is empty.
        If tags cannot be determined, logs a warning and returns an empty dict.
        '''
        # resource.tags might be None - that's okay; treat it as an empty dict.
        # Only warn if there is no resource.tags.
        try:
            tags = self._resource.tags or dict()
        except AttributeError:
            tags = None
        if tags is None:
            self.logger.warning("cannot determine tags for %s:\n%s", self.thing, expand_item_pformat(self._resource))
            return dict()
        assert isinstance(tags, dict)
        return tags

    @property
    def resource_group(self):
        '''
        Getter for resource group
        '''
        return self._toks[4]

    @property
    def thing(self):
        '''
        Getter for the RP - eg 'Microsoft.Compute/disks'
        '''
        return '/'.join([self._toks[6], self._toks[7]])

    @property
    def wot(self):
        '''
        Getter for everything in the id past self.thing
        '''
        return '/'.join(self._toks[8:])

    @property
    def resource_provisioning_state(self):
        '''
        Getter for provisioning state if it can be determined.
        If it cannot, log a warning and return None.
        '''
        try:
            return self._resource.provisioning_state
        except AttributeError:
            pass

        try:
            return self._resource.properties.provisioning_state
        except AttributeError:
            pass

        self.logger.warning("cannot determine provisioning state for %s:\n%s", self.thing, expand_item_pformat(self._resource))
        return None

    @property
    def is_deleting(self):
        '''
        Return whether this resource is currently deleting.
        Uses self.resource_provisioning_state property, so if the provisioning state
        cannot be determined, it logs a warning. In that case, this returns False.
        '''
        provisioning_state = self.resource_provisioning_state
        return provisioning_state and (provisioning_state.lower() == 'deleting')

class Manager(laaso.common.ApplicationWithResourceGroup):
    '''
    Provide a stable API for interating with Azure and handling authentication.
    You'd think the SDKs would do that, but you'd be wrong.
    '''
    def __init__(self,
                 cert_name='',
                 clientids_filepath='',
                 disk_name='',
                 gallery_name='',
                 keyvault_name='',
                 keyvault_resource_group='',
                 location='',
                 managed_identity='',
                 managed_identity_client_id='',
                 nsg_name='',
                 nic_name='',
                 offer='',
                 op_resume_debug=False,
                 os_disk_size_force=False,
                 os_disk_size_gb=None,
                 pubkey_filename='',
                 pubkey_keyvault_client_id='',
                 pubkey_keyvault_name='',
                 publisher='',
                 secret_name='',
                 source_vm_name='',
                 storage_account='',
                 subnet_name='',
                 vm_boot_diags_storage_account='',
                 vm_image_name=None,
                 vm_image_resource_group='',
                 vm_image_subscription_id='',
                 vm_image_version='',
                 vm_resource_group='',
                 vm_size='',
                 vnet_gateway_name='',
                 vnet_name='',
                 vnet_resource_group='',
                 **kwargs):
        super().__init__(**kwargs)

        self.location = self.location_effective(location)

        self.cert_name = cert_name
        self.clientids_filepath = clientids_filepath or self.UAMI_CLIENTIDS_FILE_PATH
        self.disk_name = disk_name
        self.gallery_name = gallery_name or laaso.scfg.get('dev_gallery_name', '')
        self.keyvault_name = keyvault_name or laaso.scfg.get('pubkey_keyvault_name', '')
        self.keyvault_resource_group = keyvault_resource_group or self.subscription_value_get('infra_resource_group_default', '')
        self.nic_name = nic_name
        self.nsg_name = nsg_name
        self.offer = offer
        self.op_resume_debug = op_resume_debug
        self.os_disk_size_force = bool(os_disk_size_force)
        self.os_disk_size_gb = int(os_disk_size_gb) if os_disk_size_gb is not None else os_disk_size_gb
        self.pubkey_filename = pubkey_filename or self.pubkey_filename_default()
        self.pubkey_keyvault_client_id = pubkey_keyvault_client_id or ''
        self.pubkey_keyvault_name = pubkey_keyvault_name or ''
        self.publisher = publisher
        self.source_vm_name = source_vm_name
        self.secret_name = secret_name
        self.storage_account_name = storage_account or ''
        self.subnet_name = subnet_name or self.location_value_get('subnet', '')
        self.vm_boot_diags_storage_account = vm_boot_diags_storage_account or self.location_value_get('vm_boot_diags_storage_account_default', '') or ''
        self.vm_image_name = vm_image_name
        self.vm_image_resource_group = vm_image_resource_group or laaso.scfg.get('vm_image_resource_group_default', '')
        self.vm_image_subscription_id = vm_image_subscription_id or self.subscription_id
        self.vm_image_version = vm_image_version
        self.vm_resource_group = vm_resource_group or self.resource_group
        self.vm_size = vm_size or self.VM_SIZE_DEFAULT
        self.vnet_gateway_name = vnet_gateway_name
        self.vnet_name = vnet_name or self.location_value_get('vnet', '')
        self.vnet_resource_group_name = vnet_resource_group or self.subscription_value_get('vnet_resource_group_default', '')
        for attr in self.NONEMPTY_ATTRS:
            val = getattr(self, attr, '')
            if not val:
                raise self.exc_value("invalid %s" % attr)

        for attr in self.UUID_ATTRS:
            val = getattr(self, attr, '')
            if val and (not RE_UUID_ABS.search(val)):
                raise self.exc_value("invalid %s %r" % (attr, val))

        if self.pubkey_keyvault_client_id:
            self.pubkey_keyvault_client_id = laaso.util.uuid_normalize(self.pubkey_keyvault_client_id, key='pubkey_keyvault_client_id', exc_value=self.exc_value)

        self._metadata_service_lock = threading.Lock()
        self._metadata_api_version = None

        self._ansible_playbook_lock = threading.Lock()

        self._az_client_gen_lock = threading.RLock()

        self._az_kusto = dict() # key=URI value=KustoClient

        # ManagementClient wrappers
        # Do not access these directly - access them as self.az_* - eg self.az_compute
        self._az_authorization = None
        self._az_compute = None
        self._az_keyvault_mgmt = None
        self._az_msi = None
        self._az_network = None
        self._az_resource = None
        self._az_storage = None
        self._az_subscription = None

        self._managed_identity_lock = threading.RLock()
        self._managed_identity_azrid = None
        self._managed_identity_name = managed_identity or laaso.scfg.get('msi_client_id_default', '')
        if managed_identity_client_id:
            # Only update this if the caller provided something.
            self._pin_client_id = managed_identity_client_id

        # The client_id associated with self._managed_identity_name
        self._managed_identity_client_id_for_name = None

        # load VM user-assigned identities
        self.clientids_dict = dict()
        if self.clientids_filepath:
            try:
                with open(self.clientids_filepath, "r") as cfile:
                    cfile_dict = yaml.safe_load(cfile)
                    self.clientids_dict = cfile_dict.pop('client_ids', dict())
            except FileNotFoundError:
                pass
            except Exception as exc:
                self.logger.error("Non-existent or invalid clientid file %s", self.clientids_filepath)
                raise self.exc_value("unable to load invalid clientid file %s" % self.clientids_filepath) from exc

    def __repr__(self):
        return "<%s,subscription_id=%r>" % (type(self).__name__, self.subscription_id)

    RESOURCE_GROUP_HELP = 'resource group for resource group operations and default resource group for some other operations'

    OS_DISK_SIZE_GB_DEFAULT = 0
    VM_IMAGE_NAME_DEFAULT = ''
    VM_SIZE_DEFAULT = 'Standard_D2s_v3'

    DISK_AUTONAME_SUFFIX_DEFAULT = '-data-disk'
    DISK_HOMENAME_SUFFIX = '-home-disk'

    NONEMPTY_ATTRS = ('location',
                      'subscription_id',
                      'vm_size',
                     )

    UUID_ATTRS = ('subscription_id',
                  'tenant_id',
                  'vm_image_subscription_id',
                 )

    # on deployed nodes, uami/clientid pairs are listed in a yaml file
    # in dictionary format, where uami==user-assigned managed identities:
    # clientids:
    #   uami_id1: uami_client_id1
    #   uami_id2: uami_client_id2
    # loaded into self.clientids_dict
    # try out the clientids in this file when accessing a key vault and use the first
    # one that works.
    UAMI_CLIENTIDS_FILE_PATH = "/usr/laaso/etc/uami_clientids.yaml"

    _pin_client_id = ''

    @classmethod
    def pin_managed_identity_client_id(cls, client_id):
        '''
        This defaults objects to pinning client_id as the only
        auth for operations. This may be overridden by constructing
        the object with an explicit, alternate client_id, or by
        providing an alternate client_id to calls that accept
        client_id arguments. This is typically used by onbox things
        like the shepherd that have no user auth available.
        '''
        cls._pin_client_id = client_id

    @classmethod
    def arg_resource_group__default(cls):
        '''
        Return default resource_group for command-line.
        '''
        return os.environ.get('AZURE_TOOL_RESOURCE_GROUP', super().arg_resource_group__default())

    @property
    def require_msi(self):
        '''
        Return true if only managed_identity credentials must be used.
        This is the case when _pin_client_id is set.
        '''
        return bool(self._pin_client_id)

    @property
    def managed_identity_name(self):
        '''
        Getter
        '''
        return self._managed_identity_name

    @property
    def managed_identity_azrid(self):
        '''
        Getter; figures out managed_identity_azrid, caches, and returns it
        '''
        with self._managed_identity_lock:
            if self._managed_identity_azrid:
                return self._managed_identity_azrid
            if not self._managed_identity_name:
                return None
            if self._managed_identity_name.startswith('/'):
                self._managed_identity_azrid = AzResourceId.from_text(self._managed_identity_name,
                                                                      provider_name='Microsoft.ManagedIdentity',
                                                                      resource_type='userAssignedIdentities',
                                                                      exc_value=self.exc_value)
                return self._managed_identity_azrid
            self._managed_identity_azrid = laaso.identity.uami_azrid_from_str(self._managed_identity_name, self)
            if not self._managed_identity_azrid:
                raise self.exc_value(f"cannot resolve managed_identity {self._managed_identity_name!r} to ARM resource id")
            return self._managed_identity_azrid

    @property
    def managed_identity_client_id(self):
        '''
        Getter
        '''
        if self._pin_client_id:
            return self._pin_client_id
        if not self.managed_identity_azrid:
            return None
        with self._managed_identity_lock:
            if not self._managed_identity_client_id_for_name:
                uami = self.user_assigned_identity_get_by_id(self.managed_identity_azrid)
                if not uami:
                    if self._managed_identity_name.lower() == str(self.managed_identity_azrid).lower():
                        raise self.exc_value(f"managed_identity {self.managed_identity_azrid}) not found")
                    raise self.exc_value(f"managed_identity {self._managed_identity_name!r} (id {self.managed_identity_azrid}) not found")
                self._managed_identity_client_id_for_name = uami.client_id
            return self._managed_identity_client_id_for_name

    def nic_create_parameters(self, vmdesc, network_security_group_id=None, subnet_id=None, tags=None):
        '''
        Generate parameters for creating a NIC.
        If network_security_group_id is not specified, a
        suitable default is selected or the operation fails.
        '''
        if not self.vm_resource_group:
            raise ApplicationExit("'vm_resource_group' not specified")
        if not subnet_id:
            rg = self.vnet_resource_group_name or self.resource_group
            subnet_obj = self.subnet_get(vnet_resource_group_name=rg, vnet_name=self.vnet_name, subnet_name=self.subnet_name)
            if not subnet_obj:
                raise ApplicationExit(f"resource_group {rg!r} vnet {self.vnet_name!r} subnet {self.subnet_name!r} not found")
            subnet_id = subnet_obj.id
        network_security_group_id = self.network_security_group_id_effective(network_security_group_id, resource_group=self.resource_group)
        assert network_security_group_id
        nic_parameters = {'enable_accelerated_networking' : bool(vmdesc.accelerated_networking),
                          'enable_ip_forwarding' : False,
                          'location' : self.location,
                          'ip_configurations' : [{'name' : vmdesc.nic_name,
                                                  'private_ip_allocation_method' : 'Dynamic',
                                                  'public_ip_address' : {'id' : vmdesc.public_ip_id} if vmdesc.public_ip_id else None,
                                                  'subnet' : {'id' : subnet_id,
                                                             },
                                                 },
                                                ],
                          'network_security_group' : {'id' : network_security_group_id},
                          'tags' : self.tags_get(tags),
                         }
        return nic_parameters

    def arm_poller(self, operations):
        '''
        Return an ARM polling method wrapper usable for the given operations object
        as a polling_method (polling= arg to an operation).
        operations is something like self.az_network.network_interfaces
        msapiwrap will do this automatically under the covers as well.
        The advantage of doing this early and passing it to the call
        is it shortens the first polling period. If that does not matter,
        then it does not matter if this is used or not.
        '''
        poller = armpolling_obj_for_operations(operations)
        poller.logger = self.logger
        return poller

    def nic_create_issue(self, vmdesc, network_security_group_id=None, subnet_id=None, tags=None, verb='create'):
        '''
        Issue a create for the named nic. Save the op in vmdesc. Wait for it to create
        and return the result. If network_security_group_id is not specified, a
        suitable default is selected or the operation fails.
        '''
        nic_parameters = self.nic_create_parameters(vmdesc, network_security_group_id=network_security_group_id, subnet_id=subnet_id, tags=tags)
        self.logger.info("%s NIC %s/%s with parameters:\n%s", verb, self.vm_resource_group, vmdesc.nic_name, expand_item_pformat(nic_parameters))
        poller = self.arm_poller(self.az_network.network_interfaces)
        vmdesc.nic_create_op = self.az_network.network_interfaces.begin_create_or_update(self.vm_resource_group, vmdesc.nic_name, nic_parameters, polling=poller)

    def _nic_delete(self, nic_name, wait=False):
        '''
        Issue a delete for the named NIC
        '''
        self.logger.info("issue delete for nic '%s'", nic_name)
        poller = self.arm_poller(self.az_network.network_interfaces)
        delete_op = self.az_network.network_interfaces.begin_delete(self.vm_resource_group, nic_name, polling=poller)
        if wait:
            self.logger.info("wait for delete of nic '%s'", nic_name)
            delete_op.wait()
            self.logger.info("delete nic '%s' result %s", nic_name, expand_item(delete_op.result()))
        return delete_op

    @command.printable
    def nic_get(self, resource_group=None, nic_name=None):
        '''
        Return azure.mgmt.network.models.NetworkInterface or None
        '''
        resource_group = resource_group or self.vm_resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        nic_name = nic_name or self.nic_name
        if not nic_name:
            raise ApplicationExit("'nic_name' not specified")
        return self._nic_get(resource_group, nic_name)

    def _nic_get(self, resource_group, nic_name):
        '''
        Return azure.mgmt.network.models.NetworkInterface or None
        '''
        try:
            return self.az_network.network_interfaces.get(resource_group, nic_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def nic_get_by_id(self, nic_id):
        '''
        Given a nic id ('/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/nic-rg/providers/Microsoft.Network/networkInterfaces/nic-name')
        do a get and return the NetworkInterface or None for not-found
        '''
        azrid = AzResourceId.from_text(nic_id, subscription_id=self.subscription_id, provider_name='Microsoft.Network', resource_type='networkInterfaces')
        return self._nic_get(azrid.resource_group_name, azrid.resource_name)

    def nic_list(self, resource_group=None):
        '''
        List all NICs in the resource_group.
        '''
        resource_group = resource_group or self.vm_resource_group
        assert resource_group
        return self.az_network.network_interfaces.list(resource_group)

    def nic_list_from_vms(self, resource_group=None):
        '''
        Return list of NICs belonging to VMs in resource group that are
        not tagged with status "discarded".
        '''
        vm_list = self.vm_list(resource_group=resource_group)
        nic_list = list()
        for vm in vm_list:
            if vm.tags and vm.tags.get('status', '') == 'discarded':
                continue
            for nic in vm.network_profile.network_interfaces:
                nic = self.nic_get_by_id(nic.id)
                nic_list.append(nic)
        return nic_list

    @command.printable_vm_name
    def vm_nic_get(self, vm_name):
        '''
        Return the NIC for a VM. Returns None if the VM or NIC does not exist.
        '''
        vm = self.vm_get(vm_name)
        if not vm:
            return None
        for nic in vm.network_profile.network_interfaces:
            nic_id_split = nic.id.split('/')
            nic_name = nic_id_split[-1]
            nic_rg = nic_id_split[4]
            return self.nic_get(resource_group=nic_rg, nic_name=nic_name)

    def public_ip_get(self, public_ip_name=None, resource_group=None):
        '''
        Fetch a public ip: azure.mgmt.network.models.PublicIPAddress or None for not-found
        '''
        if not public_ip_name:
            raise ApplicationExit("'public_ip_name' not specified")
        resource_group = resource_group or self.resource_group
        if not resource_group:
            self.logger.error("'resource_group' not specified")
            raise ApplicationExit(1)
        return self._public_ip_get(resource_group, public_ip_name)

    def _public_ip_get(self, resource_group, public_ip_name):
        '''
        Return azure.mgmt.network.models.PublicIPAddress or None
        '''
        try:
            return self.az_network.public_ip_addresses.get(resource_group, public_ip_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def tags_get(self, *args, **kwargs):
        '''
        Generate standard Azure tags dict for new resources
        '''
        ret = {'owner' : self.username}
        for d in args:
            if d:
                assert isinstance(d, dict)
                ret.update(d)
        ret.update(kwargs)
        assert all(isinstance(x, str) for x in ret.values())
        return ret

    def vm_create(self, vmdesc, image=None, wait=False, network_security_group_id=None, subnet_id=None, tags=None):
        '''
        Do stuff to create the VM
        '''
        if not self.vm_resource_group:
            raise ApplicationExit("vm_resource_group not specified")

        tags = self.tags_get(tags)
        admin_username = vmdesc.admin_username or self.username
        if not self.pubkey_filename:
            raise ApplicationExit("No pubkey_filename specified")
        if not os.path.isfile(self.pubkey_filename):
            raise ApplicationExit("%r is not a file" % self.pubkey_filename)
        with open(self.pubkey_filename, "r") as f:
            public_key = f.read().strip()
        pubkey_path_on_vm = "/home/%s/.ssh/authorized_keys" % admin_username

        image_id_resolved = self.vm_image_id_resolve(image)
        if not image_id_resolved:
            raise ApplicationExit("cannot resolve image_id %r" % image)

        if not vmdesc.nic_obj:
            if not vmdesc.nic_create_op:
                self.nic_create_issue(vmdesc, network_security_group_id=network_security_group_id, subnet_id=subnet_id, tags=tags)
            vmdesc.nic_create_op_wait(self.logger)
        nic_objs = [vmdesc.nic_obj]
        nic_list = [{'id' : nic_obj.id, 'properties' : {'primary' : False}} for nic_obj in nic_objs]
        nic_list[0]['properties']['primary'] = True

        try:
            return self._vm_create(vmdesc, image_id_resolved, nic_list, admin_username, public_key, pubkey_path_on_vm, tags=tags, wait=wait)
        except Exception as exc:
            self.logger.error("VM creation failed: %r\n%s\n%s", exc, expand_item_pformat(exc, noexpand_types=AZURE_NOEXPAND_TYPES), traceback.format_exc().rstrip())

        raise ApplicationExit("VM creation failed (%s/%s/%s)" % (self.subscription_id, self.vm_resource_group, vmdesc.vm_name))

    def _vm_create(self, vmdesc, image_id, nic_list, admin_username, public_key, pubkey_path_on_vm, tags=None, wait=False):
        '''
        Core of vm_create()
        vmdesc: VMDesc
        image_id: fully resolved image ID
        nic_list: NetworkInterfaceReference[] (https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/createorupdate#networkinterfacereference)
        admin_username: str, username for admin account generated at boot time
        pubkey_path_on_vm: str, path on the new VM where the public key for admin_username is stored
        '''
        image_reference = self.vm_image_reference(image_id)

        adminpw = f"{vmdesc.vm_name}-apw"
        output_redact('admin_password', adminpw)

        vm_parameters = {'diagnostics_profile' : {'boot_diagnostics' : {'enabled' : bool(vmdesc.boot_diag_enable)},
                                                 },
                         'hardware_profile' : {'vm_size' : vmdesc.vm_size,
                                              },
                         'location' : self.location,
                         'network_profile' : {'network_interfaces' : nic_list,
                                             },
                         'os_profile' : {'admin_password' : adminpw,
                                         'admin_username' : admin_username,
                                         'computer_name' : vmdesc.vm_name,
                                         'custom_data' : vmdesc.custom_data,
                                         'linux_configuration' : {'disable_password_authentication' : True,
                                                                  'provision_vm_agent' : True,
                                                                  'ssh' : {'public_keys' : [{'key_data' : public_key,
                                                                                             'path' : pubkey_path_on_vm,
                                                                                            },
                                                                                           ],
                                                                          }
                                                                 },
                                        },
                         'storage_profile' : {'data_disks' : [],
                                              'image_reference' : image_reference,
                                              'os_disk': {'caching' : 'None',
                                                          'create_option': 'FromImage',
                                                          'managed_disk' : {'storage_account_type' : VM_OS_DISK_STORAGE_ACCOUNT_TYPE_DEFAULT.value,
                                                                           },
                                                          'name' : vmdesc.osdisk_name,
                                                          'os_type' : 'Linux',
                                                         },
                                             },
                         'tags' : self.tags_get(tags),
                        }

        if vmdesc.boot_diag_enable and vmdesc.boot_diag_use_storage_account_iff_available and self.vm_boot_diags_storage_account:
            vm_parameters['diagnostics_profile']['boot_diagnostics']['storage_uri'] = self.storage_account_blob_url(storage_account_name=self.vm_boot_diags_storage_account)

        if self.managed_identity_azrid:
            vm_parameters['identity'] = {'type' : ResourceIdentityType.user_assigned,
                                         'user_assigned_identities' : {str(self.managed_identity_azrid) : {}}
                                        }
        if self.os_disk_size_gb:
            vm_parameters['storage_profile']['os_disk']['disk_size_gb'] = int(self.os_disk_size_gb)

        self.logger.info("create VM %s/%s with with parameters:\n%s", self.vm_resource_group, vmdesc.vm_name, expand_item_pformat(vm_parameters))
        vm_op = self.az_compute.virtual_machines.begin_create_or_update(self.vm_resource_group, vmdesc.vm_name, vm_parameters)
        vmdesc.vm_create_op = vm_op
        if wait:
            self.vm_create_wait(vmdesc.vm_name, vm_op)
        return vmdesc

    def polling_op_operation_id(self, op):
        '''
        Given a polling op, return a best guess at the operation ID for the op.
        A polling op is a result from a long-running operation such as vm.begin_create_or_update
        or deployments.begin_create_or_update.
        '''
        if isinstance(op, azure.mgmt.resource.resources.models.DeploymentExtended):
            try:
                # Not really a polling op - the deployment is running in the background,
                # and this is the result of creating the deployment.
                # There's no operation_id in this object, so return what we have.
                return op.properties.correlation_id
            except Exception as exc:
                self.logger.warning("%s op.properties.correlation_id %r", self.mth(), exc)
            return None

        operation_id = getattr(op, 'operation_id', None)
        if operation_id:
            return operation_id

        operation_id_get = getattr(op, 'operation_id_get', None)
        if operation_id_get:
            return operation_id_get()

        try:
            _polling_method = op._polling_method # pylint: disable=protected-access
        except Exception as exc:
            self.logger.warning("%s op._polling_method %r", self.mth(), exc)
            return None

        if _polling_method:
            operation_id = getattr(_polling_method, 'operation_id', None)
            if operation_id:
                return operation_id

        try:
            _operation = _polling_method._operation # pylint: disable=protected-access
        except Exception as exc:
            self.logger.warning("%s op._polling_method._operation %r", self.mth(), exc)
            return None

        if isinstance(_operation, msrestazure.polling.arm_polling.LongRunningOperation):
            try:
                status_link = _operation.get_status_link()
            except msrestazure.polling.arm_polling.BadResponse:
                if _operation.method == 'PATCH':
                    status_link = _operation.initial_response.request.url
                else:
                    status_link = ''
            if status_link and isinstance(status_link, str):
                path = ''
                try:
                    parsed = urllib.parse.urlparse(status_link)
                except Exception as exc:
                    self.logger.warning("%s op._polling_method._operation.get_status_link()=%r cannot parse: %r", self.mth(), status_link, exc)
                    parsed = None
                if parsed:
                    path = getattr(parsed, 'path', '')
                if path:
                    pathtoks = path.split('/')
                    if (len(pathtoks) >= 2) and (pathtoks[-2].lower() == 'operations'):
                        return pathtoks[-1]

        try:
            location_url = _operation.location_url
        except Exception as exc:
            self.logger.warning("%s op._polling_method._operation.location_url %r", self.mth(), exc)
            return None

        if not location_url:
            # If we have an operation_id attribute, then either the SDK version we are using
            # contains bugfixes/improvements that obviate it or we are going through a LaaSO
            # wrapper. Either way, it is more likely that the operation should not have
            # an ID (for example, a no-op patch) than it is that this is a problem, so only
            # log a warning when there is no operation_id attribute.
            if not hasattr(_operation, 'operation_id'):
                self.logger.warning("%s op._polling_method._operation.location_url for %s is %r; returning None", self.mth(), type(_operation), location_url)
            return None

        try:
            toks = location_url.split('/')
        except Exception as exc:
            self.logger.warning("%s op._polling_method._operation.location_url.split('/') %r %r", self.mth(), location_url, exc)
            return None
        prev_tok = toks[0]
        for tok in toks[1:]:
            if prev_tok.lower() == 'operations':
                m = RE_UUID_RE.search(tok)
                if m:
                    return m.group(0)
                break
            prev_tok = tok
        self.logger.warning("%s cannot parse op._polling_method._operation.location_url %r", self.mth(), location_url)
        return None

    def vm_create_wait(self, vm_name, vm_op, log_level=logging.INFO):
        '''
        Wait for an op returned by _vm_create() to complete
        '''
        self.logger.log(log_level, "VM create %s wait (op %s)", vm_name, self.polling_op_operation_id(vm_op))
        vm_op.wait()
        vm_res = vm_op.result()
        # Call self.polling_op_operation_id() again rather than doing it once and
        # caching because self.polling_op_operation_id() is a hack that tries to
        # figure it out from undocumented, private interfaces and the answer might
        # change or improve.
        self.logger.log(log_level, "VM create %s (op %s) result\n%s", vm_name, self.polling_op_operation_id(vm_op), expand_item_pformat(vm_res))
        return vm_res

    @command.simple
    def image_list_print(self, **kwargs):
        '''
        List available managed images in the resource group or subscription
        '''
        try:
            resource_group = kwargs.pop('resource_group')
        except KeyError:
            resource_group = self.vm_image_resource_group
        if kwargs:
            raise TypeError("unexpected argument(s) %s" % sorted(kwargs.keys()))
        if resource_group:
            image_iter = self.az_compute.images.list_by_resource_group(resource_group)
        else:
            image_iter = self.az_compute.images.list()
        image_names = ["%s/%s" % (x.id.split('/')[4], x.name) for x in image_iter]
        image_names.sort()
        for image_name in image_names:
            print(image_name)

    @command.simple
    def vm_image_list_publishers_print(self):
        '''
        List available image publishers
        '''
        xs = self.az_compute.virtual_machine_images.list_publishers(self.location)
        xs.sort(key=lambda x: x.name)
        names = [x.name for x in xs]
        for name in names:
            print(name)

    @command.simple
    def vm_image_list_offers_print(self):
        '''
        List available offers from self.publisher
        '''
        if not self.publisher:
            self.logger.error("'publisher' not specified")
            raise ApplicationExit(1)
        xs = self.az_compute.virtual_machine_images.list_offers(self.location, self.publisher)
        xs.sort(key=lambda x: x.name)
        names = [x.name for x in xs]
        for name in names:
            print(name)

    @command.simple
    def vm_image_list_skus_print(self):
        '''
        List available skus from self.publisher/self.offer
        '''
        if not self.publisher:
            self.logger.error("'publisher' not specified")
            raise ApplicationExit(1)
        if not self.offer:
            self.logger.error("'offer' not specified")
            raise ApplicationExit(1)
        xs = self.az_compute.virtual_machine_images.list_skus(self.location, self.publisher, self.offer)
        xs.sort(key=lambda x: x.id)
        names = [x.name for x in xs]
        for name in names:
            print(name)

    def vm_get(self, vm_name, resource_group=None, subscription_id=None):
        '''
        Retrieve VM info. Returns None if no such VM.
        '''
        resource_group = resource_group or self.vm_resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        subscription_id = subscription_id or self.subscription_id
        return self._vm_get(subscription_id, resource_group, vm_name)

    def vm_get_by_id(self, vm_id):
        '''
        Given vm_id as resource_id str or AzResourceId, return azure.mgmt.compute.models.VirtualMachine or None
        '''
        if isinstance(vm_id, AzResourceId):
            azrid = vm_id
        else:
            azrid = AzResourceId.from_text(vm_id)
        if not azrid.values_match(provider_name='Microsoft.Compute', resource_type='virtualMachines'):
            raise ValueError(f"{azrid!r} is not a virtual machine resource")
        return self._vm_get(azrid.subscription_id, azrid.resource_group_name, azrid.resource_name)

    def _vm_get(self, subscription_id, resource_group, vm_name):
        '''
        Return VirtualMachine or None
        '''
        try:
            az_compute = self.az_compute_get(subscription_id)
            return az_compute.virtual_machines.get(resource_group, vm_name, expand='instanceView')
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def vm_delete(self, vm_name, resource_group=None, wait=True, verbose=True):
        '''
        Delete VM after resource group check
        '''
        resource_group = resource_group or self.vm_resource_group
        if self.vm_get(vm_name, resource_group):
            return self._vm_delete(resource_group, vm_name, wait, verbose)
        return None

    def _vm_delete(self, resource_group, vm_name, wait, verbose):
        '''
        VM delete completes asynchronously if wait is set to False.
        '''
        try:
            poller = self.arm_poller(self.az_compute.virtual_machines)
            op = self.az_compute.virtual_machines.begin_delete(resource_group, vm_name, polling=poller)
            if verbose:
                self.logger.info("delete virtual machine %s operation_id %r", vm_name, self.polling_op_operation_id(op))
            if wait:
                self.vm_delete_op_wait(vm_name, op, verbose)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                if verbose:
                    self.logger.info("virtual machine %s does not exist", vm_name)
                return None
            self.logger.warning("cannot delete virtual machine %r [%s]: %r", vm_name, caught.reason(), exc)
            raise
        return op

    def vm_delete_op_wait(self, vm_name, op, verbose):
        '''
        wait for VM delete operation to complete
        '''
        if verbose:
            self.logger.info("wait for virtual machines %s delete", vm_name)
        op.wait()
        if verbose:
            self.logger.info("virtual machine %s deleted", vm_name)

    @staticmethod
    def vm_id_decompose(vm_id):
        '''
        Given a VM id, return (subscription_id, resource_group, vm_name).
        Example ID:
            /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/somerg/providers/Microsoft.Compute/virtualMachines/some-vm
        '''
        toks = vm_id.split('/')
        if len(toks) != 9:
            raise ValueError("invalid vm_id (len %d)" % len(toks))
        expect_toks = ((1, 'subscriptions'),
                       (3, 'resourcegroups'),
                       (5, 'providers'),
                       (6, 'microsoft.compute'),
                       (7, 'virtualmachines'),
                      )
        for et in expect_toks:
            if toks[et[0]].lower() != et[1]:
                raise ValueError("invalid vm_id (unexpected tok %r index %d)" % (toks[et[0]], et[0]))
        if not RE_UUID_ABS.search(toks[2]):
            raise ValueError("invalid vm_id (invalid subscription id %r)" % toks[2])
        return (toks[2], toks[4], toks[8])

    @command.vm_name
    def vm_print(self, vm_name):
        '''
        Retrieve and print VM info
        '''
        if not vm_name:
            self.logger.error("vm_name not specified")
            raise ApplicationExit(1)
        res = self.vm_get(vm_name)
        if res:
            pprint.pprint(expand_item(res))
        else:
            print("'%s' not found in resource_group '%s'" % (vm_name, self.vm_resource_group))

    def client_ids_get(self, add_default_creds=False, client_id=None):
        '''
        Return a list of client_ids caller can use to iterate through the VM's assigned identities
        order of precedence:
         1. client_id argument
         2. self._pin_client_id
            When self._pin_client_id is set, we are pinned to doing all
            auth with it. self.managed_identity_client_id evaluates to this, but when
            managed_identity is provided at init time and managed_identity_client_id
            is not, we are not pinned, and the self.managed_identity_client_id getter
            will attempt to fetch the ARM resource for self.managed_identity_azrid.
            We do not want that here, because we are not pinned to using
            managed_identity_client_id, and attempting to do so creates a recursive
            call, because that getter could be calling us.
         3. self.clientids_dict (loaded from clientids file)
        The returned list is guaranteed unique, not shared
        For convenience, when client_id is a sequence, the caller may include
        the value None as shorthand for add_default_creds=True.
        '''
        client_id = client_id or self._pin_client_id
        ret = list()
        if client_id:
            if isinstance(client_id, (list, tuple)):
                for x in client_id:
                    if not x:
                        add_default_creds = True
                    else:
                        ret.extend(self.client_ids_get(client_id=x))
            else:
                if isinstance(client_id, AzCred):
                    ret.append(client_id)
                else:
                    ret.append(laaso.identity.client_id_from_uami_str(client_id, self, resolve_using_azmgr=False))
        elif self.clientids_dict:
            ret.extend(self.clientids_dict.values())
        if not (self._pin_client_id or client_id):
            add_default_creds = True
        if add_default_creds:
            ret.append(None)
        return ret

    def vm_power_off(self, vm_resource_group, vm_name):
        '''
        Stop (power off) a VM. This does not deallocate it.
        '''
        if not vm_resource_group:
            raise ApplicationExit("'vm_resource_group' not specified")
        if not vm_name:
            raise ApplicationExit("'vm_name' not specified")
        while True:
            poller = self.arm_poller(self.az_compute.virtual_machines)
            power_off_op = self.az_compute.virtual_machines.begin_power_off(vm_resource_group, vm_name, polling=poller)
            power_off_operation_id = self.polling_op_operation_id(power_off_op)
            self.logger.info("VM %r power_off wait operation_id=%s", vm_name, power_off_operation_id)
            power_off_op.wait()
            power_off_res = power_off_op.result()
            self.logger.info("VM %r power_off operation_id=%s result:\n%s", vm_name, power_off_operation_id, expand_item_pformat(power_off_res))
            vm_obj = self.vm_get(vm_name, resource_group=vm_resource_group)
            if not vm_obj:
                self.logger.error("VM %r disappeared following power off operation_id=%s", vm_name, power_off_operation_id)
                raise ApplicationExit("VM %r disappeared following power off" % vm_name)
            if not vm_obj.instance_view:
                self.logger.warning("VM %r has no instance_view following power off operation_id=%s (will retry)", vm_name, power_off_operation_id)
                continue
            if not vm_obj.instance_view.statuses:
                self.logger.warning("VM %r instance_view has no statuses following power off operation_id=%s (will retry)", vm_name, power_off_operation_id)
                continue
            status_code = vm_obj.instance_view.statuses[-1].code
            if status_code != 'PowerState/stopped':
                self.logger.warning("VM %r completed power_off operation_id=%s but has status %r",
                                    vm_name, power_off_operation_id, status_code)
                continue
            # VM is stopped
            break
        self.logger.info("VM %r status %r following power off", vm_name, status_code)

    def vm_generalize(self, vm_resource_group, vm_name):
        '''
        Generalize the named VM
        '''
        generalize_res = self.az_compute.virtual_machines.generalize(vm_resource_group, vm_name)
        self.logger.info("VM %r generalize result:\n%s", vm_name, expand_item_pformat(generalize_res))

    @command.simple
    def vm_sizes_print(self):
        '''
        Print vm sizes
        '''
        vm_size_iter = self.az_compute.virtual_machine_sizes.list(location=self.location)
        for vm_size_obj in vm_size_iter:
            print(expand_item_pformat(vm_size_obj))

    @command.printable
    def disk_get(self, disk_name=None, resource_group=None):
        '''
        Return azure.mgmt.compute.models.Disk or None
        '''
        disk_name = disk_name or self.disk_name
        resource_group = resource_group or self.resource_group
        if not disk_name:
            raise ApplicationExit("'disk_name' not specified")
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        return self._disk_get(resource_group, disk_name)

    def _disk_get(self, resource_group, disk_name):
        '''
        Return azure.mgmt.compute.models.Disk or None
        '''
        try:
            return self.az_compute.disks.get(resource_group, disk_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def vm_primary_nic_addr_get(self, vm_info):
        '''
        Extract the primary network address from vm_info as returned by vm_get()
        '''
        if len(vm_info.network_profile.network_interfaces) == 1:
            # Special case; not always marked as primary
            nic = vm_info.network_profile.network_interfaces[0]
        else:
            for nic in vm_info.network_profile.network_interfaces:
                if nic.primary:
                    break
            else:
                self.logger.error("No primary NIC for VM %s", vm_info.name)
                return None
        nic_info = self.nic_get_by_id(nic.id)
        if not nic_info:
            self.logger.warning("VM %s has NIC %s which does not exist", vm_info.id, nic.id)
            return None
        config = None
        for config in nic_info.ip_configurations:
            if config.primary:
                return config.private_ip_address
        self.logger.warning("no primary config found for NIC %s", nic_info.id)
        return None

    @command.printable
    def deployment_get(self, deployment_name, resource_group=None, subscription_id=None, pretty=False):
        '''
        retrieve a deployment to list all resource provisioned/deployed
        '''
        resource_group = resource_group or self.resource_group
        if not resource_group:
            self.logger.error("'resource_group' not specified")
            raise ApplicationExit(1)
        subscription_id = subscription_id or self.subscription_id
        if not subscription_id:
            self.logger.error("'subscription_id' not specified")
            raise ApplicationExit(1)
        az_resource = self.az_resource_get(subscription_id)
        try:
            deployment = az_resource.deployments.get(deployment_name=deployment_name, resource_group_name=resource_group)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            self.logger.info('exception raised while deploying %r in RG %r', deployment_name, resource_group)
            if caught.is_missing():
                return None
            raise
        if not pretty:
            return deployment
        ret = {'additional_properties' : deployment.additional_properties,
               'id' : deployment.id,
               'location' : deployment.location,
               'name' : deployment.name,
               'correlation_id' : deployment.properties.correlation_id,
               'error' : deployment.properties.error,
               'output_resources': deployment.properties.output_resources,
               'provisioning_state' : deployment.properties.provisioning_state,
               'timestamp' : deployment.properties.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'),
              }
        return ret

    @command.printable
    def deployments_list_failed_by_resource_group(self, resource_group=None, pretty=False):
        '''
        Retrieve failed deployments for the given resource_group
        '''
        resource_group = resource_group or self.resource_group
        if not resource_group:
            self.logger.error("'resource_group' not specified")
            raise ApplicationExit(1)
        try:
            deployments = [x for x in self.az_resource.deployments.list_by_resource_group(resource_group) if x.properties.error is not None]
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise
        if not pretty:
            return deployments
        ret = list()
        for d in deployments:
            ret.append({'additional_properties' : d.additional_properties,
                        'id' : d.id,
                        'location' : d.location,
                        'name' : d.name,
                        'correlation_id' : d.properties.correlation_id,
                        'error' : d.properties.error,
                        'provisioning_state' : d.properties.provisioning_state,
                        'timestamp' : d.properties.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'),
                       })
        return ret

    @command.simple
    def deployments_log_failed_by_resource_group(self, resource_group=None, logger=None, log_level=logging.ERROR, pretty=False):
        '''
        Retrieve failed deployments for the given resource_group and log them.
        Log and swallow Exceptions.
        '''
        logger = logger if logger is not None else self.logger
        resource_group = resource_group or self.resource_group
        if not resource_group:
            self.logger.error("'resource_group' not specified")
            raise ApplicationExit(1)
        try:
            failures = self.deployments_list_failed_by_resource_group(resource_group=resource_group, pretty=pretty)
        except Exception as exc:
            logger.error("cannot retrieve deployments for resource_group %r: %r\n%s",
                         resource_group, exc, expand_item_pformat(exc))
            return
        if failures is None:
            logger.log(log_level, "cannot retrieve deployments for resource_group %r because it does not exist",
                       resource_group)
            return
        if not failures:
            logger.log(log_level, "no failed deployments for resource_group %r",
                       resource_group)
            return
        s = ' (simplified)' if pretty else ''
        logger.log(log_level, "failed deployments%s for resource_group %r:\n%s",
                   s, resource_group, expand_item_pformat(failures))

    def vm_find(self, vm_name):
        '''
        Return a list of VMs found across resource groups for the subscription
        '''
        rgs = self.resource_groups_list()
        ret = list()
        for rg in rgs:
            vm = self.vm_get(vm_name, resource_group=rg.name)
            if vm:
                ret.append(vm)
        return ret

    @command.vm_name
    def vm_find_print(self, vm_name):
        '''
        Print IDs of VMs with this name in the subscription
        '''
        vms = self.vm_find(vm_name)
        vms.sort(key=lambda x: x.id)
        for vm in vms:
            print(vm.id)

    # Shared across instances so that different threads/applications
    # using different managers serialize against one another.
    _resource_group_create_lock = threading.RLock()

    @property
    def resource_group_create_lock(self):
        '''
        Getter
        '''
        return self._resource_group_create_lock

    @command.simple
    def resource_group_create_iff_necessary(self, resource_group=None, location=None, tags=None):
        '''
        Create resource_group
        '''
        resource_group = resource_group or self.resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        with self.resource_group_create_lock:
            resource_group_obj = self.resource_group_get(resource_group=resource_group)
            if resource_group_obj:
                self.logger.debug("resource_group %s already exists", resource_group)
                return resource_group_obj
            ret = self.resource_group_create(resource_group=resource_group, location=location, tags=tags)
            self.logger.debug("created resource_group %s", resource_group)
            return ret

    _resource_groups_created = list()

    @property
    def resource_groups_created(self):
        '''
        Getter
        '''
        return list(self._resource_groups_created)

    @command.simple
    def resource_group_create(self, resource_group=None, location=None, tags=None):
        '''
        Create resource_group. Return azure.mgmt.resource.resources.models.ResourceGroup.
        '''
        resource_group = resource_group or self.resource_group
        location = location or self.location
        if not resource_group:
            self.logger.error("'resource_group' not specified")
            raise ApplicationExit(1)
        parameters = {'location': location,
                      'tags': self.tags_get(tags),
                      }
        self.logger.info("create resource_group %s with parameters:\n%s", resource_group, expand_item_pformat(parameters))
        res = self._resource_group_create_or_update(resource_group, parameters)
        self.logger.info("resource_group %s create result:\n%s", resource_group, expand_item_pformat(res))
        if res:
            self._resource_groups_created.append(res)
        return res

    @command.wait
    def resource_group_delete(self, resource_group=None, wait=False, verbose=True):
        '''
        Issue resource group delete and return the op. Returns None
        if the resource_group does not exist.
        '''
        resource_group = resource_group or self.resource_group
        if not resource_group:
            self.logger.error("'resource_group' not specified")
            raise ApplicationExit(1)
        if any(resource_group.lower() == x.lower() for x in laaso.scfg.tget('resource_groups_keep', tuple)):
            raise ResourceGroupMayNotBeDeleted(f"policy forbids deleting resource_group {resource_group!r}")
        if verbose:
            self.logger.info("delete resource group %s", resource_group)
        poller = self.arm_poller(self.az_compute.gallery_images)
        try:
            op = self.az_resource.resource_groups.begin_delete(resource_group, polling=poller)
            # Do the wait in this block to get the logging
            if wait:
                self.resource_group_delete_op_wait(resource_group, op, verbose=verbose)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                if verbose:
                    self.logger.info("resource group %s does not exist", resource_group)
                return None
            self.logger.warning("cannot delete resource group %r [%s]: %r", resource_group, caught.reason(), exc)
            raise
        return op

    def resource_group_delete_op_wait(self, resource_group, op, verbose=True):
        '''
        Wait for a resource_group_delete operation to complete
        '''
        if verbose:
            self.logger.info("wait for resource group %s delete", resource_group)
        op.wait()
        if verbose:
            self.logger.info("resource group %s deleted", resource_group)

    def vmdescs_generate(self, vm_names, nic_names=None, custom_data=None, public_ip_id=None):
        '''
        Generate and return a list of VMDesc objects for the given vm_names.
        If provided, nic_names must be an identical length of names for the NICs.
        '''
        vm_size = self.vm_size
        nic_names = nic_names or [None for _ in range(len(vm_names))]
        return [VMDesc(vm_name,
                       vm_size,
                       nic_name=nic_name,
                       custom_data=custom_data,
                       accelerated_networking=self.vm_size_supports_accelerated_networking(vm_size),
                       public_ip_id=public_ip_id)
                for vm_name, nic_name in zip(vm_names, nic_names)]

    def vms_create(self, vm_names, image=None, tags=None, wait=True, network_security_group_id=None, subnet_id=None, **kwargs):
        '''
        Create multiple VMs. Generate the vmdescs and invoke vm_create_do.
        '''
        vmdescs = self.vmdescs_generate(vm_names, **kwargs)
        return self.vms_create_do(vmdescs, image=image, tags=tags, wait=wait, network_security_group_id=network_security_group_id, subnet_id=subnet_id)

    def vms_create_do(self, vmdescs, image=None, tags=None, wait=True, network_security_group_id=None, subnet_id=None):
        '''
        Perform the creates for each VMDesc in vmdescs.
        '''
        if not vmdescs:
            self.logger.warning("%s.%s: no vmdescs", type(self).__name__, getframename(0))
            return vmdescs
        for vmdesc in vmdescs:
            # Optimization: skip the get if the caller did not provide a NIC name
            if vmdesc.nic_name_provided:
                vmdesc.nic_obj = self.nic_get(resource_group=self.vm_resource_group, nic_name=vmdesc.nic_name)
            if not vmdesc.nic_obj:
                self.nic_create_issue(vmdesc, network_security_group_id=network_security_group_id, subnet_id=subnet_id)
        for vmdesc in vmdescs:
            self.vm_create(vmdesc, wait=False, image=image, tags=tags)
        if wait:
            for vmdesc in vmdescs:
                vmdesc.vm_create_res = self.vm_create_wait(vmdesc.vm_name, vmdesc.vm_create_op)
            self.vmdescs_log(vmdescs)
        return vmdescs

    def vmdescs_log(self, vmdescs):
        '''
        Log a list of vmdescs
        '''
        vmdescs = sorted(vmdescs, key=lambda x: x.vm_name)
        self.logger.info("VMs:\n%s", '\n'.join([x.log_ip_str() for x in vmdescs]))

    @staticmethod
    def sku_capability_get_int(sku, name, *args):
        '''
        Fetch the named capability from a ResourceSku
        '''
        assert len(args) < 2
        for cap in sku.capabilities:
            if cap.name == name:
                return int(cap.value)
        if args:
            return int(args[0])
        raise SkuCapabilityMissingException(name)

    def vm_sku_get_vcpus_effective(self, sku, exit_on_error=False):
        '''
        Given a ResourceSku for a VM, return the effective
        number of vcpus (cores)
        '''
        if sku.resource_type != 'virtualMachines':
            raise ValueError("sku %r resource_type=%r is not a virtual machine" % (sku.name, sku.resource_type))
        try:
            vcpus = self.sku_capability_get_int(sku, 'vCPUs')
            vcpus_available = self.sku_capability_get_int(sku, 'vCPUsAvailable', vcpus)
        except SkuCapabilityMissingException as exc:
            if exit_on_error:
                self.logger.error("SKU %s missing capability %s%s\nSKU %s missing capability %s",
                                  sku.name, exc.capability_name,
                                  expand_item_pformat(sku),
                                  sku.name, exc.capability_name)
                raise ApplicationExit(1) from exc
            raise
        # vcpus_available less than vcpus is okay - that's just CPUs
        # disabled, which is the goal of several SKUs.
        if vcpus_available > vcpus:
            self.logger.error("SKU %s has inconsistent vcpus=%s vs vcpus_available=%s\n"
                              "%s\n"
                              "SKU %s has inconsistent vcpus=%s vs vcpus_available=%s",
                              sku.name, vcpus, vcpus_available,
                              expand_item_pformat(sku),
                              sku.name, vcpus, vcpus_available)
            raise ApplicationExit(1)
        return vcpus_available

    def vm_size_exists(self, vm_size):
        '''
        Check that VM size is valid
        Return True iff size is in skus_dict; False otherwise
        '''
        return vm_size in self.vm_skus_dict

    def vm_sku_in_location(self, vm_size, location=None):
        '''
        Return the ResourceSku for the given vm_size in the given location,
        or None if no such exists or is unavailable to the caller.
        '''
        location = location or self.location
        if not location:
            raise ApplicationExit("'location' not specified")
        by_location = self.vm_skus_dict.get(vm_size, dict())
        skus = by_location.get(location.lower(), list())
        for sku in skus:
            if sku_location_info_get(sku, location):
                return sku
        return None

    def vm_size_supports_nvme(self, vm_size):
        '''
        Return whether this vm_size supports NVME devices.
        '''
        by_location = self.vm_skus_dict.get(vm_size, dict())
        # All SKUs are the same in this respect, so just use the first one we find
        for skus in by_location.values():
            for sku in skus:
                return sku_supports_data_disk_type(sku, DataDiskType.NVME, self.logger)
        return False

    @command.printable
    def vm_size_supports_accelerated_networking(self, vm_size, location=None):
        '''
        Given a VM size, return whether it supports accelerated networking.
        Returns None/False/True. None is implicit; the sku descriptor does
        not say, or the vm_size is not known. False and True are explicit.
        '''
        if location:
            sku = self.vm_skus_dict_get_any_location(vm_size, location=location)
            if not sku:
                self.logger.warning("%r not present in location %r; assuming accelerated_networking is not supported", vm_size, location)
                return None
            return sku_has_capability(sku, 'AcceleratedNetworkingEnabled', sku.capabilities, self.logger)
        try:
            by_location = self.vm_skus_dict[vm_size]
        except KeyError:
            self.logger.warning("%r is not a known vm_size; cannot determine accelerated_networking", vm_size)
            return None
        if not by_location:
            self.logger.warning("%r not present in any location; cannot determine accelerated_networking", vm_size)
            return None
        ret = None
        for skus in by_location.values():
            for sku in skus:
                has_capability = sku_has_capability(sku, 'AcceleratedNetworkingEnabled', sku.capabilities, self.logger)
                if ret is None:
                    ret = has_capability
                elif ret != has_capability:
                    self.logger.warning("%r has inconsistent AcceleratedNetworkingEnabled across locations; cannot determine accelerated_networking", vm_size)
                    return None
        if ret is None:
            self.logger.warning("%r is present in at least one location but none specify whether AcceleratedNetworkingEnabled is supported; cannot determine accelerated_networking", vm_size)
        return ret

    @command.simple
    def vm_sizes_accelerated_networking_print(self):
        '''
        Show accelerated_networking support for all vm sizes.
        '''
        vm_size_iter = self.az_compute.virtual_machine_sizes.list(location=self.location)
        vm_sizes = sorted([x.name for x in vm_size_iter])
        vals = [[vm_size, self.vm_size_supports_accelerated_networking(vm_size)] for vm_size in vm_sizes]
        print(tabulate(vals, tablefmt='plain', numalign='left', stralign='left'))

    # shared across instances to avoid fetching it more than once
    _skus_dict_lock = threading.Lock()
    _skus_dict_contents = None

    def _do_fetch_skus_dicts_NL(self):
        '''
        Fetch and cache skus dicts.
        Caller holds self._skus_dict_lock.
        '''
        if self._skus_dict_contents is None:
            skus_dict = self.skus_dict_fetch()
            type(self)._skus_dict_contents = skus_dict

    def skus_dict_get(self):
        '''
        If we have not already done so, fetch and parse SKUs
        '''
        with self._skus_dict_lock:
            self._do_fetch_skus_dicts_NL()
            assert self._skus_dict_contents is not None
            return self._skus_dict_contents

    @property
    def skus_dict(self):
        '''
        Getter for self._skus_dict_contents.
        That object is shared across instances to avoid fetching
        it more than once.
        '''
        return self.skus_dict_get()

    @property
    def vm_skus_dict(self):
        '''
        Getter to return a dict of virtualMachine ResourceSku objects.
        Format of the dict is [sku_name][location] = ResourceSku.
        '''
        return self.skus_dict.get('virtualmachines', dict())

    @command.printable
    def skus_list(self):
        '''
        Return a list of known SKUs.
        '''
        return list(self.az_compute.resource_skus.list())

    def skudict_insert(self, skudict, sku):
        '''
        skudict is a dict that is or will become self._skus_dict_contents.
        sku is a ResourceSku. Insert sku in skudict.
        '''
        name = getattr(sku, 'name', '')
        if not name:
            self.logger.warning("%s.%s: ignoring anonymous sku:\n%s", type(self).__name__, getframename(0), expand_item_pformat(sku))
            return False
        resource_type = getattr(sku, 'resource_type', '')
        if not resource_type:
            self.logger.warning("%s.%s: ignoring sku %r with no resource_type:\n%s", type(self).__name__, getframename(0), name, expand_item_pformat(sku))
            return False
        rlt = resource_type.lower()
        locations = getattr(sku, 'locations', list())
        if not locations:
            self.logger.warning("%s.%s: ignoring sku %r with no locations\n%s", type(self).__name__, getframename(0), name, expand_item_pformat(sku))
            return False
        by_resource_type = skudict.setdefault(rlt, dict())
        by_location = by_resource_type.setdefault(name, dict())
        for location in set(locations):
            location = location.lower()
            if location in by_location:
                ee = expand_item(by_location[location])
                er = expand_item(sku)
                if ee == er:
                    continue
            by_location.setdefault(location, list()).append(sku)
        return True

    @command.printable
    def skus_dict_fetch(self):
        '''
        Return a dict of SKUs indexed by resource_type.lower(), SKU name and location.
        structure is [resource_type.lower()][name][location] -> [ResourceSku, ...].
        There is more than one ResourceSku in the by_location list when there
        are additional dimensions that uniquify the SKUs. Example: size for disks.
        '''
        skudict = dict()
        for sku in self.skus_list():
            self.skudict_insert(skudict, sku)
        return skudict

    @staticmethod
    def sku_get_any_of_resource_type(data, name, location=None):
        '''
        data is skus_dict[resource_type]. name is the name of a ResourceSku.
        Return any ResourceSku that matches the name, regardless of
        location or any other attribute. Returns None if no such ResourceSku.
        '''
        try:
            by_location = data[name]
        except KeyError:
            return None
        if location:
            sku_list = by_location.get(location.lower(), list())
            for sku in sku_list:
                return sku
        else:
            for skus in by_location.values():
                for sku in skus:
                    return sku
        return None

    def vm_skus_dict_get_any_location(self, vm_size, location=None):
        '''
        Return any VM SKU for the given vm_size.
        If location is specified, must be in that location.
        If not found, returns None.
        '''
        return self.sku_get_any_of_resource_type(self.vm_skus_dict, vm_size, location=location)

    # regexp used when we see a vm_size not in the list of available SKUs.
    # We use this to guess the number of vCPUs. Example: 'Standard_B8MS'
    VM_SKU_UNKNOWN_RE = re.compile(r'^[A-Za-z]+_[A-Za-z]+([0-9]+)')

    def vm_size_get_vcpus_effective(self, vm_size):
        '''
        Given a vm_size like 'Standard_D2s_v3', return the
        effective number of vcpus (cores).
        Assumes the value is the same for all locations.
        '''
        vm_sku = self.vm_skus_dict_get_any_location(vm_size)
        if not vm_sku:
            m = self.VM_SKU_UNKNOWN_RE.search(vm_size)
            if m and m.group(1):
                ret = int(m.group(1))
                self.logger.warning("unknown vm_size %r; inferring %d", vm_size, ret)
                return ret
            self.logger.warning("unknown vm_size %r and cannot extract vcpus from its name", vm_size)
            return None
        return self.vm_sku_get_vcpus_effective(vm_sku)

    def vm_size_get_memory_gb(self, vm_size):
        '''
        Given a vm_size like 'Standard_D2s_v3', return the
        amount of memory in GB that gets allocated to the VM.
        Assumes the value is the same for all locations.
        '''
        vm_sku = self.vm_skus_dict_get_any_location(vm_size)
        if not vm_sku:
            return None
        return self.sku_capability_get_int(vm_sku, 'MemoryGB')

    def disk_availability_zones(self, disk_type, location):
        '''
        Return the availability zones for the given disk_type (DataDiskType) in the given location.
        Returns None if not available in any zones.
        '''
        try:
            disk_desc = DATA_DISK_DESCS[disk_type.value]
        except KeyError as exc:
            # This implies that there's a disk_type in DataDiskType that either
            # we are missing handling for above here in this loop or for which
            # DATA_DISK_DESCS is missing handling.
            raise AssertionError("unexpected disk_type %r" % disk_type) from exc
        disk_dict = self.skus_dict.get('disks', dict())
        by_location = disk_dict.get(disk_desc['name'])
        skus = by_location.get(location.lower(), list())
        for sku in skus:
            if sku.tier.lower() != disk_desc['tier'].lower():
                continue
            li = sku_location_info_get(sku, location)
            if li:
                assert li.zones is not None
                return li.zones
        return None

    def vm_size_common_availability_zones(self, location, vm_sizes, warn_not_known=True):
        '''
        Return a list of availability zones common to the vm_sizes (str).
        Returns None if there are none in common or if a vm_size
        is not known.
        '''
        if isinstance(vm_sizes, str):
            vm_sizes = [vm_sizes]
        common_locations = set()
        # Some locations have only one availability zone. Rather than
        # representing that as a list with one entry, CRP represents
        # that as an empty list. We use any_zones to track whether
        # we have seen a non-empty list. If so, then there is more than
        # one availability zone, and an empty list means available
        # nowhere. If not, then there is only one availability zone,
        # and an empty list means everywhere.
        any_zones = False
        for vm_size in vm_sizes:
            try:
                by_location = self.vm_skus_dict[vm_size]
            except KeyError:
                if warn_not_known:
                    self.logger.warning("%s.%s: vm_size %r not known", type(self).__name__, getframe(0), vm_size)
                return None
            try:
                skus = by_location[location.lower()]
            except KeyError:
                if warn_not_known:
                    self.logger.warning("%s.%s: vm_size %r not known in location %r", type(self).__name__, getframe(0), vm_size, location)
                return None
            # As of now, there is no dimension that we expect to
            # cause us to have a list with more than one SKU.
            # Here, we handle that unanticipated case conservatively.
            # If some new dimension comes into play in the future,
            # we may want to add kwargs to this operation to
            # further filter.
            for sku in skus:
                li = sku_location_info_get(sku, location)
                if not li:
                    return None
                assert li.zones is not None
                any_zones = any_zones or bool(li.zones)
                if common_locations:
                    common_locations &= set(li.zones)
                else:
                    common_locations = set(li.zones)
                if any_zones and (not common_locations):
                    # No longer any zones in common - no point in continuing
                    return None
        if any_zones and (not common_locations):
            return None
        return availability_zones_normalize(common_locations)

    def vm_size_availability_zones(self, vm_size, location):
        '''
        Return a list of availability zones for the given vm_size in the given location.
        Returns None if vm_size is not known in location.
        '''
        try:
            sku = self.vm_skus_dict[vm_size][location][0]
        except (IndexError, KeyError):
            return None
        li = sku_location_info_get(sku, location)
        return li.zones if li else None

    def vm_size_supports_data_disk_type_anywhere(self, vm_size, data_disk_type):
        '''
        Return whether this vm_size supports the given data_disk_type in any location.
        '''
        for skus in self.vm_skus_dict.get(vm_size, dict()).values():
            for sku in skus:
                if sku_supports_data_disk_type(sku, data_disk_type, self.logger):
                    return True
        return False

    @command.simple
    def image_gallery_create(self, resource_group=None, gallery_name=None, tags=None):
        '''
        Create an image gallery
        '''
        resource_group = resource_group or self.resource_group or self.vm_image_resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        gallery_name = gallery_name or self.gallery_name
        if not gallery_name:
            raise ApplicationExit("'gallery_name' not specified")
        parameters = {'location' : self.location,
                      'tags' : self.tags_get(tags),
                     }
        self.logger.info("create image_gallery %s/%s with parameters:\n%s", resource_group, gallery_name, expand_item_pformat(parameters))
        op = self.az_compute.galleries.begin_create_or_update(resource_group, gallery_name, parameters)
        self.logger.info("create image_gallery %s/%s wait for completion", resource_group, gallery_name)
        op.wait()
        res = op.result()
        self.logger.info("create image_gallery %s/%s result:\n%s", resource_group, gallery_name, expand_item_pformat(res))
        return res

    @command.simple
    def image_gallery_delete(self, resource_group=None, gallery_name=None):
        '''
        Delete an image gallery
        '''
        resource_group = resource_group or self.resource_group or self.vm_image_resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        gallery_name = gallery_name or self.gallery_name
        if not gallery_name:
            raise ApplicationExit("'gallery_name' not specified")
        try:
            self.az_compute.galleries.begin_delete(resource_group, gallery_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return
            raise

    @command.printable
    def image_gallery_get(self, resource_group=None, gallery_name=None):
        '''
        Return info for the named image gallery
        '''
        resource_group = resource_group or self.resource_group or self.vm_image_resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        gallery_name = gallery_name or self.gallery_name
        if not gallery_name:
            raise ApplicationExit("'gallery_name' not specified")
        try:
            return self.az_compute.galleries.get(resource_group, gallery_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    @command.printable
    def image_gallery_definition_get(self, resource_group=None, gallery_name=None, definition_name=None):
        '''
        Return info for the named image definition
        '''
        resource_group = resource_group or self.resource_group or self.vm_image_resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        gallery_name = gallery_name or self.gallery_name
        if not gallery_name:
            raise ApplicationExit("'gallery_name' not specified")
        definition_name = definition_name or self.vm_image_name
        if not definition_name:
            raise ApplicationExit("'definition_name' not specified")
        try:
            return self.az_compute.gallery_images.get(resource_group, gallery_name, definition_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    @command.simple
    def image_gallery_definition_delete(self, resource_group=None, gallery_name=None, definition_name=None, wait=True):
        '''
        Delete the named image definition
        '''
        resource_group = resource_group or self.resource_group or self.vm_image_resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        gallery_name = gallery_name or self.gallery_name
        if not gallery_name:
            raise ApplicationExit("'gallery_name' not specified")
        definition_name = definition_name or self.vm_image_name
        if not definition_name:
            raise ApplicationExit("'definition_name' not specified")
        poller = self.arm_poller(self.az_compute.gallery_images)
        try:
            op = self.az_compute.gallery_images.begin_delete(resource_group, gallery_name, definition_name, polling=poller)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise
        if wait:
            op.wait()
        return op

    @command.printable
    def image_gallery_version_delete(self, resource_group=None, gallery_name=None, definition_name=None, version=None, wait=True):
        '''
        Delete the named image version (single image under a definition)
        '''
        resource_group = resource_group or self.resource_group or self.vm_image_resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        gallery_name = gallery_name or self.gallery_name
        if not gallery_name:
            raise ApplicationExit("'gallery_name' not specified")
        vm_image_name = definition_name or self.vm_image_name
        if not vm_image_name:
            raise ApplicationExit("'vm_image_name' not specified for %s" % getframename(0))
        vm_image_version = str(version) or self.vm_image_version
        if not vm_image_version:
            raise ApplicationExit("'vm_image_version' not specified")
        poller = self.arm_poller(self.az_compute.gallery_image_versions)
        try:
            op = self.az_compute.gallery_image_versions.begin_delete(resource_group, gallery_name, vm_image_name, vm_image_version, polling=poller)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise
        if wait:
            op.wait()
        return op

    @staticmethod
    def image_gallery_name_valid(name):
        '''
        Return whether name is valid for an image gallery
        '''
        if not isinstance(name, str):
            return False
        return bool(RE_GALLERY_NAME_ABS.search(name))

    @staticmethod
    def resource_group_name_valid(name):
        '''
        Return whether name is valid for a resource_group
        '''
        if not isinstance(name, str):
            return False
        return bool(RE_RESOURCE_GROUP_ABS.search(name))

    @staticmethod
    def subscription_id_valid(name):
        '''
        Return whether name is a valid subscription_id
        '''
        if not isinstance(name, str):
            return False
        return bool(RE_UUID_ABS.search(name))

    @command.printable
    def storage_account_resource_group_name_get(self, storage_account_name=None):
        '''
        Given a storage account name, get the name of its resource group.
        Storage account names are globally unique (DNS constraint), but
        in the REST API they are managed by subscription and resource group,
        just like other resources. Here we assume self.subscription_id,
        and we iterate resources in the subscription to find the resource
        group name. Return None if not found.
        '''
        storage_account_name = storage_account_name or self.storage_account_name
        if not storage_account_name:
            raise ApplicationExit("'storage_account_name' not specified")
        for resource in self.resource_list_storage_accounts():
            if resource.name == storage_account_name:
                toks = resource.id.split('/')
                if toks[1].lower() != 'subscriptions':
                    self.logger.warning("%s.%s: unexpected token 1 %r (ignoring resource)", type(self).__name__, getframe(0), toks[1])
                    continue
                if toks[3].lower() != 'resourcegroups':
                    self.logger.warning("%s.%s: unexpected token 3 %r (ignoring resource)", type(self).__name__, getframe(0), toks[3])
                    continue
                return toks[4]
        return None

    @command.printable
    def storage_account_keys_get(self, storage_account_name=None, storage_account_resource_group_name=None):
        '''
        Given a storage account name, return a list of keys for that storage
        account. Returns None if not found.
        If the resource group is not given, it is inferred. If it is given incorrectly,
        the operation returns None.
        '''
        storage_account_name = storage_account_name or self.storage_account_name
        if not storage_account_name:
            raise ApplicationExit("'storage_account_name' not specified")
        if not storage_account_resource_group_name:
            # Storage account names are globally unique (thanks to DNS constraints),
            # but the REST API requires the resource group name.
            # Figure it out.
            storage_account_resource_group_name = self.storage_account_resource_group_name_get(storage_account_name=storage_account_name)
        if not storage_account_resource_group_name:
            return None
        try:
            keys_obj = self.az_storage.storage_accounts.list_keys(storage_account_resource_group_name, storage_account_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise
        ret = [x.value for x in keys_obj.keys]
        for sk in ret:
            output_redact('SA-KEY:'+storage_account_name, sk)
        return ret

    @command.printable
    def storage_account_blob_url(self, storage_account_name=None):
        '''
        Given a storage account name, return the corresponding URL
        '''
        storage_account_name = storage_account_name or self.storage_account_name
        if not storage_account_name:
            raise ApplicationExit("'storage_account_name' not specified")
        return "https://%s.blob.%s/" % (storage_account_name, self.cloud.suffixes.storage_endpoint)

    def _blobserviceclient_get__url_is_valid(self, url):
        '''
        Return whether the given URL is valid for blobserviceclient_get
        '''
        try:
            msapicall(self.logger, requests.get, url=url)
            return True
        except requests.exceptions.ConnectionError:
            return False

    def blobserviceclient_get(self, storage_account_name=None, storage_account_resource_group_name=None, storage_account_key=None, sas_token=None, credential=None):
        '''
        Create and return a BlobServiceClient for the given storage account.
        If storage_account_key is not given, it is retrieved.
        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blobserviceclient?view=azure-python
        '''
        # See https://pypi.org/project/azure-storage-blob/
        storage_account_name = storage_account_name or self.storage_account_name
        if not storage_account_name:
            raise ApplicationExit("'storage_account_name' not specified")
        blob_url = self.storage_account_blob_url(storage_account_name=storage_account_name)
        # The SDK does not deal well with invalid storage account names.
        # See if we can reach blob_url (does not matter that we will most likely get a 400).
        if not self._blobserviceclient_get__url_is_valid(blob_url):
            self.logger.warning("%s: invalid blob_url %r", self.mth(), blob_url)
            return None
        bsc_kwargs = dict()
        if credential:
            bsc_kwargs['credential'] = credential
        elif sas_token:
            bsc_kwargs['credential'] = sas_token
        elif storage_account_key:
            bsc_kwargs['credential'] = storage_account_key
        else:
            # No auth provided. If we can retrieve SA keys, use one. If not, try using our own creds.
            # Most likely our own creds will fail in that case. Sorry.
            cred = self.azure_credential_generate()
            keys = self.storage_account_keys_get(storage_account_name=storage_account_name, storage_account_resource_group_name=storage_account_resource_group_name)
            if keys and keys[0]:
                bsc_kwargs['credential'] = keys[0]
            else:
                bsc_kwargs['credential'] = cred
        ret = msapicall(self.logger, BlobServiceClient, blob_url, **bsc_kwargs)
        if not ret:
            self.logger.warning("%s: returning BlobServiceClient %r", self.mth(), ret)
        return ret

    def blobop_bundle_get(self, name, *args, skc=None, storage_account_resource_group_name=None, storage_account_key=None, sas_token=None, credential=None, **kwargs):
        '''
        Return a BlobOpBundle. Hint this manager to the bundle if no
        manager is provided in kwargs.
        '''
        kwargs.setdefault('manager', self)
        if skc:
            if (not storage_account_key) and (not sas_token) and (not credential):
                storage_account_key = skc.retrieve_one(name, manager=self)
            if not storage_account_resource_group_name:
                storage_account_resource_group_name = skc.rg_for(name.subscription_id, name.storage_account_name, manager=self)
        ret = BlobOpBundle(name, *args, storage_account_resource_group_name=storage_account_resource_group_name, storage_account_key=storage_account_key, sas_token=sas_token, credential=credential, **kwargs)
        assert id(ret.logger) == id(self.logger)
        return ret

    @command.printable
    def vnet_gateway_get(self, vnet_gateway_name=None, resource_group=None):
        '''
        Return a VirtualNetworkGateway or None for not-found
        '''
        vnet_gateway_name = vnet_gateway_name or self.vnet_gateway_name
        if not vnet_gateway_name:
            raise ApplicationExit("'vnet_gateway_name' not specified")
        resource_group = resource_group or self.resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        try:
            return self.az_network.virtual_network_gateways.get(resource_group, vnet_gateway_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    ######################################################################
    # Subscription mgmt

    def subscription_list(self):
        '''
        List subscriptions available to this auth.
        Return a list of azure.mgmt.subscription.models.Subscription.
        '''
        return self._subscription_list()

    def _subscription_list(self):
        '''
        List subscriptions available to this auth.
        Return a list of azure.mgmt.subscription.models.Subscription.
        '''
        try:
            return list(self.az_subscription.subscriptions.list())
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def subscription_id_from_display_name(self, display_name):
        '''
        Return the subscription_id for the subscription with the
        given display name. If display_name is not found, return None.
        This means that if the caller does not have permission to
        access the subscription, this will return None.
        '''
        subs = self.subscription_list()
        for sub in subs:
            if sub.display_name == display_name:
                return sub.subscription_id
        return None

    ######################################################################
    # VM mgmt

    VM_AZRID_VALUES = {'provider_name' : 'Microsoft.Compute',
                       'resource_type' : 'virtualMachines',
                      }

    @classmethod
    def vm_azrid_build(cls, subscription_id, resource_group, resource_name):
        '''
        Build azrid
        '''
        return AzResourceId.build(subscription_id, resource_group, resource_name, cls.VM_AZRID_VALUES)

    @classmethod
    def vm_azrid(cls, resource_id):
        '''
        Return resource_id in AzResourceId form.
        '''
        return azrid_normalize(resource_id, AzResourceId, cls.VM_AZRID_VALUES)

    @classmethod
    def is_vm_resource_id(cls, resource_id):
        '''
        Return whether resource_id is a VM resource_id
        '''
        azrid = azrid_normalize_or_none(resource_id, AzResourceId, cls.VM_AZRID_VALUES)
        return azrid and azrid_is(azrid, AzResourceId, **cls.VM_AZRID_VALUES)

    @command.printable
    def vm_list(self, subscription_id=None, resource_group=None):
        '''
        List virtual machines in a subscription. If not specified explicitly, self.subscription_id is used.
        May optionally limit to a resource_group.
        Return a list of azure.mgmt.compute.models.VirtualMachine
        '''
        subscription_id = laaso.subscription_mapper.effective(subscription_id or self.subscription_id)
        resource_group = resource_group or None
        return self._vm_list(subscription_id, resource_group)

    def _vm_list(self, subscription_id, resource_group):
        '''
        List virtual machines in a subscription.
        If resource_group is truthy, restrict the list to the named RG.
        Return a list of azure.mgmt.compute.models.VirtualMachine
        '''
        az_compute = self.az_compute_get(subscription_id)
        try:
            if resource_group:
                return list(az_compute.virtual_machines.list(resource_group))
            return list(az_compute.virtual_machines.list_all())
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return list()
            raise

    ######################################################################
    # loganalytics_workspace

    LOGANALYTICS_WORKSPACE_AZRID_VALUES = {'provider_name' : 'Microsoft.OperationalInsights',
                                           'resource_type' : 'workspaces',
                                          }

    @classmethod
    def loganalytics_workspace_azrid(cls, resource_id):
        '''
        Return resource_id in AzResourceId form.
        '''
        return azrid_normalize(resource_id, AzResourceId, cls.LOGANALYTICS_WORKSPACE_AZRID_VALUES)

    @classmethod
    def loganalytics_workspace_resource_type(cls):
        '''
        Return the resource type string - eg x.type where x is the SDK resource obj.
        '''
        v = cls.LOGANALYTICS_WORKSPACE_AZRID_VALUES
        return f"{v['provider_name']}/{v['resource_type']}"

    @classmethod
    def loganalytics_workspace_obj_normalize(cls, obj):
        '''
        The OperationalInsights RP returns some strings with
        nonstandard and even inconsistent case. Normalize
        these strings to a consistent form.
        '''
        if obj:
            obj = copy.deepcopy(obj)
            obj = cls.sdk_resource_obj_normalize(obj, cls.LOGANALYTICS_WORKSPACE_AZRID_VALUES, cls.loganalytics_workspace_resource_type(), docopy=False)
            if obj.sku and obj.sku.name:
                obj.sku.name = laaso.util.enum_str_normalize_nocase(azure.mgmt.loganalytics.models.WorkspaceSkuNameEnum, obj.sku.name)
        return obj

    def _loganalytics_workspace_get(self, azrid):
        '''
        Return azure.mgmt.loganalytics.models.Workspace or None
        '''
        try:
            az_loganalytics = self.az_loganalytics_get(azrid.subscription_id)
            return az_loganalytics.workspaces.get(azrid.resource_group_name, azrid.resource_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def loganalytics_workspace_get_by_id(self, resource_id):
        '''
        Return azure.mgmt.loganalytics.models.Workspace or None
        '''
        resource_id = self.loganalytics_workspace_azrid(resource_id)
        ret = self._loganalytics_workspace_get(resource_id)
        ret = self.loganalytics_workspace_obj_normalize(ret)
        return ret

    def loganalytics_workspace_get_shared_keys(self, workspace_id):
        '''
        Return azure.mgmt.loganalytics.models.SharedKeys or None
        '''
        workspace_azrid = self.loganalytics_workspace_azrid(workspace_id)
        workspace_name = workspace_azrid.resource_name
        ret = self._loganalytics_workspace_get_shared_keys(workspace_azrid)
        if ret:
            for attr in ('primary_shared_key', 'secondary_shared_key'):
                sk = getattr(ret, attr, '')
                if sk:
                    output_redact(workspace_name+'.'+attr, sk)
        return ret

    def _loganalytics_workspace_get_shared_keys(self, azrid):
        '''
        Return azure.mgmt.loganalytics.models.SharedKeys or None
        '''
        try:
            az_loganalytics = self.az_loganalytics_get(azrid.subscription_id)
            return az_loganalytics.shared_keys.get_shared_keys(azrid.resource_group_name, azrid.resource_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def loganalytics_workspace_create_or_update(self, azrid, params):
        '''
        Create or update for loganalytics workspace
        Returns azure.mgmt.loganalytics.models.Workspace
        '''
        azrid.values_sanity(self.LOGANALYTICS_WORKSPACE_AZRID_VALUES)
        ret = self._loganalytics_workspace_create_or_update(azrid, params)
        ret = self.loganalytics_workspace_obj_normalize(ret)
        return ret

    def _loganalytics_workspace_create_or_update(self, azrid, params):
        '''
        Create or update for loganalytics workspace
        Returns azure.mgmt.loganalytics.models.Workspace
        '''
        az_loganalytics = self.az_loganalytics_get(azrid.subscription_id)
        poller = self.arm_poller(az_loganalytics.workspaces)
        op = az_loganalytics.workspaces.begin_create_or_update(azrid.resource_group_name, azrid.resource_name, params, polling=poller)
        op.wait()
        return op.result()

    ######################################################################
    # Peering (virtual network)

    VIRTUAL_NETWORK_PEERING_AZRID_VALUES = {'provider_name' : 'Microsoft.Network',
                                            'resource_type' : 'virtualNetworks',
                                            'subresource_type' : 'virtualNetworkPeerings',
                                           }

    @classmethod
    def virtual_network_peering_azrid(cls, resource_id):
        '''
        Given a virtual network peering (peering_id), return it in AzSubResourceId form.
        '''
        return azrid_normalize(resource_id, AzSubResourceId, cls.VIRTUAL_NETWORK_PEERING_AZRID_VALUES)

    def virtual_network_peering_get_by_id(self, peering_id):
        '''
        Given a peering id ('/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/infra-rg/providers/Microsoft.Network/virtualNetworks/laaso-vnet/virtualNetworkPeerings/general-2-eastus2-vnet-peering'),
        do a get and return the result obj (azure.mgmt.network.models.VirtualNetworkPeering) or None for not-found.
        '''
        azrid = self.virtual_network_peering_azrid(peering_id)
        return self._virtual_network_peering_get(azrid)

    def _virtual_network_peering_get(self, peering_azrid):
        '''
        Return azure.mgmt.network.models.VirtualNetworkPeering or None
        '''
        az_network = self.az_network_get(peering_azrid.subscription_id)
        try:
            return az_network.virtual_network_peerings.get(peering_azrid.resource_group_name, peering_azrid.resource_name, peering_azrid.subresource_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def virtual_network_peering_create(self, resource_group, vnet_name, peering_name, params):
        '''
        Create a single vnet peering.
        Return azure.mgmt.network.models.VirtualNetworkPeering.
        Remember, two of these are needed to pass traffic; on each vnet.
        '''
        return self._virtual_network_peering_create(resource_group, vnet_name, peering_name, params)

    def _virtual_network_peering_create(self, resource_group, vnet_name, peering_name, params):
        '''
        Create a single vnet peering. Returns azure.mgmt.network.models.VirtualNetworkPeering.
        '''
        poller = self.arm_poller(self.az_network.virtual_network_peerings)
        op = self.az_network.virtual_network_peerings.begin_create_or_update(resource_group, vnet_name, peering_name, params, polling=poller)
        op.wait()
        return op.result()

    ######################################################################
    # Subnet

    VIRTUAL_NETWORK_SUBNET_AZRID_VALUES = {'provider_name' : 'Microsoft.Network',
                                           'resource_type' : 'virtualNetworks',
                                           'subresource_type' : 'subnets',
                                          }

    @classmethod
    def subnet_azrid(cls, resource_id):
        '''
        Return resource_id in AzSubResourceId form.
        '''
        return azrid_normalize(resource_id, AzSubResourceId, cls.VIRTUAL_NETWORK_SUBNET_AZRID_VALUES)

    def subnet_name_get(self, vnet_name=None, subnet_name=None, vnet_resource_group_name=None):
        '''
        Return effective tuple (vnet_name, subnet_name, vnet_resource_group_name),
        raising as necessary.
        '''
        vnet_name, vnet_resource_group_name = self._vnet_name_get(vnet_resource_group_name, vnet_name)
        subnet_name = subnet_name or self.subnet_name
        if not subnet_name:
            raise ApplicationExit("'subnet_name' not specified")
        return (vnet_name, subnet_name, vnet_resource_group_name)

    def subnet_get_by_id(self, subnet_id):
        '''
        Given a subnet id ('/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/infra-rg/providers/Microsoft.Network/virtualNetworks/laaso-vnet/subnets/default'),
        do a get and return the result obj or None for not-found.
        '''
        azrid = azrid_normalize(subnet_id, AzSubResourceId, self.VIRTUAL_NETWORK_SUBNET_AZRID_VALUES)
        return self._subnet_get(azrid.subscription_id, azrid.resource_group_name, azrid.resource_name, azrid.subresource_name)

    @command.printable
    def subnet_get(self, subscription_id=None, vnet_resource_group_name=None, vnet_name=None, subnet_name=None):
        '''
        Return azure.mgmt.network.models.Subnet or None
        '''
        subscription_id = subscription_id or self.subscription_id
        vnet_name, subnet_name, vnet_resource_group_name = self.subnet_name_get(vnet_name=vnet_name, subnet_name=subnet_name, vnet_resource_group_name=vnet_resource_group_name)
        return self._subnet_get(subscription_id, vnet_resource_group_name, vnet_name, subnet_name)

    def _subnet_get(self, subscription_id, resource_group, vnet_name, subnet_name):
        '''
        Return azure.mgmt.network.models.Subnet or None
        '''
        az_network = self.az_network_get(subscription_id)
        try:
            return az_network.subnets.get(resource_group, vnet_name, subnet_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def subnet_create_or_update(self, azrid, params):
        '''
        Return azure.mgmt.network.models.Subnet
        '''
        azrid.values_sanity(self.VIRTUAL_NETWORK_SUBNET_AZRID_VALUES)
        return self._subnet_create_or_update(azrid, params)

    def _subnet_create_or_update(self, azrid, params):
        '''
        Return azure.mgmt.network.models.Subnet
        '''
        az_network = self.az_network_get(azrid.subscription_id)
        poller = self.arm_poller(az_network.subnets)
        op = az_network.subnets.begin_create_or_update(azrid.resource_group_name, azrid.resource_name, azrid.subresource_name, params, polling=poller)
        op.wait()
        return op.result()

    ######################################################################
    # SKU

    @command.simple
    def skus_print_json(self):
        '''
        Print skus in JSON format
        '''
        sku_list = [x.serialize(keep_readonly=True) for x in self.skus_list()]
        print(json.dumps(sku_list, indent=len(PF)))

    ######################################################################
    # resource_group

    def _resource_group_create_or_update(self, resource_group, parameters):
        '''
        Perform the resource_group create_or_update.
        Return azure.mgmt.resource.resources.models.ResourceGroup.
        '''
        return self.az_resource.resource_groups.create_or_update(resource_group, parameters)

    ######################################################################
    # NSG (Network Security Group)

    NSG_AZRID_VALUES = {'provider_name' : 'Microsoft.Network',
                        'resource_type' : 'networkSecurityGroups',
                       }

    @classmethod
    def nsg_azrid_build(cls, subscription_id, resource_group, resource_name):
        '''
        Build azrid
        '''
        return AzResourceId.build(subscription_id, resource_group, resource_name, cls.NSG_AZRID_VALUES)

    @command.printable
    def nsg_get(self, nsg_name=None, resource_group=None):
        '''
        Return azure.mgmt.network.models.NetworkSecurityGroup or None
        '''
        nsg_name = nsg_name or self.nsg_name
        if not nsg_name:
            raise ApplicationExit("'nsg_name' not specified")
        resource_group = resource_group or self.resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        return self._nsg_get(nsg_name, resource_group)

    def _nsg_get(self, nsg_name, resource_group):
        '''
        Return azure.mgmt.network.models.NetworkSecurityGroup or None
        '''
        try:
            return self.az_network.network_security_groups.get(resource_group, nsg_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def nsg_get_by_id(self, nsg_id):
        '''
        Given a network security group id such as:
          /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/infra-rg/providers/Microsoft.Network/networkSecurityGroups/some-nsg
        return azure.mgmt.network.models.NetworkSecurityGroup or None
        '''
        azrid = AzResourceId.from_text(nsg_id, subscription_id=self.subscription_id, provider_name='Microsoft.Network', resource_type='networkSecurityGroups')
        return self.nsg_get(resource_group=azrid.resource_group_name, nsg_name=azrid.resource_name)

    def nsg_create_or_update(self, azrid, params):
        '''
        Issue a create_or_update for the given network security group.
        Return azure.mgmt.network.models.NetworkSecurityGroup.
        '''
        assert azrid.values_match(provider_name='Microsoft.Network', resource_type='networkSecurityGroups')
        return self._nsg_create_or_update(azrid, params)

    def _nsg_create_or_update(self, azrid, params):
        '''
        Issue a create_or_update for the given network security group.
        Return azure.mgmt.network.models.NetworkSecurityGroup.
        '''
        az_network = self.az_network_get(azrid.subscription_id)
        poller = self.arm_poller(az_network.network_security_groups)
        op = az_network.network_security_groups.begin_create_or_update(azrid.resource_group_name, azrid.resource_name, params, polling=poller)
        op.wait()
        return op.result()

    ######################################################################
    # vnet

    VIRTUAL_NETWORK_AZRID_VALUES = {'provider_name' : 'Microsoft.Network',
                                    'resource_type' : 'virtualNetworks',
                                   }

    @classmethod
    def virtual_network_azrid(cls, resource_id):
        '''
        Return resource_id in AzResourceId form.
        '''
        return azrid_normalize(resource_id, AzResourceId, cls.VIRTUAL_NETWORK_AZRID_VALUES)

    def _vnet_name_get(self, vnet_resource_group_name, vnet_name):
        '''
        Return effective tuple (vnet_name, vnet_resource_group_name),
        raising as necessary.
        '''
        vnet_name = vnet_name or self.vnet_name
        if not vnet_name:
            self.logger.error("'vnet_name' not specified")
            raise ApplicationExit(1)
        vnet_resource_group_name = vnet_resource_group_name or self.vnet_resource_group_name
        if not vnet_resource_group_name:
            self.logger.error("'vnet_resource_group_name' not specified")
            raise ApplicationExit(1)
        return (vnet_name, vnet_resource_group_name)

    def vnet_get_by_id(self, vnet_id):
        '''
        Return vnet object (azure.mgmt.network.models.VirtualNetwork) or None
        '''
        azrid = azrid_normalize(vnet_id, AzResourceId, self.VIRTUAL_NETWORK_AZRID_VALUES)
        return self._vnet_get(azrid.subscription_id, azrid.resource_group_name, azrid.resource_name)

    @command.printable
    def vnet_get(self, vnet_resource_group_name=None, vnet_name=None):
        '''
        Return vnet object (azure.mgmt.network.models.VirtualNetwork) or None
        '''
        vnet_name, vnet_resource_group_name = self._vnet_name_get(vnet_resource_group_name, vnet_name)
        return self._vnet_get(self.subscription_id, vnet_resource_group_name, vnet_name)

    def _vnet_get(self, subscription_id, resource_group, vnet_name):
        '''
        Return vnet object (azure.mgmt.network.models.VirtualNetwork) or None
        '''
        az_network = self.az_network_get(subscription_id)
        try:
            return az_network.virtual_networks.get(resource_group, vnet_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def vnet_create_or_update(self, azrid, params):
        '''
        azure.mgmt.network.models.VirtualNetwork
        '''
        assert azrid.values_match(provider_name='Microsoft.Network', resource_type='virtualNetworks')
        return self._vnet_create_or_update(azrid, params)

    def _vnet_create_or_update(self, azrid, params):
        '''
        azure.mgmt.network.models.VirtualNetwork
        '''
        az_network = self.az_network_get(azrid.subscription_id)
        poller = self.arm_poller(az_network.subnets)
        op = az_network.virtual_networks.begin_create_or_update(azrid.resource_group_name, azrid.resource_name, params, polling=poller)
        op.wait()
        return op.result()

    ######################################################################
    # Resource IDs

    def resource_id_expand(self, resource_ids, exc_value=None, namestack=''):
        '''
        Given resource_ids as a str or list of str, return a list of
        resource IDs resulting from expanding wildcards.
        At this time, the only wildcard supported is '*' for subscription_id.
        This substitutes each managed subscription_id.
        Unrecognized formats, wildcards, etc are left alone in the result.
        '''
        exc_value = exc_value or self.exc_value
        prefix = f"{namestack}: " if namestack else ''
        if isinstance(resource_ids, str):
            resource_ids = [resource_ids]
        if not all(isinstance(x, str) for x in resource_ids):
            raise exc_value(f"{prefix}resource_ids must be a list of str")
        ret = list()
        for rid in resource_ids:
            toks = rid.split('/')
            if (len(toks) >= 2) and (not toks[0]) and (toks[1].lower() == 'subscriptions') and (toks[2] == '*'):
                ret.extend(['/'.join([toks[0], toks[1], subscription_id, *toks[3:]]) for subscription_id in laaso.paths.managed_subscription_ids])
                continue
            ret.append(rid)
        return ret

    ######################################################################
    # Resources

    def resource_list(self, resource_type_match=None):
        '''
        Return a list of azure.mgmt.resource.resources.models.GenericResourceExpanded objects.
        '''
        return self._resource_list(resource_type_match)

    def _resource_list(self, resource_type_match):
        '''
        List all resources in this subscription, returning a list of type azure.mgmt.resource.resources.models.GenericResourceExpanded
        '''
        lfilter = "resourceType eq %r" % resource_type_match if resource_type_match else None
        try:
            return list(self.az_resource.resources.list(filter=lfilter))
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return list()
            raise

    def resource_list_storage_accounts(self):
        '''
        Return a list of all storage accounts in the default subscription.
        Returns an empty list (not None) if the subscription does not exist.
        This trivial wrappper provides a useful hook for testing (mocking).
        '''
        return self.resource_list('Microsoft.Storage/storageAccounts')

    ######################################################################
    # RBAC role assignments

    @staticmethod
    def rbac_role_assignment_normalize(obj):
        '''
        Handle converting preview API results.
        Returns azure.mgmt.authorization.v2018_01_01_preview.models.RoleAssignment.
        The preview version has a "nicer" object layout, and one might
        reasonably presume that "someday" it will become azure.mgmt.authorization.models.RoleAssignment.
        '''
        if isinstance(obj, azure.mgmt.authorization.v2018_01_01_preview.models.RoleAssignment):
            return obj
        ret = azure.mgmt.authorization.v2018_01_01_preview.models.RoleAssignment()
        if isinstance(obj, azure.mgmt.authorization.models.RoleAssignment):
            ret.additional_properties = obj.additional_properties
            ret.id = obj.id
            ret.name = obj.name
            ret.principal_id = obj.properties.principal_id
            ret.role_definition_id = obj.properties.role_definition_id
            ret.scope = obj.properties.scope
            ret.type = obj.type
        else:
            raise ValueError(f"{getframe(0)}: unknown obj type {type(obj)}")
        return ret

    def rbac_role_assignments_list_for_scope(self, azrid, lfilter=None):
        '''
        Return a list of role assignments (azure.mgmt.authorization.v2018_01_01_preview.models.RoleAssignment) for the scope defined by azrid.
        Accepts azresourceid form because many callers have that in hand.
        '''
        if isinstance(azrid, str):
            azrid = azresourceid_from_text(azrid)
        ret = self._rbac_role_assignments_list_for_scope(azrid, lfilter=lfilter)
        return [self.rbac_role_assignment_normalize(x) for x in ret]

    def _rbac_role_assignments_list_for_scope(self, azrid, lfilter=None):
        '''
        Return a list of role assignments (azure.mgmt.authorization.v2018_01_01_preview.models.RoleAssignment) for the scope (azrid).
        Restrict to at or above the scope: lfilter='atScope()'
        Restrict to a specific principal_id: lfilter='principalId eq {id}'
        '''
        az_authorization = self.az_authorization_get(azrid.subscription_id)
        return list(az_authorization.role_assignments.list_for_scope(str(azrid), filter=lfilter))

    def rbac_role_assignment_create(self, principal_id, principal_type, scope, role_definition_id):
        '''
        Create a new role assignment. Auto-generates the name.
        '''
        name = str(uuid.uuid4())
        self._rbac_role_assignment_create(name, principal_id, principal_type, scope, role_definition_id)

    def _rbac_role_assignment_create(self, name, principal_id, principal_type, scope, role_definition_id): # pylint: disable=unused-argument
        '''
        Create a new role assignment.
        see:
          https://docs.microsoft.com/en-us/rest/api/authorization/roleassignments/create
          https://docs.microsoft.com/en-us/python/api/azure-mgmt-authorization/azure.mgmt.authorization.v2015_07_01.models.roleassignmentcreateparameters?view=azure-python
        '''
        # It looks like things are different in the v2020_04_01_preview. When
        # that goes live, this may need to start considering API versions. Yowza.
        # principal_type is passed through to here anticipating that change.
        parameters = azure.mgmt.authorization.v2018_01_01_preview.models.RoleAssignmentCreateParameters(principal_id=principal_id,
                                                                                                        role_definition_id=role_definition_id,
                                                                                                       )
        try:
            self.az_authorization.role_assignments.create(scope, name, parameters)
        except azure.core.exceptions.ResourceExistsError as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.any_code_matches('RoleAssignmentExists'):
                return
            raise

    ######################################################################
    # RBAC role definitions

    def rbac_role_definitions_list_for_scope(self, azrid, lfilter=None):
        '''
        Return a list of role definitions (azure.mgmt.authorization.models.RoleDefinition) for the scope defined by azrid
        '''
        if isinstance(azrid, str):
            azrid = azresourceid_from_text(azrid)
        return self._rbac_role_definitions_list_for_scope(azrid, lfilter=lfilter)

    def _rbac_role_definitions_list_for_scope(self, azrid, lfilter=None):
        '''
        Return a list of role assignments (azure.mgmt.authorization.models.RoleDefinition) for the scope identified by azrid.
        Example lfilters:
          roleName eq '{value}'
          type eq 'BuiltInRole|CustomRole'
        '''
        subscription_id = azrid.subscription_id or self.subscription_id
        az_authorization = self.az_authorization_get(subscription_id)
        return list(az_authorization.role_definitions.list(str(azrid), filter=lfilter))

    def rbac_role_definition_get_by_id(self, definition_id):
        '''
        Given a definition_id, return azure.mgmt.authorization.models.RoleDefinition or None
        Example definition IDs:
            /providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111
            /subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111
        '''
        # Normalize through role_definition_azrid_from_text to get subscription aliasing
        definition_azrid = self.role_definition_azrid_from_text(definition_id, exc_value=self.exc_value)
        return self._rbac_role_definition_get_by_id(definition_azrid)

    def _rbac_role_definition_get_by_id(self, definition_azrid):
        '''
        Return azure.mgmt.authorization.models.RoleDefinition
        subscription_id is the subscription_id of the definition_id.
        Takes definition_azrid rather than definition_id to make mocking simpler and more efficient.
        '''
        try:
            return self.az_authorization.role_definitions.get_by_id(str(definition_azrid))
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    @staticmethod
    def role_definition_azrid_from_text(role_definition_id, exc_value=EXC_VALUE_DEFAULT):
        '''
        Convert str (role_definition_id) to a subclass of AzAnyResourceId
        '''
        role_definition_azrid = azresourceid_from_text(role_definition_id,
                                                       provider_name='Microsoft.Authorization',
                                                       resource_type='roleDefinitions',
                                                       exc_desc='role_definition_id',
                                                       exc_value=exc_value)
        assert isinstance(role_definition_azrid, (AzProviderResourceId, AzSubscriptionProviderResourceId))
        return role_definition_azrid

    def rbac_role_definition_logical_name(self, role_definition_id):
        '''
        Given role_definition_id as a resource_id, return a human-facing logical string.
        '''
        rd = self.rbac_role_definition_get_by_id(role_definition_id)
        return rd.role_name if rd else role_definition_id

    @command.simple
    def rbac_role_definitions_print_json(self):
        '''
        print JSON-serialized rbac_role_definitions_list_for_scope
        laaso/azure_tool.py rbac_role_definitions_print_json > tests/data/rbac_role_definitions_print.json
        '''
        rds = self.rbac_role_definitions_list_for_scope('/')
        rds_serialized = [rd.serialize(keep_readonly=True) for rd in rds]
        txt = json.dumps(rds_serialized, indent=len(PF))
        assert self.subscription_id not in txt
        print(txt)

    # key = scope_azrid
    # value = dict [role_name] -> azure.mgmt.authorization.models.RoleDefinition
    _cache_rbac_role_definition_bynamedict = laaso.cacher.Cache()
    laaso.reset_hooks.append(_cache_rbac_role_definition_bynamedict.reset)

    def _rbac_role_definition_bynamedict__cachemiss(self, scope_azrid):
        '''
        Helper for rbac_role_definition_get_by_name.
        Returns one azure.mgmt.authorization.models.RoleDefinition for role_name in subscription_id.
        subscription_id may be None or '' (they are treated identically as scope /).
        '''
        rds = self._rbac_role_definitions_list_for_scope(scope_azrid)
        ret = {rd.role_name : rd for rd in rds}
        return ret

    def rbac_role_definition_get_by_name(self, role_name, scope):
        '''
        Return the matching azure.mgmt.authorization.models.RoleDefinition or None
        '''
        if (not scope) or (scope == '/'):
            scope = AzAnyResourceId()
        elif not isinstance(scope, AzAnyResourceId):
            tmp = laaso.util.uuid_normalize(scope, key='scope', exc_value=None)
            if tmp:
                scope = AzSubscriptionResourceId(tmp)
            else:
                scope = azresourceid_from_text(scope, exc_desc='scope')
        assert isinstance(scope, AzAnyResourceId)
        # role definitions are all subscription scoped within a subscription.
        # flatten it out to share caching.
        if isinstance(scope, AzSubscriptionResourceId):
            subscription_id = scope.subscription_id
        else:
            subscription_id = ''
        rd_by_name = self._cache_rbac_role_definition_bynamedict.get(subscription_id,
                                                                     self._rbac_role_definition_bynamedict__cachemiss, scope)
        return rd_by_name.get(role_name, None)

    ######################################################################
    # keyvault utility ops

    @staticmethod
    def keyvault_vaultname_from_url(url):
        '''
        Given a keyvault URL, extract the vault name
        '''
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.split('.')
        return host[0]

    def keyvault_urlbase_from_vaultname(self, vault_name):
        '''
        Given a keyvault name, return the base of a URL (including trailing /)
        '''
        return f'https://{vault_name}{self.cloud.suffixes.keyvault_dns}/'

    ######################################################################
    # keyvault mgmt

    KEYVAULT_AZRID_VALUES = {'provider_name' : 'Microsoft.KeyVault',
                             'resource_type' : 'vaults',
                            }

    @classmethod
    def keyvault_azrid(cls, resource_id):
        '''
        Return resource_id in AzResourceId form.
        '''
        return azrid_normalize(resource_id, AzResourceId, cls.KEYVAULT_AZRID_VALUES)

    @command.printable
    def keyvault_get(self, subscription_id=None, resource_group=None, vault_name=None):
        '''
        Fetch and return Vault or None
        '''
        subscription_id = subscription_id or self.subscription_id
        if not subscription_id:
            raise self.exc_value("'subscription_id' not specified")
        resource_group = resource_group or self.keyvault_resource_group or self.resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        vault_name = vault_name or self.keyvault_name
        if not vault_name:
            raise ApplicationExit("'vault_name' not specified")
        azrid = AzResourceId.build(subscription_id, resource_group, vault_name, self.KEYVAULT_AZRID_VALUES)
        return self._keyvault_get(azrid)

    def _keyvault_get(self, azrid):
        '''
        Fetch and return Vault or None
        '''
        az_keyvault_mgmt = self.az_keyvault_mgmt_get(azrid.subscription_id)
        try:
            return az_keyvault_mgmt.vaults.get(azrid.resource_group_name, azrid.resource_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def keyvault_get_by_id(self, vault_id):
        '''
        Given a keyvault id ('/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/infra-rg/providers/Microsoft.KeyVault/vaults/keyvault-name'),
        do a get and return the Vault or None for not-found
        '''
        azrid = azrid_normalize(vault_id, AzResourceId, self.KEYVAULT_AZRID_VALUES)
        return self._keyvault_get(azrid)

    def keyvault_create(self, resource_group, resource_name, params):
        '''
        Create a keyvault
        Return azure.mgmt.keyvault.models.Vault
        '''
        return self._keyvault_create(resource_group, resource_name, params)

    def _keyvault_create(self, resource_group, resource_name, params):
        '''
        Create a keyvault
        Return azure.mgmt.keyvault.models.Vault
        '''
        poller = self.arm_poller(self.az_keyvault_mgmt.vaults)
        op = self.az_keyvault_mgmt.vaults.begin_create_or_update(resource_group, resource_name, params, polling=poller)
        op.wait()
        return op.result()

    ######################################################################
    # keyvault certificate issuers

    def keyvault_certificate_issuer_list(self, keyvault_name):
        '''
        Return a list of azure.keyvault.certificates.IssuerProperties
        '''
        return self._keyvault_certificate_issuer_list(keyvault_name)

    def _keyvault_certificate_issuer_list(self, keyvault_name):
        '''
        Return a list of azure.keyvault.certificates.IssuerProperties
        '''
        try:
            certificate_client = self.az_certificate_client(keyvault_name)
            return list(certificate_client.list_properties_of_issuers())
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return list()
            raise

    def keyvault_certificate_issuer_get(self, keyvault_name, issuer_name):
        '''
        Return azure.keyvault.certificates.CertificateIssuer or None
        https://docs.microsoft.com/en-us/python/api/azure-keyvault-certificates/azure.keyvault.certificates.certificateclient?view=azure-python#get-issuer-issuer-name----kwargs-
        Mocking is done in CertificateClientMock.
        '''
        try:
            certificate_client = self.az_certificate_client(keyvault_name)
            return certificate_client.get_issuer(issuer_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    ######################################################################
    # keyvault certificates
    # We do not rely on msapicall.msapiwrap

    def az_certificate_client(self, keyvault_name, client_id=None, allow_login_cred=True):
        '''
        Return azure.keyvault.certificates.CertificateClient for the named vault.
        '''
        return self._keyvault_content_client_generate(keyvault_name,
                                                      azure.keyvault.certificates.CertificateClient,
                                                      azure.keyvault.certificates._shared.client_base.KeyVaultClientBase, # pylint: disable=protected-access
                                                      client_id=client_id,
                                                      allow_login_cred=allow_login_cred)

    @command.printable_raw
    def keyvault_certificate_versions_get(self, cert_name=None, keyvault_name=None, client_id=None):
        '''
        Fetch certificate versions. Return them sorted by create time.
        '''
        keyvault_name = keyvault_name or self.keyvault_name
        if not keyvault_name:
            raise ApplicationExit("'keyvault_name' not specified")
        cert_name = cert_name or self.cert_name
        if not cert_name:
            raise ApplicationExit("'cert_name' not specified")
        lres = self._keyvault_certificate_versions_get(cert_name, keyvault_name, client_id)
        # sort the list by create time
        lres.sort(key=lambda x: x.created_on)
        return lres

    def _keyvault_certificate_versions_get(self, cert_name, keyvault_name, client_id=None):
        '''
        Internals of keyvault_certificate_versions_get
        '''
        cid_list = self.client_ids_get(client_id=client_id)
        for cid in cid_list:
            try:
                client = self.az_certificate_client(keyvault_name, client_id=cid)
                # force to list here inside the try/except block because
                # not-found happens during paging
                return list(client.list_properties_of_certificate_versions(cert_name))
            except Exception as exc:
                caught = laaso.msapicall.Caught(exc)
                self.logger.warning("%s failed with client_id=%r is_missing=%s: %r", self.mth(), cid, caught.is_missing(), exc)
                raise
        return list()

    @command.printable_raw
    def keyvault_certificate_get(self, cert_name=None, keyvault_name=None, client_id=None):
        '''
        Get the newest certificate.
        Return azure.keyvault.certificates.KeyVaultCertificate or None.
        '''
        keyvault_name = keyvault_name or self.keyvault_name
        if not keyvault_name:
            raise ApplicationExit("'keyvault_name' not specified")
        cert_name = cert_name or self.cert_name
        if not cert_name:
            raise ApplicationExit("'cert_name' not specified")
        cert = self._keyvault_certificate_get(cert_name, keyvault_name, client_id)
        if cert and cert.cer:
            kn = keyvault_name + '/' + cert_name
            output_redact(kn, repr(bytes(cert.cer))[2:-1])
            output_redact(kn, str(base64.b64encode(cert.cer), encoding='utf-8'))
        return cert

    def _keyvault_certificate_get(self, cert_name, keyvault_name, client_id):
        '''
        Get the newest certificate.
        Return azure.keyvault.certificates.KeyVaultCertificate or None.
        '''
        cid_list = self.client_ids_get(client_id=client_id)
        res = None
        for cid in cid_list:
            try:
                client = self.az_certificate_client(keyvault_name, client_id=cid)
                res = client.get_certificate(cert_name)
                break
            except Exception as exc:
                caught = laaso.msapicall.Caught(exc)
                if caught.is_missing():
                    return None
                self.logger.warning("%s failed with clientid=%r: %r", self.mth(), cid, exc)
                continue
        return res

    def keyvault_certificate_import_from_objs(self, keyvault_name, cert_name, cert_obj, secret_obj, log_level=logging.INFO):
        '''
        Import a certificate to a keyvault.
        cert_obj is azure.keyvault.certificates.KeyVaultCertificate.
        '''
        client = self.az_certificate_client(keyvault_name)
        params = {'enabled' : cert_obj.policy.enabled,
                  'policy' : cert_obj.policy,
                 }
        # Generate cert in PFX format.
        pfx = OpenSSL.crypto.PKCS12()
        cert_data = b'-----BEGIN CERTIFICATE-----\n'
        cert_data += base64.encodebytes(cert_obj.cer)
        cert_data += b'-----END CERTIFICATE-----\n'
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
        pfx.set_certificate(x509)
        secret_data = base64.decodebytes(bytes(secret_obj.value, encoding='ascii'))
        # https://docs.microsoft.com/en-us/azure/key-vault/certificates/how-to-export-certificate?tabs=azure-cli
        # "When you export the certificate, the password is blank."
        secret_passwd = b''
        if secret_obj.properties.content_type.lower() == 'application/x-pkcs12':
            tup = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(secret_data, secret_passwd)
            pkey = OpenSSL.crypto.PKey.from_cryptography_key(tup[0])
        else:
            raise ApplicationExit("%s vault=%r cert=%r secret has unsupported type %r" % (self.mth(), keyvault_name, cert_name, secret_obj.properties.content_type))
        pfx.set_privatekey(pkey)
        cert = pfx.export()
        self.logger.log(log_level, "import keyvault_name=%r cert_name=%r params:\n%s", keyvault_name, cert_name, expand_item_pformat(params))
        try:
            newcert = client.import_certificate(cert_name, cert, **params)
        except Exception as exc:
            self.logger.error("%s import keyvault_name=%r cert_name=%r error (params follow): %r\n%s",
                              self.mth(), keyvault_name, cert_name, exc, expand_item_pformat(params))
            raise
        self.logger.log(log_level, "import keyvault_name=%r cert_name=%r result:\n%s", keyvault_name, cert_name, expand_item_pformat(newcert))

    ######################################################################
    # keyvault secrets

    def az_secrets_client(self, keyvault_name, client_id=None, allow_login_cred=True):
        '''
        Return azure.keyvault.secrets.SecretClient for the named vault.
        https://docs.microsoft.com/en-us/python/api/azure-keyvault-secrets/azure.keyvault.secrets.secretclient?view=azure-python
        '''
        return self._keyvault_content_client_generate(keyvault_name,
                                                      azure.keyvault.secrets.SecretClient,
                                                      azure.keyvault.secrets._shared.client_base.KeyVaultClientBase, # pylint: disable=protected-access
                                                      client_id=client_id,
                                                      allow_login_cred=allow_login_cred)

    @command.printable_raw
    def keyvault_secret_get(self, secret_name=None, keyvault_name=None, client_id=None):
        '''
        Get a secret from the keyvault
        Return azure.keyvault.secrets.KeyVaultSecret or None.
        '''
        keyvault_name = keyvault_name or self.keyvault_name
        if not keyvault_name:
            raise self.exc_value("'keyvault_name' not specified")
        secret_name = secret_name or self.secret_name
        if not secret_name:
            raise self.exc_value("'secret_name' not specified")
        secret = self._keyvault_secret_get(secret_name, keyvault_name, client_id)
        if secret and secret.value:
            kn = keyvault_name + '/' + secret_name
            output_redact(kn, secret.value)
        return secret

    def _keyvault_secret_get(self, secret_name, keyvault_name, client_id):
        '''
        Get a secret from the keyvault
        Return azure.keyvault.secrets.KeyVaultSecret or None.
        '''
        ret = None
        cid_list = self.client_ids_get(client_id=client_id)
        for cid in cid_list:
            try:
                client = self.az_secrets_client(keyvault_name, client_id=cid)
                ret = client.get_secret(secret_name)
                break
            except Exception as exc:
                caught = laaso.msapicall.Caught(exc)
                if caught.is_missing():
                    continue
                self.logger.warning("%s failed with secret_name=%r client_id=%r: %r", self.mth(), secret_name, cid, exc)
                continue
        return ret

    @command.printable_raw
    def keyvault_secret_value_get(self, keyvault_name=None, secret_name=None, client_id=None):
        '''
        Get a secret from the keyvault and return its value.
        '''
        secret = self.keyvault_secret_get(keyvault_name=keyvault_name, secret_name=secret_name, client_id=client_id)
        if secret:
            return secret.value
        return None

    def keyvault_secret_set(self, keyvault_name, secret_name, secret_value, client_id=None, **kwargs):
        '''
        Set the named secret in the named keyvault.
        '''
        client = self.az_secrets_client(keyvault_name, client_id=client_id)
        client.set_secret(secret_name, secret_value, enabled=True, **kwargs)

    @command.printable
    def keyvault_secret_list_names(self, keyvault_name=None, client_id=None, enabled_only=True):
        '''
        Return a list of secret names in the given vault
        '''
        keyvault_name = keyvault_name or self.keyvault_name
        if not keyvault_name:
            raise self.exc_value("'keyvault_name' not specified")
        return self._keyvault_secret_list(keyvault_name, client_id, enabled_only=enabled_only)

    def _keyvault_secret_list(self, keyvault_name, client_id, enabled_only=True):
        '''
        Return a list of secret names in the given vault.
        Returns None or raises if the vault cannot be listed.
        '''
        cid_list = self.client_ids_get(client_id=client_id)
        for cid in cid_list:
            client = self.az_secrets_client(keyvault_name, client_id=cid)
            try:
                res = list(client.list_properties_of_secrets())
            except Exception as exc:
                if 'ManagedIdentityCredential authentication unavailable' in str(exc):
                    continue
                raise
            return [x.name for x in res if (not enabled_only) or x.enabled]
        return None

    ######################################################################
    # keyvault contents (type-independent)

    def _keyvault_content_client_generate(self, keyvault_name, client_class, client_parent_class, client_id=None, allow_login_cred=True):
        '''
        Create an return an object of type client_class for the named vault.
        client_class is something like azure.keyvault.secrets.SecretClient.
        '''
        credential = self.azure_credential_generate(client_id=client_id, allow_login_cred=allow_login_cred)
        keyvault_url = "https://%s%s/" % (keyvault_name, self.cloud.suffixes.keyvault_dns)
        cli = client_class(vault_url=keyvault_url, credential=credential)
        laaso.msapicall.wrap_child_only_methods(cli, client_parent_class, self.logger)
        return cli

    ######################################################################
    # pubkey

    @command.printable_raw
    def user_pubkey_get(self, keyvault_name=None, keyvault_client_id=None, username=None):
        '''
        Return the public key for the given user. This is retrieved
        from the keyvault.
        '''
        keyvault_name = keyvault_name or self.pubkey_keyvault_name or laaso.scfg.get('pubkey_keyvault_name', '')
        if not keyvault_name:
            raise self.exc_value("'pubkey_keyvault_name' not specified")
        keyvault_client_id = keyvault_client_id or self.pubkey_keyvault_client_id or laaso.scfg.get('pubkey_keyvault_client_id', '')
        if keyvault_client_id:
            # Attempt both the provided client_id and default credentials
            client_id = [keyvault_client_id, None]
        else:
            # No client_id provided and no default available; just use default credentials
            client_id = [None]
        username = username or self.username
        if not username:
            raise self.exc_value("'username' not specified")
        secret_name = 'pubkey-' + username
        self.logger.debug("%s attempt to retrieve keyvault_name=%r secret_name=%r client_id=%r", self.mth(), keyvault_name, secret_name, client_id)
        ret = self.keyvault_secret_get(keyvault_name=keyvault_name, secret_name=secret_name, client_id=client_id)
        if ret:
            ret = ret.value.rstrip()
        return ret

    @command.simple
    def user_pubkey_download(self, keyvault_name=None, keyvault_client_id=None, username=None):
        '''
        Retrieve the public key for the given user from the keyvault.
        Store it in the home directory for that user.
        '''
        username = username or self.username
        if not username:
            raise ApplicationExit("'username' not specified")
        pubkey_username = None

        pw = self.pw_get(username)
        if not pw:
            raise ApplicationExit(f"cannot get user {username!r}")

        fallback = 'laaso'

        ssh = os.path.abspath(os.path.join('/home', username, '.ssh'))
        if not os.path.isdir(ssh):
            raise ApplicationExit(f"ssh directory {ssh!r} does not exist")
        self.logger.debug("ssh directory is %s", ssh)

        pubkey = self.user_pubkey_get(keyvault_name=keyvault_name, keyvault_client_id=keyvault_client_id, username=username)
        if pubkey:
            self.logger.debug("retrieved public key for %s", username)
            pubkey_username = username
        if (not pubkey) and (username != fallback):
            pubkey = self.user_pubkey_get(username=fallback)
            if pubkey:
                self.logger.debug("could not retrieve public key for %s; falling back to default", username)
                pubkey_username = fallback
        if not pubkey:
            raise ApplicationExit("could not retrieve a suitable public key")

        authorized_keys = ''
        filename = os.path.join(ssh, 'authorized_keys')
        try:
            with open(filename, 'r') as f:
                authorized_keys = f.read()
        except FileNotFoundError:
            # Create as an empty file. We do this now so we can chmod it before writing.
            with open(filename, 'w+') as f:
                pass
        os.chown(filename, pw.pw_uid, pw.pw_gid)
        os.chmod(filename, 0o600)
        # Make it end with exactly one newline
        authorized_keys = authorized_keys.rstrip()
        if authorized_keys.find(pubkey) < 0:
            authorized_keys += '\n'
            authorized_keys += pubkey
            with open(filename, 'w') as f:
                f.write(authorized_keys.strip())
                f.write('\n')
                f.flush()
                os.fsync(f.fileno())
            self.logger.info("public key for %s added to %s", pubkey_username, filename)
        else:
            self.logger.info("public key for %s already present in %s", pubkey_username, filename)

        pk = None
        filename = os.path.join(ssh, 'id_rsa.pub')
        try:
            with open(filename, 'r') as f:
                pk = f.read()
        except FileNotFoundError:
            # Create as an empty file. We do this now so we can chmod it before writing.
            with open(filename, 'w+') as f:
                pass
        os.chown(filename, pw.pw_uid, pw.pw_gid)
        os.chmod(filename, 0o644)
        if pk and (pk.find(pubkey) > 0):
            self.logger.info("public key for %s already present in %s", pubkey_username, filename)
        else:
            if pk and (pk.find(pubkey) < 0):
                self.logger.warning("will update public key file %s with key for %s", filename, pubkey_username)
            with open(filename, 'w') as f:
                f.write(pubkey.strip())
                f.write('\n')
                f.flush()
                os.fsync(f.fileno())
            self.logger.info("public key for %s added to %s", pubkey_username, filename)

    ######################################################################
    # requests wrappers

    def _requests_get_fail(self, resp, fail_exit=True, msg=''):
        '''
        Handle a failed requests.get(), where failed means the status is not OK.
        resp is the return from requests.get()
        '''
        if not fail_exit:
            return None
        self.logger.error("Failed request\n%s\n%s", expand_item_pformat(resp), expand_item_pformat(traceback.format_stack()))
        if msg:
            self.logger.error(msg)
            raise ApplicationExit("failed request from %s (%s)" % (getframename(1), msg))
        raise ApplicationExit("failed request from %s" % getframename(1))

    ######################################################################
    # metadata service

    def _metadata_request_at_version(self, target, api_version, headers=None, parameters=None, rformat=None):
        '''
        target is a string like 'instance' or 'instance/compute/resourceGroupName'
        headers and parameters are optional dicts.
        '''
        url = 'http://169.254.169.254/metadata/' + target.strip('/')

        p = dict()
        if api_version:
            p.setdefault('api-version', api_version)
        if rformat:
            p.setdefault('format', rformat)
        if parameters:
            p.update(parameters)

        req_headers = {'Metadata' : 'true'}
        if headers:
            req_headers.update(headers)

        resp = msapicall(self.logger, requests.get, url, headers=req_headers, params=p)
        return resp

    @command.printable
    def metadata_api_version_determine(self, ignore=None, fail_exit=False):
        '''
        Determine a working API version for the metadata service.
        Do not select any version in ignore. This does not cache
        any state or used any cached state other than the starting
        point hard-coded in REST_API_VERSIONS. That way, if the
        host changes what versions it accepts (a case we have seen),
        this operation can adapt to the new reality. This operation
        is sensitive to such changes that happen while it is executing.
        There is only so much we can do if the host changes the set
        of versions that it accepts so frequently and radically
        while this operation is running that it cannot find a single
        working version.
        If ignore is provided, it is a set of known-not-good versions.
        If a version is tested here and found not-working, it is added
        to ignore.
        '''
        ignore = ignore or set()
        api_versions_tried = set()
        # Start with our believed-good version
        api_version = REST_API_VERSIONS['metadata_service']
        while True:
            resp = self._metadata_request_at_version('instance', api_version, rformat='json')
            if api_version:
                if resp.status_code == http.client.OK:
                    return api_version
                api_versions_tried.add(api_version)
                ignore.add(api_version)
            if resp.status_code == http.client.BAD_REQUEST:
                # If we tried with an API version, try again without one. That will
                # give us a response containing a list of API versions to try.
                if api_version:
                    api_version = None
                    continue
                api_version = self._metadata_extract_good_api_version(resp, ignore)
                if not api_version:
                    if ignore != api_versions_tried:
                        self.logger.error("%s cannot find a usable metadata service API version; ignore %s", self.mth(), ignore)
                    self.logger.error("%s cannot find a usable metadata service API version; tried %s", self.mth(), api_versions_tried)
                    if fail_exit:
                        raise ApplicationExit("cannot find a usable metadata service API version")
                    return None
                continue
            self.logger.error("%s got unexpected response status %r from metadata service", self.mth(), resp.status_code)
            if fail_exit:
                raise ApplicationExit("unexpected response status %r from metadata service" % resp.status_code)
            return None

    def _metadata_extract_good_api_version(self, resp, ignore):
        '''
        resp is a BAD_REQUEST response from a metadata service operation
        ignore is a set of API versions to reject (ignore)
        Pick the newest API version suggested in resp that is not ignored.
        Return None if no match is found or the response cannot be parsed.
        '''
        try:
            content = json.loads(resp.content)
        except Exception as exc:
            self.logger.warning("%s cannot parse resp.content %r: %r", self.mth(), resp.content, exc)
            self.logger.warning("resp:\n%s", expand_item_pformat(resp))
            return None
        vk = 'newest-versions'
        try:
            versions = content[vk]
        except KeyError:
            self.logger.warning("%s %r not found in resp.content %r", self.mth(), vk, resp.content)
            return None
        if not all(isinstance(x, str) for x in versions):
            self.logger.warning("%s versions is not all strings, it is %r", self.mth(), versions)
            return None
        versions.sort()
        versions_orig = copy.copy(versions)
        while versions:
            version = versions.pop()
            if not version:
                self.logger.warning("%s versions contains empty string %r", self.mth(), version)
                continue
            if version in ignore:
                continue
            return version
        self.logger.warning("%s no acceptable version found in %r", self.mth(), versions_orig)
        return None

    @property
    def metadata_api_version(self):
        '''
        Getter
        '''
        with self._metadata_service_lock:
            if not self._metadata_api_version:
                self._metadata_api_version = self.metadata_api_version_determine(fail_exit=False)
            return self._metadata_api_version

    def _metadata_request_any_version(self, target, headers=None, parameters=None, fail_exit=False, rformat=None):
        '''
        target is a string like 'instance' or 'instance/compute/resourceGroupName'
        headers is an optional dict.
        If the request fails and the endpoint suggests alternate API versions,
        retry with an alternate version. Keep that up until we run out of
        versions or see a different-looking failure.
        '''
        api_versions = set()
        api_version = self.metadata_api_version
        if not api_version:
            raise ApplicationExit("%s from %s cannot find an initial api_version" % (self.mth(), getframe(1)))
        while True:
            api_versions.add(api_version)
            with self._metadata_service_lock:
                resp = self._metadata_request_at_version(target, api_version, headers=headers, parameters=parameters, rformat=rformat)
                if resp.status_code == http.client.OK:
                    self._metadata_api_version = api_version
                    if rformat == 'json':
                        return json.loads(resp.content)
                    return resp.content
                if resp.status_code == http.client.BAD_REQUEST:
                    api_version = self._metadata_extract_good_api_version(resp, api_versions)
                    if api_version:
                        continue
                    if fail_exit:
                        self.logger.warning("%s %s cannot find suitable API version; tried %r", self.mth(), getframe(1), api_versions)
                        raise ApplicationExit("%s cannot find suitable API version" % (getframe(1)))
                    return None
                break
        return self._requests_get_fail(resp, fail_exit=fail_exit)

    @command.printable
    def metadata_instance_get(self):
        '''
        Fetch and return instance info from the metadata service.
        '''
        return self._metadata_request_any_version('instance', fail_exit=True, rformat='json')

    @command.printable
    def metadata_instance_compute_get(self):
        '''
        Fetch and return instance info from the metadata service.
        '''
        return self._metadata_request_any_version('instance/compute', fail_exit=True, rformat='json')

    @command.printable
    def metadata_subscription_id_get(self):
        '''
        Fetch and return the subscription_id for the local VM
        '''
        ret = self.metadata_instance_compute_get()['subscriptionId']
        return laaso.util.uuid_normalize(ret)

    @command.printable
    def metadata_resource_group_get(self):
        '''
        Fetch and return the resource_group name for the local VM
        '''
        return self.metadata_instance_compute_get()['resourceGroupName']

    @command.printable
    def metadata_location_get(self):
        '''
        Fetch and return the location for the local VM
        '''
        return self.metadata_instance_compute_get()['location']

    @command.printable
    def metadata_tags_get(self):
        '''
        Fetch and return the resource_group name for the local VM
        '''
        tags_list = self.metadata_instance_compute_get()['tagsList']
        # tagsList is a list of dicts, where each dict looks like {'name': 'purpose', 'value': 'devel'}
        tags = {x['name'] : x['value'] for x in tags_list}
        return tags

    @command.printable
    def metadata_name_get(self):
        '''
        Return the name of the local VM
        '''
        return self.metadata_instance_compute_get()['name']

    @command.printable
    def metadata_vm_azrid_get(self):
        '''
        Return AzResourceId for this VM
        '''
        instance_data = self.metadata_instance_compute_get()
        return AzResourceId(instance_data['subscriptionId'],
                            instance_data['resourceGroupName'],
                            'Microsoft.Compute',
                            'virtualMachines',
                            instance_data['name'])

    # https://www.dmtf.org/sites/default/files/standards/documents/DSP0243_1.0.0.pdf
    METADATA_OVF_ENV = '/var/lib/waagent/ovf-env.xml'

    @classmethod
    def metadata_custom_data_get(cls):
        '''
        Return the custom data for this VM in bytes form.
        '''
        # At this time, the ability of the metadata service to return
        # custom data is disabled; it always claims there is no data.
        # The custom data is available in a file in an iso9660
        # filesystem accessible via /dev/dvd. Getting it that way
        # is slow and painful, because it involves mounting the device.
        # To keep this code out of dealing with these device mounts
        # (which requires running as superuser), we instead rely
        # on the waagent writing the custom data to a well-known
        # file on the local disk. Unfortunately, we get VMs with
        # older waagent versions that do not write /var/lib/waagent/CustomData,
        # so we must read and parse /var/lib/waagent/ovf-env.xml.
        with open(cls.METADATA_OVF_ENV, 'r') as f:
            xmltxt = f.read()
        et_root = ElementTree.fromstring(xmltxt)
        nsdict = {x[1][0] : x[1][1] for x in ElementTree.iterparse(io.StringIO(xmltxt), events=['start-ns'])}
        elem = et_root.find('.//ns1:CustomData', nsdict)
        elem_text = getattr(elem, 'text', b'') # bool(elem) is False. No kidding.
        if not elem_text:
            return b''
        ret = base64.decodebytes(bytes(elem_text, encoding='utf-8'))
        return ret

    ######################################################################
    # Managed identities (MSI) (UAMI)

    UAMI_AZRID_VALUES = {'provider_name' : 'Microsoft.ManagedIdentity',
                         'resource_type' : 'userAssignedIdentities',
                        }

    @classmethod
    def user_assigned_identity_azrid(cls, resource_id):
        '''
        Return resource_id in AzResourceId form.
        '''
        return azrid_normalize(resource_id, AzResourceId, cls.UAMI_AZRID_VALUES)

    @classmethod
    def is_uami_resource_id(cls, resource_id):
        '''
        Return whether resource_id is a user assigned managed identity
        '''
        azrid = azrid_normalize_or_none(resource_id, AzResourceId, cls.UAMI_AZRID_VALUES)
        return azrid and azrid_is(azrid, AzResourceId, **cls.UAMI_AZRID_VALUES)

    @classmethod
    def user_assigned_identity_resource_type(cls):
        '''
        Return the resource type string - eg x.type where x is the SDK resource obj.
        '''
        v = cls.UAMI_AZRID_VALUES
        return f"{v['provider_name']}/{v['resource_type']}"

    @classmethod
    def user_assigned_identity_obj_normalize(cls, obj):
        '''
        The ManagedIdentity RP returns strings with
        nonstandard case. Normalize these strings to
        a consistent form.
        '''
        return cls.sdk_resource_obj_normalize(obj, cls.UAMI_AZRID_VALUES, cls.user_assigned_identity_resource_type())

    @command.printable
    def user_assigned_identity_get(self, subscription_id=None, resource_group=None, name=None):
        '''
        Return azure.mgmt.msi.models.Identity or None
        '''
        subscription_id = subscription_id or self.subscription_id
        name = name or self.managed_identity_name
        if not name:
            raise ApplicationExit("'managed_identity' not specified")
        if name.startswith('/'):
            return self.user_assigned_identity_get_by_id(name)
        resource_group = resource_group or self.resource_group or self.keyvault_resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        ret = self._user_assigned_identity_get(subscription_id, resource_group, name)
        ret = self.user_assigned_identity_obj_normalize(ret)
        return ret

    def _user_assigned_identity_get(self, subscription_id, resource_group, name):
        '''
        Return azure.mgmt.msi.models.Identity or None
        '''
        az_msi = self.az_msi_get(subscription_id)
        try:
            return az_msi.user_assigned_identities.get(resource_group, name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def user_assigned_identity_get_by_id(self, msi_id):
        '''
        Return azure.mgmt.msi.models.Identity or None
        The full resource id will embed the subscription id -- use that instead of self.subscription_id
        '''
        azrid = self.user_assigned_identity_azrid(msi_id)
        ret = self._user_assigned_identity_get(azrid.subscription_id, azrid.resource_group_name, azrid.resource_name)
        ret = self.user_assigned_identity_obj_normalize(ret)
        return ret

    def user_assigned_identity_create_or_update(self, resource_group, resource_name, location, tags):
        '''
        Create or update UAMI. Return azure.mgmt.msi.models.Identity.
        '''
        return self._user_assigned_identity_create_or_update(resource_group, resource_name, location, tags)

    def _user_assigned_identity_create_or_update(self, resource_group, resource_name, location, tags):
        '''
        Create or update UAMI. Return azure.mgmt.msi.models.Identity.
        '''
        poller = self.arm_poller(self.az_msi.user_assigned_identities)
        ret = self.az_msi.user_assigned_identities.create_or_update(resource_group, resource_name,
                                                                    location=location,
                                                                    tags=tags,
                                                                    polling=poller)
        ret = self.user_assigned_identity_obj_normalize(ret)
        return ret

    ######################################################################
    # Active directory (AAD) user, service_principal

    _cache_ad_service_principal_by_object_id = CacheIndexer()
    laaso.reset_hooks.append(_cache_ad_service_principal_by_object_id.reset)

    def ad_service_principal_wait(self, object_id, max_wait_secs=300, sleep_secs=0.5):
        '''
        Wait for object_id to show up as an AAD service principal.
        This is useful because after creating a UAMI, it is registered
        with AAD, but that registration can take some time.
        Bypass the cache to avoid caching does-not-exist.
        Return azure.graphrbac.models.ServicePrincipal or None.
        '''
        t = time.monotonic()
        deadline = t + max_wait_secs
        while t <= deadline:
            sp = self._ad_service_principal_get_by_object_id(object_id)
            if sp:
                return sp
            if t < deadline:
                time.sleep(sleep_secs)
            t = time.monotonic()
        return None

    def ad_service_principal_get_by_object_id(self, object_id):
        '''
        Return azure.graphrbac.models.ServicePrincipal or None
        '''
        return self._cache_ad_service_principal_by_object_id.get(self.tenant_id, object_id,
                                                                 self._ad_service_principal_get_by_object_id, object_id)

    def _ad_service_principal_get_by_object_id(self, object_id):
        '''
        Return azure.graphrbac.models.ServicePrincipal or None
        '''
        try:
            return self.az_graphrbac_mgmt.service_principals.get(object_id)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            if caught.any_code_matches('PrincipalNotFound'):
                return None
            raise

    _cache_ad_user_by_upn_or_object_id = CacheIndexer()
    laaso.reset_hooks.append(_cache_ad_user_by_upn_or_object_id.reset)

    def ad_user_get(self, upn_or_object_id):
        '''
        Return azure.graphrbac.models.User or None
        Reminder: when doing a username, include @microsoft.com (or whatever)
        '''
        return self._cache_ad_user_by_upn_or_object_id.get(self.tenant_id, upn_or_object_id,
                                                           self._ad_user_get, upn_or_object_id)

    def _ad_user_get(self, upn_or_object_id):
        '''
        Return azure.graphrbac.models.User or None
        '''
        try:
            return self.az_graphrbac_mgmt.users.get(upn_or_object_id)
        except azure.graphrbac.models.GraphErrorException as exc:
            if exc.error.code == 'Request_ResourceNotFound':
                return None
            raise
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def ad_get_objects_by_object_ids(self, object_ids, types=None, subscription_id=None):
        '''
        object_ids is a list of UUID-as-str.
        Returns a list of the appropriate SDK objects (eg User, ServicePrincipal).
        Unrecognized IDs are omitted from the returned list.
        The ordering in the return list does not correspond to the ordering of object_ids.
        If types is specified, it is a list of strings such as 'Application'.
        These semantics correspond to the underlying REST operation.
        See https://docs.microsoft.com/en-us/python/api/azure-graphrbac/azure.graphrbac.operations.objectsoperations?view=azure-python
        '''
        subscription_id = subscription_id or self.subscription_id
        return self._ad_get_objects_by_object_ids(subscription_id, object_ids, types)

    def _ad_get_objects_by_object_ids(self, subscription_id, object_ids, types):
        '''
        object_ids is a list of UUID-as-str.
        Returns a list of the appropriate SDK objects (eg User, ServicePrincipal).
        Unrecognized IDs are omitted from the returned list.
        The ordering in the return list does not correspond to the ordering of object_ids.
        types is a list of strings such as 'Application'. If not specified, looks at all types.
        These semantics correspond to the underlying REST operation.
        See https://docs.microsoft.com/en-us/python/api/azure-graphrbac/azure.graphrbac.operations.objectsoperations?view=azure-python
        '''
        az_graphrbac_mgmt = self.az_graphrbac_mgmt_get(subscription_id)
        param = {'object_ids' : object_ids}
        if types:
            param['types'] = types
        return list(az_graphrbac_mgmt.objects.get_objects_by_object_ids(param))

    def ad_get_object_by_object_id(self, object_id, types=None, subscription_id=None):
        '''
        Wrapper for ad_get_objects_by_object_ids that handles a single object_id.
        Returns the object or None for not-found.
        '''
        res = self.ad_get_objects_by_object_ids([object_id], types=types, subscription_id=subscription_id)
        if res:
            return res[0]
        return None

    ######################################################################
    # Kusto support

    def az_kusto_client(self, kusto_uri):
        '''
        Return self._az_kusto[kusto_uri], creating iff necessary
        '''
        with self._az_client_gen_lock:
            try:
                return self._az_kusto[kusto_uri]
            except KeyError:
                pass
            sb = azure.kusto.data.KustoConnectionStringBuilder.with_az_cli_authentication(kusto_uri)
            kc = azure.kusto.data.KustoClient(sb)
            self._az_kusto[kusto_uri] = kc
            return kc

    ######################################################################
    # resource_group operations

    @command.printable
    def resource_group_get(self, resource_group=None):
        '''
        Return azure.mgmt.resource.resources.models.ResourceGroup or None
        '''
        resource_group = resource_group or self.resource_group
        if not resource_group:
            self.logger.error("'resource_group' not specified")
            raise ApplicationExit(1)
        try:
            return self.az_resource.resource_groups.get(resource_group)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    @command.printable
    def resource_groups_list(self, subscription_id=None):
        '''
        Return a list of azure.mgmt.resource.resources.models.ResourceGroup
        '''
        return list(self.resource_groups_list_iter_get(subscription_id=subscription_id))

    @command.printable
    def resource_groups_list_names(self, subscription_id=None):
        '''
        List resource groups in the subscription
        '''
        return [x.name for x in self.resource_groups_list_iter_get(subscription_id=subscription_id)]

    def resource_groups_list_iter_get(self, subscription_id=None):
        '''
        Return an iterator for resource group objects (azure.mgmt.resource.resources.models.ResourceGroup)
        '''
        return self._resource_groups_list_iter_get(subscription_id=subscription_id)

    def _resource_groups_list_iter_get(self, subscription_id=None):
        '''
        Return an iterator for resource group objects (azure.mgmt.resource.resources.models.ResourceGroup)
        '''
        subscription_id = subscription_id or self.subscription_id
        az_resource = self.az_resource_get(subscription_id)
        ret = az_resource.resource_groups.list()
        return ret

    ######################################################################
    # SDK client properties

    @property
    def az_authorization(self):
        '''
        Getter: self.az_authorization, generated on the first call and then cached
        '''
        return self._az_client_gen_property('_az_authorization', AuthorizationManagementClient)

    @property
    def az_compute(self):
        '''
        Getter: self.az_compute, generated on the first call and then cached
        '''
        return self._az_client_gen_property('_az_compute', ComputeManagementClient)

    @property
    def az_graphrbac_mgmt(self):
        '''
        Getter: self.az_graphrbac_mgmt, generated on the first call and then cached
        '''
        # TODO (9042401) Figure out a strategy for handling AAD access
        client_id = [None] # Force login creds only because chained creds do not seem to work with GraphRbacManagementClient
        return self._az_client_gen_property('_az_graphrbac_mgmt', GraphRbacManagementClient, client_id=client_id)

    @property
    def az_keyvault_mgmt(self):
        '''
        Getter: self.az_keyvault_mgmt, generated on the first call and then cached
        '''
        return self._az_client_gen_property('_az_keyvault_mgmt', KeyVaultManagementClient)

    @property
    def az_loganalytics(self):
        '''
        Getter: self.az_loganalytics, generated on the first call and then cached
        '''
        return self._az_client_gen_property('_az_loganalytics', LogAnalyticsManagementClient)

    @property
    def az_msi(self):
        '''
        Getter: self.az_msi, generated on the first call and then cached
        '''
        return self._az_client_gen_property('_az_msi', ManagedServiceIdentityClient)

    @property
    def az_network(self):
        '''
        Getter: self.az_network, generated on the first call and then cached
        '''
        return self._az_client_gen_property('_az_network', NetworkManagementClient)

    @property
    def az_resource(self):
        '''
        Getter: self.az_resource, generated on the first call and then cached
        ResourceManagementClient is for resource groups
        '''
        return self._az_client_gen_property('_az_resource', ResourceManagementClient)

    @property
    def az_resource_graph(self):
        '''
        Getter: self.az_resource_graph, generated on the first call and then cached
        '''
        return self._az_client_gen_property('_az_resource_graph', ResourceGraphClient)

    @property
    def az_storage(self):
        '''
        Getter: self.az_storage, generated on the first call and then cached
        '''
        return self._az_client_gen_property('_az_storage', StorageManagementClient)

    @property
    def az_subscription(self):
        '''
        Getter: self.az_subscription, generated on the first call and then cached
        '''
        return self._az_client_gen_property('_az_subscription', SubscriptionClient)

    ######################################################################
    # SDK client get operations

    def az_authorization_get(self, subscription_id):
        '''
        Get a AuthorizationManagementClient for the given subscription.
        '''
        subscription_id = laaso.subscription_mapper.effective(subscription_id)
        if subscription_id == self.subscription_id:
            return self.az_authorization
        return self._az_client_gen_do('authorization', AuthorizationManagementClient, subscription_id=subscription_id)

    def az_compute_get(self, subscription_id):
        '''
        Get a ComputeManagementClient for the given subscription.
        '''
        subscription_id = laaso.subscription_mapper.effective(subscription_id)
        if subscription_id == self.subscription_id:
            return self.az_compute
        return self._az_client_gen_do('compute', ComputeManagementClient, subscription_id=subscription_id)

    def az_graphrbac_mgmt_get(self, subscription_id, client_id=None):
        '''
        Get a GraphRbacManagementClient for the given subscription.
        '''
        subscription_id = laaso.subscription_mapper.effective(subscription_id)
        if subscription_id == self.subscription_id:
            return self.az_graphrbac_mgmt
        # TODO (9042401) Figure out a strategy for handling AAD access
        if not client_id:
            client_id = [None] # Force login creds only because chained creds do not seem to work with GraphRbacManagementClient
        return self._az_client_gen_do('graphrbac_mgmt', GraphRbacManagementClient, subscription_id=subscription_id, client_id=client_id)

    def az_keyvault_mgmt_get(self, subscription_id):
        '''
        Get a KeyVaultManagementClient for the given subscription.
        '''
        subscription_id = laaso.subscription_mapper.effective(subscription_id)
        if subscription_id == self.subscription_id:
            return self.az_keyvault_mgmt
        return self._az_client_gen_do('keyvault_mgmt', KeyVaultManagementClient, subscription_id=subscription_id)

    def az_loganalytics_get(self, subscription_id):
        '''
        Getter: self.az_loganalytics, generated on the first call and then cached
        '''
        subscription_id = laaso.subscription_mapper.effective(subscription_id)
        if subscription_id == self.subscription_id:
            return self.az_loganalytics
        return self._az_client_gen_do('loganalytics', LogAnalyticsManagementClient, subscription_id=subscription_id)

    def az_msi_get(self, subscription_id):
        '''
        Get a ManagedServiceIdentityClient given a subscription_id and client id
        if client_id is not specified, try using default azure creds (client_id: default)
        '''
        subscription_id = laaso.subscription_mapper.effective(subscription_id)
        if subscription_id == self.subscription_id:
            return self.az_msi
        return self._az_client_gen_do('msi', ManagedServiceIdentityClient, subscription_id=subscription_id)

    def az_network_get(self, subscription_id):
        '''
        Get a NetworkManagementClient given a subscription_id and client id
        if client_id is not specified, try using default azure creds (client_id: default)
        '''
        subscription_id = laaso.subscription_mapper.effective(subscription_id)
        if subscription_id == self.subscription_id:
            return self.az_network
        return self._az_client_gen_do('network', NetworkManagementClient, subscription_id=subscription_id)

    def az_resource_generate(self, subscription_id, client_id=None):
        '''
        Get a ResourceManagementClient for the given subscription.
        Always generates a new client, bypassing any caching.
        '''
        subscription_id = laaso.subscription_mapper.effective(subscription_id)
        return self._az_client_gen_do('resource', ResourceManagementClient, subscription_id=subscription_id, client_id=client_id)

    def az_resource_get(self, subscription_id):
        '''
        Get a ResourceManagementClient for the given subscription.
        '''
        return self.az_resource_generate(subscription_id)

    ######################################################################
    # SDK client object generation

    def _az_client_gen_do(self, name, client_class, subscription_id=None, client_id=None):
        '''
        Factory for Azure SDK client of type client_class.
        '''
        ret = self._az_client_gen_do_cli(name, client_class, subscription_id=subscription_id, client_id=client_id)
        # Generate the wrappers here directly rather than wrapping _az_client_gen_do_cli()
        # or get_client_from_cli_profile() with msapicall() to avoid
        # retrying construction errors and to specialize
        # auth error handling in _az_client_gen_do_cli().
        return msapiwrap(self.logger, ret)

    def _az_client_gen_do_cli(self, name, client_class, subscription_id=None, client_id=None, max_tries=5):
        '''
        Factory for Azure SDK client of type client_class using CLI creds.
        Do not call this directly; call _az_client_gen_do().
        '''
        assert max_tries > 0
        subscription_id = subscription_id or self.subscription_id
        for try_num in range(1, max_tries+1):
            try:
                return self._get_client_from_cli_profile(client_class, subscription_id=subscription_id, client_id=client_id)
            except knack.util.CLIError as exc:
                if (self.logger.level <= logging.DEBUG) or self.debug:
                    st = '\n' + traceback.format_exc().rstrip() + '\n' + repr(exc)
                else:
                    st = ''
                if try_num >= max_tries:
                    log_level = logging.ERROR
                    wr = 'will not retry'
                else:
                    log_level = logging.DEBUG
                    wr = 'will retry'
                self.logger.log(log_level, "%s cannot generate %s (%s)%s", self.mth(), name, wr, st)
                if try_num < max_tries:
                    # When several threads start up at the same time, we sometimes
                    # see transient failures when they try to auth simultaneously.
                    # Do a jittered sleep to break up convoys.
                    time.sleep(random.uniform(1.0, 3.0))
                    continue
                self.logger.log(log_level, "Try: az login --use-device-code")
                raise

    def _get_client__kwargs_extract_base_url(self, client_class, client_kwargs):
        '''
        Given kwargs used to construct an SDK client, extract and
        return the base_url. Apply any special-cases for client_class.
        '''
        ret = client_kwargs.pop('base_url', None)
        if ret:
            return ret
        if client_class is GraphRbacManagementClient:
            return self.cloud.endpoints.active_directory_graph_resource_id.rstrip('/')
        if client_class is KeyVaultManagementClient:
            return self.cloud.endpoints.resource_manager.rstrip('/')
        _, ret = azure.common.client_factory._client_resource(client_class, self.cloud) # pylint: disable=protected-access
        if ret:
            return ret
        return self.cloud.endpoints.resource_manager.rstrip('/')

    def _get_client__kwargs_extract_credential(self, client_kwargs, caller_tag=None):
        '''
        Given kwargs used to construct an SDK client, extract and
        return the credentials. Use default credentials from
        self.azure_credential_generate if none are found.
        '''
        client_id = client_kwargs.get('client_id', None)

        if ('credentials' in client_kwargs) and ('credential' in client_kwargs):
            assert id(client_kwargs['credentials']) == id(client_kwargs['credential'])
            credential = client_kwargs.pop('credentials')
            client_kwargs.pop('credential')
        elif 'credentials' in client_kwargs:
            credential = client_kwargs.pop('credentials')
        elif 'credential' in client_kwargs:
            credential = client_kwargs.pop('credential')
        else:
            credential = None

        if not credential:
            credential = self.azure_credential_generate(client_id=client_id, caller_tag=caller_tag)

        return credential

    def _get_client_from_cli_profile(self, client_class, **kwargs):
        '''
        Replacement for azure.common.client_factory.get_client_from_cli_profile()
        that does not depend on azure_cli_core.
        Instantiates an SDK client object of the given client_class.
        Do not call this directly; call _az_client_gen_do().
        '''
        base_url = self._get_client__kwargs_extract_base_url(client_class, kwargs)
        if not base_url:
            self.logger.warning("%s: no base_url for %s", self.mth(), client_class)
        credential = self._get_client__kwargs_extract_credential(kwargs, caller_tag=client_class.__name__)
        if not laaso.msapicall.client_is_track2(client_class):
            resource_url = base_url.rstrip('/') + '/.default'
            credential = laaso.msapicall.LaaSO_AzureIdentityCredentialAdapter(self.logger, credential, resource_url)
        subscription_id = kwargs.pop('subscription_id', '') or self.subscription_id
        tenant_id = kwargs.pop('tenant_id', '') or self.tenant_id

        parameters = {'base_url' : base_url,
                      'credential' : credential,
                      'credentials' : credential,
                      'subscription_id' : subscription_id,
                     }

        if tenant_id:
            parameters['tenant_id'] = tenant_id

        for kls, vers in API_VERSIONS_DEFAULT:
            if issubclass(client_class, kls):
                parameters['api_version'] = vers
                break

        parameters.update(kwargs)

        args = inspect.getfullargspec(client_class.__init__).args
        if ('adla_job_dns_suffix' in args) and ('adla_job_dns_suffix' not in parameters): # Datalake
            parameters['adla_job_dns_suffix'] = self.cloud.suffixes.azure_datalake_analytics_catalog_and_job_endpoint
        elif ('base_url' in args) and (not parameters['base_url']):
            parameters['base_url'] = self.cloud.endpoints.resource_manager
        if ('tenant_id' in args) and ('tenant_id' not in parameters) and self.tenant_id:
            parameters['tenant_id'] = self.tenant_id

        ret = self._instantiate_client(client_class, **parameters)
        return ret

    @staticmethod
    def _instantiate_client(target_class, **kwargs):
        '''
        Instantiate target_class. Extract positional arguments
        from kwargs and get them in the right order. Matches
        strictly by name. Silently discards anything in kwargs
        that does not match in target_class.
        '''
        signature = inspect.signature(target_class)
        cli_args_all = set(signature.parameters.keys())
        cli_args_positional = [name for name, param in signature.parameters.items() if param.default is inspect.Parameter.empty and param.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)]
        use_args = list()
        for key in cli_args_positional:
            assert isinstance(key, str)
            if key not in kwargs:
                raise ValueError("missing argument %r" % key)
            use_args.append(kwargs.pop(key))
        # Discard unwanted kwargs
        use_kwargs = {k : v for k, v in kwargs.items() if k in cli_args_all}
        return target_class(*use_args, **use_kwargs)

    def _az_client_gen_property(self, name, client_class, **kwargs):
        '''
        Generate self.<name> as self._az_client_gen_do(...).
        This sits on top of _az_client_gen_do and caches the result
        so it may be reused later, because some of these clients are
        expensive to construct.
        Currently, this only caches clients for the local subscription_id.
        '''
        with self._az_client_gen_lock:
            ret = getattr(self, name, None)
            if ret is None:
                ret = self._az_client_gen_do(name, client_class, **kwargs)
                setattr(self, name, ret)
            return ret

    ######################################################################
    # credentials

    def _credential_from_spec(self, spec, caller_tag):
        '''
        spec describes a credential
          AzCred.LOGIN: login credential
          AzCred.SYSTEM_ASSIGNED: system-assigned identity for this VM
          UUID-as-string: UAMI for this ID
        '''
        if spec == AzCred.LOGIN:
            credential = laaso.msapicall.AzLoginCredential(self.logger)
        elif spec == AzCred.SYSTEM_ASSIGNED:
            credential = azure.identity.ManagedIdentityCredential()
        else:
            credential = self._managed_identity_credential_generate(spec, caller_tag)
        return msapiwrap(self.logger, credential)

    def azure_credential_generate(self, client_id=None, caller_tag=None, allow_login_cred=True):
        '''
        Generate and return an appropriate credential object.
        If client_id is specified, use a ManagedIdentityCredential.
        Otherwise, use our custom AzLoginCredential object, which is a
        variant of DefaultAzureCredential that only considers cached
        az login credentials but does retries when fetching them.

        If a client_id is explicitly passed or pinned,
        then uami client_id is used to acquire credential obj of type ManagedIdentityCredential().
        '''
        caller_tag = caller_tag or getframe(1)

        append_login_credential = not self.require_msi

        client_id = client_id or self._pin_client_id or [AzCred.LOGIN]
        credentials = list()
        seen = list() # do not use a set to maintain ordering for debugging
        if client_id:
            if isinstance(client_id, (list, tuple)):
                for x in client_id:
                    xdesc = x.value if isinstance(x, AzCred) else x
                    if not x:
                        append_login_credential = True
                    elif xdesc not in seen:
                        credentials.append(self._credential_from_spec(x, caller_tag))
                        seen.append(xdesc)
            else:
                credentials.append(self._credential_from_spec(client_id, caller_tag))
                seen.append(client_id)
        else:
            append_login_credential = allow_login_cred

        if allow_login_cred and append_login_credential and (AzCred.LOGIN not in seen):
            credentials.append(self._credential_from_spec(AzCred.LOGIN, caller_tag))
            seen.append(None)

        self.logger.debug("%s caller_tag=%s generated %s", self.mth(), caller_tag, seen)

        if not credentials:
            self.logger.error("%s: no credentials caller_tag=%s client_id %s", self.mth(), caller_tag, client_id)
            raise ApplicationException(f"{self.mth()}: no credentials caller_tag={caller_tag}")
        if len(credentials) > 1:
            return azure.identity._credentials.chained.ChainedTokenCredential(*credentials) # pylint: disable=protected-access
        return credentials[0]

    def _managed_identity_credential_generate(self, client_id, caller_tag):
        '''
        Generate a single azure.identity.ManagedIdentityCredential for the given client_id.
        '''
        cid_mapped = laaso.identity.client_id_from_uami_str(client_id, self, resolve_using_azmgr=False)
        if not cid_mapped:
            raise ValueError("%s cannot process client_id=%r caller_tag=%s" % (self.mth(), client_id, caller_tag))
        try:
            credential = azure.identity.ManagedIdentityCredential(client_id=cid_mapped)
        except Exception as exc:
            self.logger.warning("cannot get managed credentials for identity %r caller_tag=%s: %r", cid_mapped, caller_tag, exc)
            raise
        self.logger.debug("acquired ManagedIdentityCredential for client_id=%r cid_mapped=%r caller_tag=%s self=%s", client_id, cid_mapped, caller_tag, hex(id(self)))
        return msapiwrap(self.logger, credential)

    ######################################################################
    # cloud meta operations

    _cloud_lock = threading.Lock()
    _cloud_obj = None

    def _cloud_obj_populate(self):
        '''
        Ensure that _cloud_obj is populated and return it
        '''
        with self._cloud_lock:
            if not self._cloud_obj:
                cloud = self.cloud_obj_get()
                type(self)._cloud_obj = cloud
                # Patch azure modules to return this cloud object
                # so we avoid import errors when azure-cli-core is not present.
                get_cli_active_cloud = lambda *args: cloud
                azure.common.client_factory.get_cli_active_cloud = get_cli_active_cloud
                azure.common.cloud.get_cli_active_cloud = get_cli_active_cloud
            return self._cloud_obj

    @property
    def cloud(self):
        '''
        Getter for cloud descriptor
        '''
        return self._cloud_obj_populate()

    @command.printable
    def cloud_obj_get(self):
        '''
        Return the cloud object corresponding to the cloud in which this VM is running.
        '''
        md = self.metadata_instance_get()
        cloud_str = md['compute']['azEnvironment']
        return laaso.clouds.cloud_get(cloud_str, exc_value=self.exc_value)

    ######################################################################
    # managed image operations

    MANAGED_IMAGE_AZRID_VALUES = {'provider_name' : 'Microsoft.Compute',
                                  'resource_type' : 'images',
                                 }

    @classmethod
    def managed_image_azrid(cls, resource_id):
        '''
        Return resource_id in AzResourceId form.
        '''
        return azrid_normalize(resource_id, AzResourceId, cls.MANAGED_IMAGE_AZRID_VALUES)

    @command.printable
    def managed_image_get(self, subscription_id=None, vm_image_resource_group=None, vm_image_name=None):
        '''
        Managed image; return azure.mgmt.compute.models.Image or None
        '''
        subscription_id = subscription_id or self.vm_image_subscription_id or self.subscription_id
        if not subscription_id:
            raise self.exc_value("'subscription_id' not specified")
        vm_image_resource_group = vm_image_resource_group or self.vm_image_resource_group or self.resource_group or laaso.scfg.get('vm_image_resource_group_default', '')
        if not vm_image_resource_group:
            raise self.exc_value("'vm_image_resource_group' not specified")
        vm_image_name = vm_image_name or self.vm_image_name
        if not vm_image_name:
            raise self.exc_value("'vm_image_name' not specified for %s" % getframename(0))
        return self._managed_image_get(subscription_id, vm_image_resource_group, vm_image_name)

    def _managed_image_get(self, subscription_id, resource_group, name):
        '''
        Managed image; return azure.mgmt.compute.models.Image or None
        '''
        az_compute = self.az_compute_get(subscription_id)
        try:
            return az_compute.images.get(resource_group, name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    @staticmethod
    def managed_image_id_parse(image_id):
        '''
        Determine whether image_id looks like a managed image ID.
        Return (subscription_id, resource_group, image_name) or None
        '''
        if not isinstance(image_id, str):
            return None
        scut = 'managed:'
        if image_id.lower().startswith(scut):
            toks = tuple(image_id[len(scut):].split('/'))
            if not all(toks):
                return False
            if len(toks) == 1:
                return (laaso.subscription_ids.subscription_default, laaso.scfg.get('vm_image_resource_group_default', '')) + toks
            if len(toks) == 2:
                return (laaso.subscription_ids.subscription_default,) + toks
            if len(toks) == 3:
                return toks
            return None
        try:
            azrid = AzResourceId.from_text(image_id, provider_name='Microsoft.Compute', resource_type='images', exc_value=ValueError)
        except ValueError:
            return None
        return (azrid.subscription_id, azrid.resource_group_name, azrid.resource_name)

    def managed_image_get_by_id(self, image_id):
        '''
        Given a managed image ID as an ARM resource ID or an abbreviated id, return azure.mgmt.compute.models.Image or None
        Example: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/someuser-image-build-b-22/providers/Microsoft.Compute/images/someuser-cbld-devel
        This is only for managed images.
        '''
        parsed = self.managed_image_id_parse(image_id)
        if not parsed:
            return None
        return self.managed_image_get_by_toks(parsed)

    def managed_image_get_by_toks(self, toks):
        '''
        toks is the result of gallery_image_id_parse()
        Return azure.mgmt.compute.models.Image or None.
        '''
        return self._managed_image_get(*toks)

    @staticmethod
    def managed_image_id_generate(subscription_id, resource_group, name):
        '''
        Generate and return a managed image resource id
        '''
        azrid = AzResourceId(subscription_id, resource_group, 'Microsoft.Compute', 'images', name)
        return str(azrid)

    ######################################################################
    # gallery image operations

    def _gallery_image_args_normalize(self, subscription_id, resource_group, gallery_name, image_name):
        '''
        Fill in values. Return tuple (subscription_id, resource_group, gallery_name, image_name, version).
        '''
        subscription_id = subscription_id or self.subscription_id
        if not subscription_id:
            raise self.exc_value("'subscription_id' not specified")
        resource_group = resource_group or self.resource_group
        if not resource_group:
            raise self.exc_value("'resource_group' not specified")
        gallery_name = gallery_name or self.gallery_name
        if not gallery_name:
            raise self.exc_value("'gallery_name' not specified")
        image_name = image_name or self.vm_image_name
        if not image_name:
            raise self.exc_value("'image_name' not specified")
        return (subscription_id, resource_group, gallery_name, image_name)

    def gallery_image_version_latest(self, subscription_id, resource_group, gallery_name, image_name):
        '''
        Get the latest version for the given gallery image definition. Return it as azure.mgmt.compute.models.GalleryImageVersion
        Return None for no-such-anything.
        '''
        image_versions = self.gallery_image_versions_list(subscription_id=subscription_id, resource_group=resource_group, gallery_name=gallery_name, image_name=image_name, sort=True)
        if not image_versions:
            return None
        return image_versions[-1]

    def gallery_image_versions_list(self, subscription_id=None, resource_group=None, gallery_name=None, image_name=None, sort=False, include_failed=False):
        '''
        Return a list of azure.mgmt.compute.models.GalleryImageVersion
        If any part of this does not exist, return an empty list. Does not return None.
        '''
        subscription_id, resource_group, gallery_name, image_name = self._gallery_image_args_normalize(subscription_id, resource_group, gallery_name, image_name)
        image_versions = self._gallery_image_versions_list(subscription_id, resource_group, gallery_name, image_name)
        if not include_failed:
            image_versions = [x for x in image_versions if x.provisioning_state.lower() == 'succeeded']
        if sort:
            try:
                image_versions.sort(key=lambda x: SemanticVersion.from_text(x.id.split('/')[-1]))
            except Exception as exc:
                self.logger.warning("%s.%s: unable to sort image_versions: %r\n%s",
                                    type(self).__name__, getframename(0), exc, indent_simple([x.id for x in image_versions]))
                raise
        return image_versions

    def _gallery_image_versions_list(self, subscription_id, resource_group, gallery_name, image_name):
        '''
        Return a list of azure.mgmt.compute.models.GalleryImageVersion
        If any part of this does not exist, return an empty list. Does not return None.
        List ordering is arbitrary.
        Only returns items with provisioning_state Succeeded.
        '''
        az_compute = self.az_compute_get(subscription_id=subscription_id)
        # image_versions is now an instance of msrest.paging.Paged.
        # Convert it to a list and exclude images that have not completed provisioning.
        # If there are no versions, or if the image definition or image gallery
        # do not exist, we still get a Paged object that will yield no items. If the
        # resource group does not exist, we get an error. Simplify the result
        # by always returning an empty list, even if the resource group does not exist.
        # We must expand the list inside the exception check because during expansion
        # the Paged object will make at least one call.
        try:
            image_versions = az_compute.gallery_image_versions.list_by_gallery_image(resource_group, gallery_name, image_name)
            # Force complete fetch of paged items inside the catch block to handle corner-cases with gallery updates
            image_versions = list(image_versions)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return list()
            raise
        return image_versions

    @command.printable
    def gallery_image_get(self, subscription_id=None, resource_group=None, gallery_name=None, image_name=None, version=None):
        '''
        Return azure.mgmt.compute.models.GalleryImageVersion or None
        '''
        subscription_id, resource_group, gallery_name, image_name = self._gallery_image_args_normalize(subscription_id, resource_group, gallery_name, image_name)
        if (not version) or (version == 'latest'):
            return self.gallery_image_version_latest(subscription_id, resource_group, gallery_name, image_name)
        return self._gallery_image_get(subscription_id, resource_group, gallery_name, image_name, version)

    def _gallery_image_get(self, subscription_id, resource_group, gallery_name, image_name, version):
        '''
        Return azure.mgmt.compute.models.GalleryImageVersion or None.
        Caller is responsible for providing version.
        '''
        try:
            az_compute = self.az_compute_get(subscription_id=subscription_id)
            return az_compute.gallery_image_versions.get(resource_group, gallery_name, image_name, version)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    @staticmethod
    def gallery_image_id_parse(image_id):
        '''
        Determine whether image_id looks like a gallery image ID, with or without version.
        Examples:
            /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/SBID-Build-Test/providers/Microsoft.Compute/galleries/cbldtest/images/cbld10-int/versions/0.1.1600256061
            /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/SBID-Build-Test/providers/Microsoft.Compute/galleries/cbldtest/images/cbld10-int
            gallery:11111111-1111-1111-1111-111111111111/SBID-Build-Test/cbldtest/cbld10-int/0.1.1600256061
            gallery:11111111-1111-1111-1111-111111111111/SBID-Build-Test/cbldtest/cbld10-int/latest
            gallery:infra-rg/some-gallery/cbld-devel/latest
            gallery:some-gallery/cbld-devel/latest
            gallery:cbld-devel/latest
        Return (subscription_id, resource_group, gallery_name, image_name, version)
        When no version is specified, version is None.
        '''
        if not isinstance(image_id, str):
            return None
        scut = 'gallery:'
        if image_id.lower().startswith(scut):
            toks = tuple(image_id[len(scut):].split('/'))
            if not all(toks):
                return False
            if len(toks) == 2:
                return (laaso.subscription_ids.dev_gallery_subscription_id, laaso.scfg.dev_gallery_resource_group, laaso.scfg.dev_gallery_name) + toks
            if len(toks) == 3:
                return (laaso.subscription_ids.dev_gallery_subscription_id, laaso.scfg.dev_gallery_resource_group) + toks
            if len(toks) == 4:
                return (laaso.subscription_ids.dev_gallery_subscription_id,) + toks
            if len(toks) == 5:
                return toks
            return None
        try:
            azrid = AzSub2ResourceId.from_text(image_id,
                                               provider_name='Microsoft.Compute',
                                               resource_type='galleries',
                                               subresource_type='images',
                                               sub2resource_type='versions',
                                               exc_value=ValueError)
            return (azrid.subscription_id, azrid.resource_group_name, azrid.resource_name, azrid.subresource_name, azrid.sub2resource_name)
        except ValueError:
            pass
        try:
            azrid = AzSubResourceId.from_text(image_id,
                                              provider_name='Microsoft.Compute',
                                              resource_type='galleries',
                                              subresource_type='images',
                                              exc_value=ValueError)
            return (azrid.subscription_id, azrid.resource_group_name, azrid.resource_name, azrid.subresource_name, None)
        except ValueError:
            pass
        return None

    def gallery_image_get_by_id(self, image_id):
        '''
        image_id is a gallery image ID with or without a version.
        Return azure.mgmt.compute.models.GalleryImageVersion or None.
        Returns None if image_id is not a gallery image ID.
        '''
        parsed = self.gallery_image_id_parse(image_id)
        if not parsed:
            return None
        return self.gallery_image_get_by_toks(parsed)

    def gallery_image_get_by_toks(self, toks):
        '''
        toks is the result of gallery_image_id_parse()
        Return azure.mgmt.compute.models.GalleryImageVersion or None.
        '''
        if (not toks[0]) or (not toks[-1]) or (toks[-1].lower() == 'latest'):
            return self.gallery_image_version_latest(*toks[:-1])
        return self._gallery_image_get(*toks)

    @staticmethod
    def gallery_image_id_generate(subscription_id, resource_group, gallery_name, image_name, version=None, exc_value=EXC_VALUE_DEFAULT):
        '''
        Generate and return a gallery image version resource id
        '''
        if version and (version.lower() != 'latest'):
            if not SemanticVersion.valid_with_patch(version):
                if exc_value:
                    raise exc_value("invalid version %r" % version)
                return None
            azrid = AzSub2ResourceId(subscription_id,
                                     resource_group,
                                     'Microsoft.Compute',
                                     'galleries',
                                     gallery_name,
                                     'images',
                                     image_name,
                                     'versions',
                                     version,
                                     exc_value=exc_value)
        else:
            azrid = AzSubResourceId(subscription_id,
                                    resource_group,
                                    'Microsoft.Compute',
                                    'galleries',
                                    gallery_name,
                                    'images',
                                    image_name,
                                    exc_value=exc_value)
        return str(azrid)

    def gallery_image_versions_create_or_update(self, resource_group, gallery_name, definition_name, image_version, parameters, subscription_id=None, log_level=logging.INFO, wait=True):
        '''
        Perform a gallery image version create_or_update using the given parameters.
        If wait is set, the operation completes and the result is returned.
        If wait is not set, the operation is launched and the LRO object is returned.
        Pass None for log_level to suppress logging for non-error paths.
        '''
        subscription_id = subscription_id or self.subscription_id
        if isinstance(image_version, SemanticVersion):
            image_version = str(image_version)
        image_id = self.gallery_image_id_generate(subscription_id, resource_group, gallery_name, definition_name, image_version)
        az_compute = self.az_compute_get(subscription_id=subscription_id)
        if log_level is not None:
            self.logger.log(log_level, "create image %s with parameters:\n%s", image_id, expand_item_pformat(parameters))
        try:
            poller = self.arm_poller(az_compute.gallery_image_versions)
            op = az_compute.gallery_image_versions.begin_create_or_update(resource_group, gallery_name, definition_name, image_version, parameters, polling=poller)
            if not wait:
                return op
            op.wait()
            res = op.result()
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                self.logger.error("cannot create image %s: %r", image_id, exc)
            else:
                self.logger.error("cannot create image %s: %r:\n%s", image_id, exc, expand_item_pformat(exc, noexpand_types=AZURE_NOEXPAND_TYPES))
            raise ApplicationExit("cannot create image %s: %r" % (image_id, exc)) from exc
        if log_level is not None:
            self.logger.log(log_level, "create %s result:\n%s", image_id, expand_item_pformat(res))
        return res

    ######################################################################
    # marketplace image operations

    def _marketplace_image_args_normalize(self, location, publisher, offer, sku):
        '''
        Fill in values. Return tuple (location, publisher, offer, sku)
        '''
        location = location or self.location
        if not location:
            raise self.exc_value("'location' not specified")
        publisher = publisher or self.publisher
        if not publisher:
            raise self.exc_value("'publisher' not specified")
        offer = offer or self.offer
        if not offer:
            raise self.exc_value("'offer' not specified")
        if not sku:
            raise self.exc_value("'sku' not specified")
        return (location, publisher, offer, sku)

    def marketplace_image_version_latest(self, location, publisher, offer, sku):
        '''
        Get the latest version for the given marketplace image.
        Return it as azure.mgmt.compute.models.VirtualMachineImage
        Return None for no-such-anything.
        '''
        # This is a unit testing hook; in production ASSUME_LATEST_IMAGE_VERSION is never set
        image_versions = self.marketplace_image_versions_list(location=location, publisher=publisher, offer=offer, sku=sku, sort=True)
        if not image_versions:
            return None
        # image_versions is not a list of azure.mgmt.compute.models.VirtualMachineImage, so do a get
        return self.marketplace_image_get_by_id(image_versions[-1].id)

    def marketplace_image_versions_list(self, location=None, publisher=None, offer=None, sku=None, sort=False):
        '''
        Return a list of azure.mgmt.compute.models.VirtualMachineImage
        If any part of this does not exist, return an empty list. Does not return None.
        '''
        location, publisher, offer, sku = self._marketplace_image_args_normalize(location, publisher, offer, sku)
        image_versions = self._marketplace_image_versions_list(location, publisher, offer, sku)
        if sort:
            image_versions.sort(key=lambda x: SemanticVersion.from_text(x.id.split('/')[-1]))
        return image_versions

    def _marketplace_image_versions_list(self, location, publisher, offer, sku):
        '''
        Return a list of azure.mgmt.compute.models.VirtualMachineImageResource
        NOTE: this is not the same type as marketplace_image_versions_get
        If any part of this does not exist, return an empty list. Does not return None.
        List ordering is arbitrary.
        '''
        # image_versions is now an instance of msrest.paging.Paged.
        # If there are no versions, or if the image definition or image gallery
        # do not exist, we still get a Paged object that will yield no items. If the
        # resource group does not exist, we get an error. Simplify the result
        # by always returning an empty list, even if the resource group does not exist.
        # We must expand the list inside the exception check because during expansion
        # the Paged object will make at least one call.
        try:
            image_versions = self.az_compute.virtual_machine_images.list(location, publisher, offer, sku)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return list()
            raise
        return image_versions

    def marketplace_image_get(self, location=None, publisher=None, offer=None, sku=None, version=None):
        '''
        Return azure.mgmt.compute.models.VirtualMachineImage or None
        If version is not specified, return the one with the largest version number.
        '''
        location, publisher, offer, sku = self._marketplace_image_args_normalize(location, publisher, offer, sku)
        if (not version) or (version == 'latest'):
            return self.marketplace_image_version_latest(location, publisher, offer, sku)
        return self._marketplace_image_get(location, publisher, offer, sku, version)

    def _marketplace_image_get(self, location, publisher, offer, sku, version):
        '''
        Return azure.mgmt.compute.models.VirtualMachineImage or None.
        Caller is responsible for providing version.
        '''
        try:
            return self.az_compute.virtual_machine_images.get(location, publisher, offer, sku, version)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    @classmethod
    def marketplace_image_id_parse(cls, image_id):
        '''
        Determine whether image_id looks like a marketplace ID, with or without version.
        Examples:
          /Subscriptions/11111111-1111-1111-1111-111111111111/Providers/Microsoft.Compute/Locations/eastus2/Publishers/Debian/ArtifactTypes/VMImage/Offers/debian-10/Skus/10/Versions/0.20200803.347
          /Subscriptions/11111111-1111-1111-1111-111111111111/Providers/Microsoft.Compute/Locations/eastus2/Publishers/Canonical/ArtifactTypes/VMImage/Offers/UbuntuServer/Skus/18_04-lts-gen2
        If not, return None.
        If so, return (location, publisher, offer, sku, version).
        If the ID matches but does not specify a version, the version in the result is None.
        We toss the subscription ID because it really does not matter. That ID
        is from the point-of-view of whoever generated it; this is not a resource that
        is part of the subscription.
        '''
        expect = [(0, ''),
                  (1, 'subscriptions'),
                  (3, 'providers'),
                  (4, 'microsoft.compute'),
                  (5, 'locations'),
                  (7, 'publishers'),
                  (9, 'artifacttypes'),
                  (10, 'vmimage'),
                  (11, 'offers'),
                  (13, 'skus'),
                 ]
        toks = cls._image_id_tokenize(image_id, expect)
        if not (toks and all(toks[1:])):
            return None
        if not cls.subscription_id_valid(laaso.subscription_mapper.effective(toks[2])):
            return None
        if len(toks) not in (15, 17):
            return None
        if len(toks) == 15:
            return (toks[6], toks[8], toks[12], toks[14], None)
        if len(toks) == 17:
            if toks[15].lower() != 'versions':
                return None
            return (toks[6], toks[8], toks[12], toks[14], toks[16])
        return None

    def marketplace_image_get_by_id(self, image_id):
        '''
        image_id is a marketplace image ID with or without a version.
        Return azure.mgmt.compute.models.VirtualMachineImage or None.
        Returns None if image_id is not a marketplace image ID.
        '''
        parsed = self.marketplace_image_id_parse(image_id)
        if not parsed:
            return None
        return self.marketplace_image_get_by_toks(parsed)

    def marketplace_image_get_by_toks(self, toks):
        '''
        toks is the result of marketplace_image_id_parse()
        Return azure.mgmt.compute.models.VirtualMachineImage or None.
        '''
        toks = list(toks)
        if (not toks[-1]) or (toks[-1].lower() == 'latest'):
            # Do not call marketplace_image_version_latest() here - that calls this operation.
            image_versions = self.marketplace_image_versions_list(location=toks[0], publisher=toks[1], offer=toks[2], sku=toks[3], sort=True)
            if not image_versions:
                return None
            latest = image_versions[-1]
            ltoks = self.marketplace_image_id_parse(latest.id)
            if not (ltoks and ltoks[-1] and SemanticVersion.valid_with_patch(ltoks[-1])):
                raise ValueError("%s.%s toks %s cannot parse latest.id=%r" % (type(self).__name__, getframename(0), toks, latest.id))
            toks = ltoks
        return self._marketplace_image_get(*toks)

    def marketplace_image_id_generate(self, location, publisher, offer, sku, version=None, exc_value=EXC_VALUE_DEFAULT):
        '''
        Generate and return a marketplace ID
        '''
        if version and (version.lower() != 'latest'):
            if not SemanticVersion.valid_with_patch(version):
                if exc_value:
                    raise exc_value("invalid version %r" % version)
                return None
            tmpl = '/Subscriptions/{subscription_id}/Providers/Microsoft.Compute/Locations/{location}/Publishers/{publisher}/ArtifactTypes/VMImage/Offers/{offer}/Skus/{sku}/Versions/{version}'
            return tmpl.format(subscription_id=self.subscription_id, location=location, publisher=publisher, offer=offer, sku=sku, version=version)
        tmpl = '/Subscriptions/{subscription_id}/Providers/Microsoft.Compute/Locations/{location}/Publishers/{publisher}/ArtifactTypes/VMImage/Offers/{offer}/Skus/{sku}'
        return tmpl.format(subscription_id=self.subscription_id, location=location, publisher=publisher, offer=offer, sku=sku)

    ######################################################################
    # all-purpose image operations

    @classmethod
    def _image_id_tokenize(cls, image_id, expect):
        '''
        Break image_id into tokens on '/' boundaries.
        expect is a bunch of index, value tuples.
        If the token at the given index does not match the given value (case-insensitive),
        return None.
        Return None for any other kind of parse failure as well.
        '''
        if not isinstance(image_id, str):
            return None
        toks = image_id.split('/')
        if (not toks) or toks[0]:
            return None
        for idx, expect_val in expect:
            try:
                if toks[idx].lower() != expect_val.lower():
                    return None
            except IndexError:
                return None
        return toks

    @classmethod
    def vm_image_id_is_fully_resolved(cls, image_id):
        '''
        Determine whether the given image_id is fully resolved.
        That means that it is a valid resource ID. If the resource
        id contains a version (such as for a gallery or marketplace image),
        the version must be resolved to a semantic version.
        '''
        # marketplace
        toks = cls.marketplace_image_id_parse(image_id)
        if toks:
            # This is a marketplace image. Check for a valid version.
            return SemanticVersion.valid_with_patch(toks[-1])

        azrid = azresourceid_from_text(image_id, exc_value=None)
        if not azrid:
            return False

        if isinstance(azrid, AzResourceId) and azrid.values_match(provider_name='Microsoft.Compute',
                                                                  resource_type='images'):
            # managed image
            return True

        if isinstance(azrid, AzSub2ResourceId) and azrid.values_match(provider_name='Microsoft.Compute',
                                                                      resource_type='galleries',
                                                                      subresource_type='images',
                                                                      sub2resource_type='versions'):
            # gallery image version
            return SemanticVersion.valid_with_patch(azrid.sub2resource_name)

        return False

    @classmethod
    def vm_image_name_extract(cls, image_id):
        '''
        Extract the logical image name from an image ID.
        Returns None if the image ID is not parseable.
        '''
        if not isinstance(image_id, str):
            return None

        # marketplace
        toks = cls.marketplace_image_id_parse(image_id)
        if toks:
            # marketplace image - return the offer name
            return toks[2]

        azrid = azresourceid_from_text(image_id, exc_value=None)
        if not azrid:
            return None

        if isinstance(azrid, AzResourceId) and azrid.values_match(provider_name='Microsoft.Compute',
                                                                  resource_type='images'):
            # managed image - return the image name
            return azrid.resource_name

        if isinstance(azrid, AzSubResourceId) and azrid.values_match(provider_name='Microsoft.Compute',
                                                                     resource_type='galleries',
                                                                     subresource_type='images'):
            # gallery image version but no version specified - return the definition name
            return azrid.subresource_name

        if isinstance(azrid, AzSub2ResourceId) and azrid.values_match(provider_name='Microsoft.Compute',
                                                                      resource_type='galleries',
                                                                      subresource_type='images',
                                                                      sub2resource_type='versions'):
            # gallery image version - return the definition name
            return azrid.subresource_name

        return None

    # image mapping: orchestrating apps may add translations of
    # image_id to azure resource ID by calling vm_image_map_add()
    _image_map_lock = threading.Lock()
    _image_map_dict = dict()

    def vm_image_map_add(self, name, image_id, exc_value=EXC_VALUE_DEFAULT):
        '''
        Add a name -> image_id mapping as a virtual shortcut.
        This is useful for orchestrating apps such as ImageBuildApplication.
        '''
        self.logger.debug("%s.%s map %r -> %r", type(self).__name__, getframename(0), name, image_id)
        assert isinstance(name, str)
        assert isinstance(image_id, str)
        with self._image_map_lock:
            if name in laaso.scfg.image_shortcuts:
                raise exc_value("%s.%s attempt to map shortcut %r to %r" % (type(self).__name__, getframename(0), name, image_id))
            prev = self._image_map_dict.setdefault(name, image_id)
            if prev != image_id:
                raise exc_value("%s.%s attempt to replace %r mapping %r -> %r" % (type(self).__name__, getframename(0), name, prev, image_id))

    def _vm_image_mapped(self, image_id):
        '''
        Iterate resolving the image through the map and shortcuts.
        Return the mapped result.
        '''
        cur = image_id
        done = False
        while not done:
            done = True
            for d in (laaso.scfg.get('image_shortcuts', {}), self._image_map_dict):
                try:
                    cur = d[cur]
                    done = False
                    assert isinstance(cur, str)
                except KeyError:
                    pass
        return cur

    def vm_image_get_by_id(self, image_id):
        '''
        Given an arbitrary resource ID string, figure out and use the appropriate
        API to get and return the corresponding image object.
        Return None for not-found or if image_id is not a valid image ID.
        '''
        if not isinstance(image_id, str):
            raise TypeError("image_id expected str, not %s" % type(image_id))

        image_id_mapped = self._vm_image_mapped(image_id)

        toks = self.managed_image_id_parse(image_id_mapped)
        if toks:
            return self.managed_image_get_by_toks(toks)

        toks = self.gallery_image_id_parse(image_id_mapped)
        if toks:
            return self.gallery_image_get_by_toks(toks)

        toks = self.marketplace_image_id_parse(image_id_mapped)
        if toks:
            return self.marketplace_image_get_by_toks(toks)

        return None

    def vm_image_id_normalize(self, image_id):
        '''
        Take an image_id that might be a fully-qualified ID,
        a gallery or marketplace image missing a version,
        a shortcut, etc. Return a fully-qualified ID. Does not
        populate the version of versioned image IDs if the
        version is not provided. To fully resolve the version,
        use vm_image_id_resolve() instead.
        '''
        if not isinstance(image_id, str):
            raise TypeError("image_id expected str, not %s" % type(image_id))

        image_id = self._vm_image_mapped(image_id)

        toks = self.managed_image_id_parse(image_id)
        if toks:
            return self.managed_image_id_generate(*toks)

        toks = self.gallery_image_id_parse(image_id)
        if toks:
            return self.gallery_image_id_generate(*toks, exc_value=self.exc_value)

        toks = self.marketplace_image_id_parse(image_id)
        if toks:
            return self.marketplace_image_id_generate(*toks)

        raise self.exc_value("invalid image_id %r" % image_id)

    def vm_image_id_resolve(self, image_id):
        '''
        Like vm_image_id_normalize(), but resolves to an exact
        version of a versioned image. Returns None if the image
        cannot be resolved.
        '''
        image_obj = self.vm_image_get_by_id(image_id)
        if not image_obj:
            return None
        return image_obj.id

    @command.printable
    def vm_image_os_disk_size_gb_get(self, image=None):
        '''
        Return the size in GiB of the OS disk for the given image or None if not known
        '''
        image = image or self.vm_image_name
        if not image:
            raise self.exc_value("'image' not specified")

        if isinstance(image, str):
            image_obj = self.vm_image_get_by_id(image)
        else:
            image_obj = image

        if isinstance(image_obj, azure.mgmt.compute.models.Image):
            try:
                return image_obj.storage_profile.os_disk.disk_size_gb
            except AttributeError:
                return None

        if isinstance(image_obj, azure.mgmt.compute.models.GalleryImageVersion):
            try:
                return image_obj.storage_profile.os_disk_image.size_in_gb
            except AttributeError:
                return None

        if isinstance(image_obj, azure.mgmt.compute.models.VirtualMachineImage):
            try:
                return image_obj.os_disk_image.additional_properties['sizeInGb']
            except AttributeError:
                return None

        return None

    def vm_image_reference(self, image_id):
        '''
        Given an image_id (str), return an appropriate image_reference.
        This result may be used as the image_reference for a VM storage_profile.
        The image_id may not be used directly because marketplace image IDs
        may not be provided.
        '''
        if not isinstance(image_id, str):
            raise TypeError("image_id expected str, not %s" % type(image_id))

        image_id_mapped = self._vm_image_mapped(image_id)

        toks = self.marketplace_image_id_parse(image_id_mapped)
        if toks:
            _, publisher, offer, sku, version = toks
            if version and (version.lower() == 'latest'):
                version = None
            ret = {'offer' : offer,
                   'publisher' : publisher,
                   'sku' : sku,
                  }
            if version:
                ret['exact_version'] = version
                ret['version'] = version
            return ret

        return {'id' : image_id_mapped}

    ######################################################################
    # dedicated-host group and dedicated host wrappers
    #

    def dedicated_host_group_create(self, dh_rg, dh_group_name, dh_group_params):
        '''
        create a dedicated host group and return azure.compute.models.DedicatedHostGroup obj
        '''
        return self._dedicated_host_group_create(self.subscription_id, dh_rg, dh_group_name, dh_group_params)

    def _dedicated_host_group_create(self, subscription_id, dh_rg, dh_group_name, dh_group_params):
        '''
        wrapper around DedicatedHostGroupsOperations create_or_update
        '''
        try:
            az_compute = self.az_compute_get(subscription_id)
            res = az_compute.dedicated_host_groups.begin_create_or_update(dh_rg, dh_group_name, dh_group_params)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if self.debug > 0:
                if caught.is_missing():
                    self.logger.debug("cannot create dedicated host group %r in RG %r: %r", dh_group_name, dh_rg, exc)
                else:
                    self.logger.debug("cannot create dedicated host group %r in RG %r: %r:\n%s",
                                      dh_group_name, dh_rg, exc, expand_item_pformat(exc, noexpand_types=AZURE_NOEXPAND_TYPES))
            raise
        if self.debug > 0:
            self.logger.debug("Dedicated Host Group Op Result:\n%s", expand_item_pformat(res))
        return res

    def dedicated_host_group_get(self, dh_group_name, resource_group=None, subscription_id=None):
        '''
        wrapper around _dedicated_host_group_get
        '''
        if not dh_group_name:
            raise ApplicationExit("%s: 'dh_group_name' not specified" % self.mth())
        resource_group = resource_group or self.resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        subscription_id = subscription_id or self.subscription_id
        return self._dedicated_host_group_get(self.subscription_id, resource_group, dh_group_name)

    def _dedicated_host_group_get(self, subscription_id, resource_group, dh_group_name):
        '''
        wrapper around DedicatedHostGroupsOperations get
        '''
        try:
            az_compute = self.az_compute_get(subscription_id)
            return az_compute.dedicated_host_groups.get(resource_group, dh_group_name, expand='instanceView')
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    def dedicated_host_create(self, dh_rg, dh_group_name, dh_name, dh_params):
        '''
        creates dedicated host and return azure.mgmt.compute.DedicatedHost object
        '''
        return self._dedicated_host_create(self.subscription_id, dh_rg, dh_group_name, dh_name, dh_params)

    def _dedicated_host_create(self, subscription_id, dh_rg, dh_group_name, dh_name, dh_params):
        '''
        wrapper around DedicatedHostOperations create_or_update
        '''
        try:
            az_compute = self.az_compute_get(subscription_id)
            poller = self.arm_poller(az_compute.dedicated_hosts)
            op = az_compute.dedicated_hosts.begin_create_or_update(dh_rg, dh_group_name, dh_name, dh_params, polling=poller)
            op.wait()
            res = op.result()
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if self.debug > 0:
                if caught.is_missing():
                    self.logger.debug("cannot create dedicated host %r in host group %r in RG %r: %r", dh_name, dh_group_name, dh_rg, exc)
                else:
                    self.logger.debug("cannot create dedicated host %r in host group %r in RG %r: %r:\n%s",
                                      dh_name, dh_group_name, dh_rg, exc, expand_item_pformat(exc, noexpand_types=AZURE_NOEXPAND_TYPES))
            raise
        if self.debug > 0:
            self.logger.debug("Dedicated Host Op Result:\n%s", expand_item_pformat(res))
        return res

    def dedicated_host_get(self, dh_group_name, dh_name, resource_group=None, subscription_id=None):
        '''
        wrapper around _dedicated_host_group_create
        '''
        if not dh_group_name:
            raise ApplicationExit("%s: 'dh_group_name' not specified" % self.mth())
        if not dh_name:
            raise ApplicationExit("%s: 'dh_name' not specified" % self.mth())
        resource_group = resource_group or self.resource_group
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        subscription_id = subscription_id or self.subscription_id
        return self._dedicated_host_get(self.subscription_id, resource_group, dh_group_name, dh_name)

    def _dedicated_host_get(self, subscription_id, resource_group, dh_group_name, dh_name):
        '''
        wrapper around DedicatedHostOperations get
        '''
        try:
            az_compute = self.az_compute_get(subscription_id)
            return az_compute.dedicated_hosts.get(resource_group, dh_group_name, dh_name, expand='instanceView')
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    ######################################################################
    # vm_extension wrappers

    def vm_extension_create(self, vm_rg, vm_name, vm_extension_name, vm_ext_parameters):
        '''
        wrapper around _vm_extension_create which is mocked in managermock
        '''
        return self._vm_extension_create(self.subscription_id, vm_rg, vm_name, vm_extension_name, vm_ext_parameters)

    def _vm_extension_create(self, subscription_id, vm_rg, vm_name, vm_extension_name, vm_ext_parameters):
        '''
        Wrapper around vm_extension create_or_update
        '''
        try:
            az_compute = self.az_compute_get(subscription_id)
            poller = self.arm_poller(az_compute.virtual_machine_extensions)
            op = az_compute.virtual_machine_extensions.begin_create_or_update(vm_rg, vm_name, vm_extension_name, vm_ext_parameters, polling=poller)
            op.wait()
            res = op.result()
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                self.logger.error("cannot create extension %r in VM %r: %r", vm_extension_name, vm_name, exc)
            else:
                self.logger.error("cannot create extension %r in VM %r: %r:\n%s",
                                  vm_extension_name, vm_name, exc, expand_item_pformat(exc, noexpand_types=AZURE_NOEXPAND_TYPES))
            raise ApplicationExit("cannot create extension %r in VM %r" % (vm_extension_name, vm_name)) from exc
        if self.debug > 0:
            self.logger.debug("VM Extension Op Result:\n%s", expand_item_pformat(res))
        return res

    def vm_extension_get(self, vm_name, vm_extension_name, resource_group=None, subscription_id=None):
        '''
        Return azure.mgmt.compute.models.VirtualMachineExtension or None
        '''
        if not vm_name:
            raise ApplicationExit("%s: 'vm_name' not specified" % self.mth())
        if not resource_group:
            raise ApplicationExit("'resource_group' not specified")
        subscription_id = subscription_id or self.subscription_id
        return self._vm_extension_get(subscription_id, resource_group, vm_name, vm_extension_name)

    def _vm_extension_get(self, subscription_id, vm_rg, vm_name, vm_extension_name):
        '''
        Return azure.mgmt.compute.models.VirtualMachineExtension or None
        '''
        try:
            az_compute = self.az_compute_get(subscription_id)
            return az_compute.virtual_machine_extensions.get(vm_rg, vm_name, vm_extension_name)
        except Exception as exc:
            caught = laaso.msapicall.Caught(exc)
            if caught.is_missing():
                return None
            raise

    ######################################################################
    # VM mgmt

    def vm_update(self, vm_rg, vm_name, vm_parameters,
                  log_level=logging.INFO,
                  opname='',
                  reissue=None,
                  wait_error=None):
        '''
        Do the work to issue and wait for a VM update to complete.
        reissue is a callout invoked when the operation must be reissued for any reason.
        wait_error is a callout invoked when the LRO poller wait() fails. This is invoked in the exception context.
        '''
        reissue = reissue or (lambda *args: None)
        wait_error = wait_error or (lambda *args: None)
        vm_op = None
        time0 = time.time()
        do_reissue = True
        verb = 'begin'
        prefix = opname.rstrip()
        if prefix:
            prefix += ' '
        while True:
            if (not vm_op) or do_reissue:
                if vm_op:
                    reissue(vm_rg, vm_name, vm_parameters)
                verb = 'begin'
                poller = self.arm_poller(self.az_compute.virtual_machines)
                vm_op = self.az_compute.virtual_machines.begin_update(vm_rg, vm_name, vm_parameters, polling=poller)
            else:
                verb = 'resume'
                if self.op_resume_debug:
                    thread_info = [[thread.name, thread, traceback.format_stack(sys._current_frames()[thread.ident])] for thread in threading.enumerate()] # pylint: disable=protected-access
                    self.logger.log(log_level, "%s%s thread=%s threads:\n%s",
                                    prefix, verb, laaso.msapicall.op_thread_get(vm_op),
                                    expand_item_pformat(thread_info))
            do_reissue = True
            if vm_op.done():
                self.logger.log(log_level, "%sop %s done with status %s", prefix, type(vm_op), vm_op.status())
                break
            if elapsed(time0) < 300:
                timeout = 60
            elif elapsed(time0) < 1800:
                timeout = 300
            else:
                timeout = None
            self.logger.log(log_level, "%sop %s %s waiting with status %r", prefix, self.polling_op_operation_id(vm_op), verb, vm_op.status())
            try:
                vm_op.wait(timeout=timeout)
                if vm_op.done():
                    break
                do_reissue = False
            except Exception as exc:
                self.logger.warning("%swait op %s wait failure %r", prefix, self.polling_op_operation_id(vm_op), exc)
                wait_error(vm_rg, vm_name, vm_parameters, exc)
        self.logger.log(log_level, "%sop %s %s done waiting", prefix, type(vm_op).__name__, self.polling_op_operation_id(vm_op))
        res = vm_op.result()
        return res

    ######################################################################
    # VM other

    @staticmethod
    def vm_custom_data_encode(data, check_len=True, exc_value=EXC_VALUE_DEFAULT):
        '''
        Convert data to encoded VM custom data. This accepts data as anything that base64.b64encode
        accepts. Further, if data is a str, it is assumed ascii and converted
        to bytes automatically.
        '''
        if isinstance(data, str):
            data = bytes(data, encoding='ascii')
        ret = str(base64.b64encode(data), encoding='ascii')
        if check_len and (len(ret) > VM_CUSTOM_DATA_LEN_MAX):
            raise exc_value(f"custom_data is too long ({len(ret)} > {VM_CUSTOM_DATA_LEN_MAX})")
        return ret

    @classmethod
    def vm_custom_data_from_file(cls, filename, exc_value=EXC_VALUE_DEFAULT):
        '''
        Read filename, base64 encode it, and return it.
        '''
        with open(laaso.paths.repo_root_path(filename), 'rb') as f:
            data = f.read()
        ret = cls.vm_custom_data_encode(data, check_len=False, exc_value=exc_value)
        if len(ret) > VM_CUSTOM_DATA_LEN_MAX:
            raise exc_value(f"vm_custom_data_filename {filename!r} is too long ({len(ret)} > {VM_CUSTOM_DATA_LEN_MAX})")
        return ret

    ######################################################################
    # common SDK iteractions

    @staticmethod
    def sdk_resource_obj_normalize(obj, resource_values, resource_type_str, docopy=True):
        '''
        obj is an arbitrary SDK object that represents a resource.
        Normalize obj.id and obj.type using the contents of the resource_values dict.
        '''
        if obj:
            if docopy:
                obj = copy.deepcopy(obj)
            azrid = azresourceid_or_none_from_text(obj.id, **resource_values)
            if azrid:
                obj.id = str(azrid)
            if obj.type.lower() == resource_type_str.lower():
                obj.type = resource_type_str
        return obj

    ######################################################################
    # bootstrapping helpers

    @classmethod
    def bootstrap_from_subscription_display_name(cls, subscription_display_name, **kwargs):
        '''
        Generate an object for the given subscription_display_name
        '''
        managed_identity_client_id = kwargs.get('managed_identity_client_id', None)
        az_mgr = cls(managed_identity_client_id=managed_identity_client_id,
                     subscription_id=laaso.util.UUID_ZERO)
        subscription_id = az_mgr.subscription_id_from_display_name(subscription_display_name)
        if not subscription_id:
            raise ApplicationExit(f"cannot find subscription with display_name {subscription_display_name!r}")
        kwargs.setdefault('subscription_id', subscription_id)
        return cls(**kwargs)

    ######################################################################
    # main stuff below here

    ARG_USERNAME_ADD = True
    ARG_USERNAME_HELP = 'user name'

    @classmethod
    def main_add_parser_args(cls, ap_parser):
        '''
        See laaso.Application.main_add_parser_args()
        '''
        super().main_add_parser_args(ap_parser)

        at_group = ap_parser.get_argument_group('azure_tool')

        # We could say choices=command.actions here, but doing so prevents
        # us from auto-handling X_print.
        ap_parser.add_argument('action', type=str,
                               help='what to do')

        at_group.add_argument('--cert_name', type=str, default='',
                              help='certificate name')
        at_group.add_argument('--clientids_filepath', type=str, default='',
                              help='path to yaml file containing managed identity:client_id key/value pair')
        at_group.add_argument('--disk_name', type=str, default='',
                              help='name of Azure persistent disk')
        at_group.add_argument('--gallery_name', type=str, default='',
                              help='name of Azure image gallery')
        at_group.add_argument('--idx_min', type=int, default=1,
                              help='minimum index (for substituions)')
        at_group.add_argument('--idx_max', type=int, default=1,
                              help='maximum index (for substituions)')
        at_group.add_argument('--keyvault_name', type=str, default='',
                              help='name of for user managed identity for dev keyvault')
        at_group.add_argument('--keyvault_resource_group', type=str, default='',
                              help='resource_group for keyvault_id')
        at_group.add_argument('--location', type=str, default='',
                              help="Azure location (defaults to per-subscription default if there is one, otherwise %s)" % laaso.base_defaults.LOCATION_DEFAULT_FALLBACK)
        at_group.add_argument('--managed_identity', type=str, default='',
                              help='user managed identity for dev keyvault')
        at_group.add_argument('--managed_identity_client_id', type=str, default='',
                              help='client id for managed identity credentials')
        at_group.add_argument('--nic_name', type=str, default='',
                              help='name of Azure NIC')
        at_group.add_argument('--nsg_name', type=str, default='',
                              help='name of network security group')
        at_group.add_argument('--offer', type=str, default='',
                              help='offer (as in VM marketplace image)')
        at_group.add_argument('--os_disk_size_force', action="store_true",
                              help='force the use of an incompatible os_disk_size_gb')
        at_group.add_argument('--os_disk_size_gb', type=int, default=Manager.OS_DISK_SIZE_GB_DEFAULT,
                              help='size of OS disk (GB)')
        at_group.add_argument('--pubkey_filename', type=str, default='',
                              help='SSH public key filename')
        at_group.add_argument('--pubkey_keyvault_client_id', type=str, default='',
                              help='client_id (uuid) for pubkey downloads')
        at_group.add_argument('--pubkey_keyvault_name', type=str, default='',
                              help='name of keyvault for pubkey downloads')
        at_group.add_argument('--publisher', type=str, default='',
                              help='publisher name to use for relevant ops; otherwise ignored')
        at_group.add_argument('--secret_name', type=str, default='',
                              help='secret name')
        at_group.add_argument('--storage_account', type=str, default='',
                              help='name of storage account')
        at_group.add_argument('--subnet_name', type=str, default='',
                              help='name of subnet in vnet')
        at_group.add_argument('--vm_boot_diags_storage_account', type=str, default='',
                              help="storage account for VM boot diagnostics")
        at_group.add_argument('--vm_image_name', type=str, default=Manager.VM_IMAGE_NAME_DEFAULT,
                              help='name of image to use for VM creation')
        at_group.add_argument('--vm_image_resource_group', type=str, default='',
                              help='resource group of image to use for VM creation')
        at_group.add_argument('--vm_image_version', type=str, default='',
                              help='version of vm_image_name image within gallery')
        at_group.add_argument('--vm_name', type=str, default='',
                              help="VM name (example: 'userid-tmp-{idx:02d}')")
        at_group.add_argument('--vm_resource_group', type=str, default='',
                              help='VM resource_group')
        at_group.add_argument('--vm_size', type=str, default=Manager.VM_SIZE_DEFAULT,
                              help='vm_size (see https://docs.microsoft.com/en-us/azure/virtual-machines/linux/sizes-storage)')
        at_group.add_argument('--vnet_name', type=str, default='',
                              help='name of vnet in vnet')
        at_group.add_argument('--vnet_resource_group', type=str, default='',
                              help='resource group of vnet in vnet')
        at_group.add_argument('--vnet_gateway_name', type=str, default='',
                              help='name of virtual network gateway')

    ARGS_SAVE = ('action',
                 'idx_min',
                 'idx_max',
                 'vm_name',
                )

    command = None

    def main_execute(self):
        '''
        See laaso.Application.main_execute()
        '''
        action = self._args_saved['action']
        idx_max = self._args_saved['idx_max']
        idx_min = self._args_saved['idx_min']
        vm_name = self._args_saved['vm_name']

        if idx_min > idx_max:
            self.logger.error("invalid idx range %d..%d", idx_min, idx_max)
            raise ApplicationExit(1)

        vm_names = [vm_name.format(idx=idx) for idx in range(idx_min, idx_max+1)]

        if (action == 'resource_group_delete') and ('resource_group' not in self.args_explicit):
            # safety: do not delete RGs from the environment
            self.logger.error("must specify resource_group explicitly for action %s", action)
            raise ApplicationExit(1)

        simple_handlers = ('printable', 'printable_raw', 'simple')
        vm_name_handlers = ('printable_vm_name', 'vm_name')

        if action == 'vm_create':
            self.vms_create(vm_names)
        elif self.command.handle(action, simple_handlers, self):
            pass
        elif self.command.can_handle(action, vm_name_handlers, self, ''):
            for vm_name in vm_names:
                assert self.command.handle(action, vm_name_handlers, self, vm_name)
        elif self.command.handle(action, 'wait', self, wait=1):
            pass
        else:
            ext = '_print'
            if action.endswith(ext):
                try:
                    a = getattr(self, action[:-len(ext)])
                    if not callable(a):
                        self.command.print(a)
                        raise ApplicationExit(0)
                except AttributeError:
                    pass
            self.logger.error("Unknown action '%s'", action)
            raise ApplicationExit(1)
        raise ApplicationExit(0)

Manager.command = command

def manager_for(thing, manager=None, update_thing=False, logger=None):
    '''
    thing is a subscription_id or an object with a subscription_id attribute
    manager is None or a Manager object
    Return a Manager object for thing, using the passed-in manager iff appropriate
    '''
    if isinstance(thing, str):
        assert not update_thing
        subscription_id = thing.lower()
    else:
        if (thing.subscription_id is None) and isinstance(manager, Manager) and manager.subscription_id:
            if update_thing:
                thing.subscription_id = manager.subscription_id
            return manager
        subscription_id = thing.subscription_id.lower()
    assert isinstance(subscription_id, str)
    assert RE_UUID_ABS.search(subscription_id)
    if manager:
        assert isinstance(manager, Manager)
        if manager.subscription_id and (manager.subscription_id.lower() == subscription_id):
            return manager
        if not logger:
            logger = manager.logger
    else:
        assert manager is None
    return Manager(subscription_id=subscription_id, logger=logger)

class StorageKeyCache():
    '''
    Cache storage keys
    '''
    def __init__(self, logger):
        self.logger = logger
        self._skc = dict() # [subscription][rg][sa] : StorageKeyCacheEnt
        self._lock_skc = threading.Lock() # locks _skc, but not the ent
        self._sarg = dict() # [subscription][sa] : resource_group_name
        self._lock_sarg = threading.Lock()

    def _ent_get(self, subscription_id, resource_group_name, storage_account_name):
        '''
        Retrieve or create StorageKeyCacheEnt
        '''
        with self._lock_skc:
            rgs = self._skc.setdefault(subscription_id, dict())
            sas = rgs.setdefault(resource_group_name, dict())
            try:
                return sas[storage_account_name]
            except KeyError:
                ret = self.StorageKeyCacheEnt(subscription_id, resource_group_name, storage_account_name)
                sas[storage_account_name] = ret
                return ret

    def rg_for(self, subscription_id, storage_account_name, manager=None):
        '''
        Figure out the resource_group for storage_account_name. Use a cache.
        '''
        assert (isinstance(subscription_id, str) and subscription_id) or ((subscription_id is None) and isinstance(manager, Manager) and manager.subscription_id)
        assert isinstance(storage_account_name, str) and storage_account_name
        subscription_id = subscription_id or manager.subscription_id
        with self._lock_sarg:
            sas = self._sarg.setdefault(subscription_id, dict())
            try:
                return sas[storage_account_name]
            except KeyError:
                pass
            # This will re-list on subsequent misses. We do that to handle
            # the case where the SA is created after the first list.
            manager = manager_for(subscription_id, manager=manager, logger=self.logger)
            for resource in manager.resource_list_storage_accounts():
                toks = resource.id.split('/')
                if toks[1].lower() != 'subscriptions':
                    self.logger.warning("%s.%s: unexpected token 1 %r (ignoring resource)", type(self).__name__, getframe(0), toks[1])
                    continue
                if toks[3].lower() != 'resourcegroups':
                    self.logger.warning("%s.%s: unexpected token 3 %r (ignoring resource)", type(self).__name__, getframe(0), toks[3])
                    continue
                if toks[5].lower() != 'providers':
                    self.logger.warning("%s.%s: unexpected token 5 %r (ignoring resource)", type(self).__name__, getframe(0), toks[5])
                    continue
                if toks[6].lower() != 'microsoft.storage':
                    self.logger.warning("%s.%s: unexpected token 6 %r (ignoring resource)", type(self).__name__, getframe(0), toks[6])
                    continue
                if toks[7].lower() != 'storageaccounts':
                    self.logger.warning("%s.%s: unexpected token 7 %r (ignoring resource)", type(self).__name__, getframe(0), toks[7])
                    continue
                sas[toks[8]] = toks[4]
            try:
                return sas[storage_account_name]
            except KeyError:
                return None

    def retrieve(self, storage_account_name, subscription_id=None, resource_group_name=None, manager=None):
        '''
        Return list of keys, or None if something does not exist.
        storage_account_name can be a string, StorageAccountName, ContainerName, or BlobName.
        '''
        assert storage_account_name
        if isinstance(storage_account_name, StorageAccountName):
            assert (not subscription_id) or (subscription_id == storage_account_name.subscription_id)
            subscription_id = storage_account_name.subscription_id
            storage_account_name = storage_account_name.storage_account_name
            if not resource_group_name:
                if not subscription_id:
                    raise ValueError("missing subscription_id")
                resource_group_name = self.rg_for(subscription_id, storage_account_name, manager=manager)
        if not (subscription_id or manager):
            raise ValueError("must provide at least one of subscription_id, manager")
        subscription_id = subscription_id if subscription_id else manager.subscription_id
        assert subscription_id
        if not resource_group_name:
            resource_group_name = self.rg_for(subscription_id, storage_account_name, manager=manager)
        if not resource_group_name:
            # storage account does not exist
            return None
        ent = self._ent_get(subscription_id, resource_group_name, storage_account_name)
        assert ent
        return ent.fetch(manager)

    def retrieve_one(self, *args, **kwargs):
        '''
        Return one key, or None if something does not exist.
        '''
        keys = self.retrieve(*args, **kwargs)
        if keys:
            for key in keys:
                if key:
                    return key
        return None

    class StorageKeyCacheEnt():
        '''
        One entry in StorageKeyCache. Factored out to make the populated/busy
        logic easier to read. That logic is necessary because populating
        one entry can take a long time, and there's no reason to serialize
        populating separate entries on each other.
        '''
        def __init__(self, subscription_id, resource_group_name, storage_account_name):
            self.subscription_id = subscription_id
            self.resource_group_name = resource_group_name
            self.storage_account_name = storage_account_name
            self.cond = threading.Condition(lock=threading.Lock())
            self.busy = False
            self.populated = False
            self.keys = list()

        def fetch(self, manager):
            '''
            Iff necessary, attempt to populate.
            '''
            with self.cond:
                while self.busy:
                    self.cond.wait()
                try:
                    if not self.populated:
                        self.busy = True
                        # This caches a miss as well
                        self.keys = manager.storage_account_keys_get(storage_account_name=self.storage_account_name, storage_account_resource_group_name=self.resource_group_name)
                        self.populated = True
                    return self.keys
                finally:
                    if self.busy:
                        self.busy = False
                        self.cond.notify()

Manager.main(__name__)

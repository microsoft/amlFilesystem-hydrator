#
# laaso/data_disks.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Types, values, and ops related to data disk management
'''
import enum

from laaso.btypes import EnumMixin
from laaso.node_types import NodeType

class DataDiskType(EnumMixin, enum.Enum):
    '''
    Enumeration of the data disk types we support
    '''
    NVME = 'nvme'
    ULTRA = 'ultra'
    PREMIUM = 'premium'
    STANDARD = 'standard'
    SAME_AS_OSS = 'same_as_oss' # used to say "make MDS match OSS"
DEFAULT_DISK_TYPE = DataDiskType.PREMIUM

# DATA_DISK_DESCS maps DataDiskType to ARM name/tier tuples.
# It is inserted in deploy_cluster.TemplateManager templates
# variables as dataDiskSKU. The contents are suitable as
# attributes for azure.mgmt.compute.models.DiskSku.
DATA_DISK_DESCS = {'standard' : {'name' : 'Standard_LRS',
                                 'tier' : 'Standard',
                                },
                   'premium' : {'name' : 'Premium_LRS',
                                'tier' : 'Premium',
                               },
                   'ultra' : {'name' : 'UltraSSD_LRS',
                              'tier' : 'Ultra',
                             },
                  }

_NODE_DDTYPES_ALLOWED = {
    NodeType.MDS.value: list(DataDiskType),
    NodeType.OSS.value: [DataDiskType.ULTRA, DataDiskType.PREMIUM, DataDiskType.NVME, DataDiskType.STANDARD],
    NodeType.AGTPRI.value: [DataDiskType.ULTRA, DataDiskType.PREMIUM],
    NodeType.AGTSTD.value: [],
    NodeType.LCLIENT.value: []
}

def ddtypes_allowed(ntype):
    '''
    return types of datadisks for a given node type
    '''
    if isinstance(ntype, enum.Enum):
        return _NODE_DDTYPES_ALLOWED[ntype.value]
    assert isinstance(ntype, str)
    return _NODE_DDTYPES_ALLOWED[ntype]

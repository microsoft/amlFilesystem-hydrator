#
# laaso/node_types.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Types, values, and ops related to node types
'''
import enum

from laaso.btypes import EnumMixin

class NodeType(EnumMixin, enum.Enum):
    '''
    Node types created by deploy_cluster.py.
    Other software components may identify these nodes
    by looking for these values in the VM tags as 'VMPurpose'.
    '''
    MDS = 'MDServer'
    OSS = 'OSServer'
    AGTPRI = 'AgentPrimary'
    AGTSTD = 'AgentStandard'
    LCLIENT = 'LustreClient'

class AnsibleNodeType(EnumMixin, enum.Enum):
    '''
    Ansible playbooks introduce an additional type MGS
    '''
    MGS = 'mgs'
    MDS = 'mds'
    OSS = 'oss'
    AGTPRI = 'agtpri'
    AGTSTD = 'agtstd'
    LCLIENT = 'client'
    SHP = 'shp'  # there is no NodeType equivalent of shp since deploy_cluster does not deploy it

_ANTYPE_NTYPE = {
    AnsibleNodeType.MGS.value: NodeType.MDS.value,
    AnsibleNodeType.MDS.value: NodeType.MDS.value,
    AnsibleNodeType.OSS.value: NodeType.OSS.value,
    AnsibleNodeType.AGTPRI.value: NodeType.AGTPRI.value,
    AnsibleNodeType.AGTSTD.value: NodeType.AGTSTD.value,
    AnsibleNodeType.LCLIENT.value: NodeType.LCLIENT.value,
}

_NTYPE_ANTYPE = {
    NodeType.MDS.value: AnsibleNodeType.MDS.value,
    NodeType.OSS.value: AnsibleNodeType.OSS.value,
    NodeType.AGTPRI.value: AnsibleNodeType.AGTPRI.value,
    NodeType.AGTSTD.value: AnsibleNodeType.AGTSTD.value,
    NodeType.LCLIENT.value: AnsibleNodeType.LCLIENT.value,
}

def ntype_ansntype(ntype):
    '''
    translate NodeType to AnsibleNodeType
    '''
    if isinstance(ntype, enum.Enum):
        return _NTYPE_ANTYPE[ntype.value]
    assert isinstance(ntype, str)
    return _NTYPE_ANTYPE[ntype]

def ansntype_ntype(ansntype):
    '''
    translater ansntype str to valid node type
    '''
    if isinstance(ansntype, enum.Enum):
        assert ansntype != AnsibleNodeType.SHP
        return _ANTYPE_NTYPE[ansntype.value]
    assert isinstance(ansntype, str)
    assert ansntype != AnsibleNodeType.SHP.value
    return _ANTYPE_NTYPE[ansntype]

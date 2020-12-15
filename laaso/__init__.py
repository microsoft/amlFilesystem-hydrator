#
# laaso/__init__.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Base laaso import
'''
from ._paths import paths
from ._scfg import scfg
from ._subscription_ids import SubscriptionIdCacher
from ._subscriptions import (subscription_info_get,
                             subscription_mapper,
                            )
from .onbox import ONBOX

__all__ = ['ONBOX',
           'paths',
           'scfg',
           'subscription_ids',
           'subscription_info_get',
           'subscription_mapper',
          ]

subscription_ids = SubscriptionIdCacher()

reset_hooks = [scfg.reset,
               subscription_mapper.reset,
              ]

def reset_caches(subscription_config_filename='', subscription_config_data=None):
    '''
    Discard cached content.
    '''
    paths.reset(subscription_config_filename=subscription_config_filename, subscription_config_data=subscription_config_data)
    for reset_hook in reset_hooks:
        reset_hook()

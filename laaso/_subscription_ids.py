#
# laaso/_subscription_ids.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Implement an object that can pull subscription_ids from the config
as logical names and return them as str-as-uuid.
This is done in a separate file to keep dependencies linear and simple.
'''
from ._scfg import scfg
from ._subscriptions import subscription_mapper

class SubscriptionIdCacher():
    '''
    Exports read-only attributes that map strings
    in the scfg to effective subscription IDs.
    Effective IDs are UUIDs-as-strings if the input
    is a UUID-as-string, or if the input is a string
    that is a known alias for a subscription.
    Otherwise, the effective ID is the input ID.
    This exists to do just-in-time evaluation to handle
    codepaths that alter the defaults, such as
    subscription_setup.py or unit tests.
    '''
    def __getattr__(self, name):
        return self.translate(getattr(scfg, name))

    @staticmethod
    def translate(name):
        '''
        Translate the given subscription name.
        This is a best-effort conversion to UUID-as-str.
        Otherwise, just returns name.
        '''
        return subscription_mapper.effective(name)

#
# laaso/base_defaults.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
'''
Default settings that are not loaded from any configuration.
To keep dependencies simple, use only Python built-in types here.
'''
# This is hardcoded in things like the keyvault VM extension that are outside LaaSO control.
# This is paired with azure_certificate_store in src/ansible/linux.facts.tasks.yaml.
AZURE_CERTIFICATE_STORE = '/var/lib/waagent/Microsoft.Azure.KeyVault.Store'

EXC_VALUE_DEFAULT = ValueError

LOCATION_DEFAULT_FALLBACK = 'eastus2'

# Prefix for item expansion
PF = '  '

TEST_STATUS_NOT_STARTED = 'not started'
TEST_STATUS_RUNNING = 'running'

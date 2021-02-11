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

LAASO_VENV_PATH = '/usr/laaso/venv' # onbox virtualenv; keep in sync with laaso_venv_path in basic.facts.tasks.yaml

LOCATION_DEFAULT_FALLBACK = 'eastus2'

# Prefix for item expansion
PF = '  '

# When generating RSA keypairs, use this default for the public exponent.
RSA_EXPONENT = 2**16 + 1

# Well-known name for the secret in the per-cluster KV
# that contains the SAS URL for the shepherd config.
SHEPHERD_CONFIG_SECRET_NAME = 'shepherd-config-url'

# SHEPHERD_SERVICE_NAME is the name of the systemd service that nannies shepherd.py
SHEPHERD_SERVICE_NAME = 'laaso-shepherd.service'

# Well-known names for the secrets in the per-cluster KV
# that represent the public and private keys that the shepherd
# uses for ssh access to the cluster nodes.
SHEPHERD_SSH_PRIVATE = 'shepherd-ssh-private'
SHEPHERD_SSH_PUBLIC = 'shepherd-ssh-public'

TEST_STATUS_NOT_STARTED = 'not started'
TEST_STATUS_RUNNING = 'running'

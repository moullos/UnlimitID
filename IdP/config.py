import os
from IdP import app
PSEUDONYM_ENTRY_LIFETIME = 300
# The keys a user exposes to a client
ANONYMOUS_KEYS = ['name', 'gender', 'zoneinfo', 'birthdate' ]
# Credential Lifetime. Default is two weeks
CREDENTIAL_LIFETIME = 1209600

CRYPTO_DIR = os.path.join(app.instance_path,'crypto')

# Credential Lifetime in days. Default is two weeks
CREDENTIAL_LIFETIME = 14
# Define the module directory
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Define the database
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR,'IdP.db')
SQLALCHEMY_TRACK_MODIFICATIONS = True
DATABASES_CONNECT_OPTIONS = {}

# Disable CSRF mitigation for testing. Enable in a real deployment
WTF_CSRF_ENABLED = False
WTF_CSRF_SESSION_KEY = 'secret'

# Secret Key for signing cookies. Stronger key in real deployment
SECRET_KEY = 'secret'

# Folder for storing cryptographic files
CRYPTO_DIR = 'crypto_idp'

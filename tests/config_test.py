# Credential Lifetime in days. Default is two weeks
CREDENTIAL_LIFETIME = 14
# Define the module directory
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Define the database
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR,'test.db')
SQLALCHEMY_TRACK_MODIFICATIONS = True
DATABASES_CONNECT_OPTIONS = {}

# Secret Key for signing cookies
SECRET_KEY = 'testing'

WTF_CSRF_ENABLED = False

# Folder for storing cryptographic files
CRYPTO_DIR = 'crypto_idp_test'

TESTING = True

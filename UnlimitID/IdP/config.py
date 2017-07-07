# Credential Lifetime in days. Default is two weeks
CREDENTIAL_LIFETIME = 14
# Define the module directory
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Define the database
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR,'IdP.db')
SQLALCHEMY_TRACK_MODIFICATIONS = True
DATABASES_CONNECT_OPTIONS = {}

# Enable CSRF mitigation
CSRF_ENABLED = True
CSRF_SESSION_KEY = 'secret'

# Secret Key for signing cookies
SECRET_KEY = 'secret'

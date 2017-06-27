from flask import Flask
from amacscreds.cred_user import CredentialUser

app = Flask(__name__)
from config import  CRYPTO_DIR, INFO_URL
cs = CredentialUser(CRYPTO_DIR, INFO_URL)
    
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
app.debug = True
app.secret_key = 'development'
import User.views

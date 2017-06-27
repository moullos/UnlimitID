from User import app
import os
CRYPTO_DIR = os.path.join(app.instance_path,'crypto')

CREDENTIAL_URL = 'http://127.0.0.1:5000/unlimitID/credential'
INFO_URL = 'http://127.0.0.1:5000/unlimitID/.well-known/info'

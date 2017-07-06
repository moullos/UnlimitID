from UnlimitID.User import create_app
CRYPTO_DIR = 'crypto_user'
CREDENTIAL_URL = 'http://127.0.0.1:5000/unlimitID/credential'
INFO_URL = 'http://127.0.0.1:5000/unlimitID/.well-known/info'
app = create_app(CRYPTO_DIR, CREDENTIAL_URL, INFO_URL)
app.run(host='localhost', port=3000)

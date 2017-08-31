from UnlimitID.User import create_app
CRYPTO_DIR = 'crypto_user'
idp_url = 'https://unlimitid.online'
if __name__ == '__main__':
    app = create_app(CRYPTO_DIR, idp_url=idp_url)
    app.secret_key = 'dev'
    app.run(host='localhost', port=3000, debug=True)

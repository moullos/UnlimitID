from flask import Flask
from .views import setUpViews


def create_app(crypto_dir, idp_url=None, params=None, ipub=None, user_cs=False):
    app = Flask(__name__)
    credential_url = idp_url + '/unlimitID/credential'
    info_url = idp_url + '/unlimitID/info'
    app, cs = setUpViews(app, crypto_dir, credential_url,
                         info_url=info_url, params=params, ipub=ipub)
    if user_cs is True:
        return app, cs
    else:
        return app

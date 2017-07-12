import os
from flask import Flask, session
from flask_oauthlib.provider import OAuth2Provider
from datetime import datetime, timedelta
from .models import Client, Pseudonym, Token, Grant, db
from .cred_server import CredentialServer
from .views import setUpViews


def load_current_pseudonym():
    if 'pseudonym_id' in session:
        id = session['pseudonym_id']
        pseudonym = Pseudonym.query.filter_by(id=id).first()
    else:
        pseudonym = None
    return pseudonym


def default_provider(app):
    oauth = OAuth2Provider(app)

    @oauth.clientgetter
    def get_client(client_id):
        return Client.query.filter_by(client_id=client_id).first()

    @oauth.grantgetter
    def get_grant(client_id, code):
        return Grant.query.filter_by(client_id=client_id, code=code).first()

    @oauth.tokengetter
    def get_token(access_token=None, refresh_token=None):
        if access_token:
            return Token.query.filter_by(access_token=access_token).first()
        if refresh_token:
            return Token.query.filter_by(refresh_token=refresh_token).first()
        return None

    @oauth.grantsetter
    def set_grant(client_id, code, request, *args, **kwargs):
        pseudonym = load_current_pseudonym()
        expires = datetime.utcnow() + timedelta(seconds=100)
        grant = Grant(
            client_id=client_id,
            code=code['code'],
            redirect_uri=request.redirect_uri,
            scope=' '.join(request.scopes),
            user_id=pseudonym.id,
            expires=expires
        )
        db.session.add(grant)
        db.session.commit()

    @oauth.tokensetter
    def set_token(token, request, *args, **kwargs):
        tok = Token(**token)
        tok.user_id = request.user.id
        tok.client_id = request.client.client_id
        db.session.add(tok)
        db.session.commit()

    return oauth


def create_app(crypto_dir, return_all=False):
    app = Flask(__name__)
    app.config.from_object('UnlimitID.IdP.config')
    oauth = default_provider(app)
    cs = CredentialServer(os.path.join(app.instance_path, 'IdP', crypto_dir))
    db.init_app(app)
    db.app = app
    db.create_all()
    setUpViews(app, oauth, db, cs)
    if return_all is False:
        return app
    else:
        return app, db, cs

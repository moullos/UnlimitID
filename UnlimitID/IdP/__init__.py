# Flask related imports
from flask import Flask, session
from flask_oauthlib.provider import OAuth2Provider
from datetime import datetime, timedelta
from .models import User, Client, Pseudonym, Token, Grant, db
from .amacscreds.cred_server import CredentialServer

import os
from petlib.pack import decode, encode 


app = Flask(__name__)
# pseudonym entry lifetime after a users registers it
# Crypto URL
from config import CRYPTO_DIR

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
            client_id = client_id,
            code=code['code'],
            redirect_uri = request.redirect_uri,
            scope=' '.join(request.scopes),
            user_id = pseudonym.id,
            expires = expires
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


def prepare_app(app):
    client1 = Client(
        name='dev', client_id='dev', client_secret='dev',
        redirect_uris=(
            'http://localhost:8000/authorized '
            'http://localhost/authorized'
        ),
        client_type = 'confidential',
        default_scope = ['name', 'gender']
    )
    user = User(
                name='admin', 
                given_name ='Panayiotis', 
                family_name ='Moullotos', 
                email='admin@gmail.com', 
                email_verified = True,
                gender = 'Male',
                zoneinfo = 'UK\London',
                birthdate = '1991-09-29',
                password='12345')
  
    try:
        db.session.add(client1)
        db.session.add(user)
        db.session.commit()
    except:
        db.session.rollback()
    return app


def create_server(app, oauth=None):
    if not oauth:
        oauth = default_provider(app)
    cs = CredentialServer(os.path.join( app.instance_path,'IdP', CRYPTO_DIR))
    return app, oauth, cs


app.config.from_object('UnlimitID.IdP.config')
db.init_app(app)
db.app = app
db.create_all()
app, oauth, credentialServer = create_server(app)
from .views import *

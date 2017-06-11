# coding: utf-8
from datetime import datetime, timedelta
from flask import g, render_template, request, jsonify, make_response
from flask_oauthlib.provider import OAuth2Provider
from flask_oauthlib.contrib.oauth2 import bind_sqlalchemy
from flask_oauthlib.contrib.oauth2 import bind_cache_grant
from flask import Flask
from models import db, Client, User, Token, Grant
from forms import SignupForm
from werkzeug import generate_password_hash, check_password_hash
 
def current_user():
    return g.user


def cache_provider(app):
    oauth = OAuth2Provider(app)

    bind_sqlalchemy(oauth, db.session, user=User,
                    token=Token, client=Client)

    app.config.update({'OAUTH2_CACHE_TYPE': 'simple'})
    bind_cache_grant(app, oauth, current_user)
    return oauth


def sqlalchemy_provider(app):
    oauth = OAuth2Provider(app)

    bind_sqlalchemy(oauth, db.session, user=User, token=Token,
                    client=Client, grant=Grant, current_user=current_user)

    return oauth


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
        expires = datetime.utcnow() + timedelta(seconds=100)
        grant = Grant(
            client_id=client_id,
            code=code['code'],
            redirect_uri=request.redirect_uri,
            scope=' '.join(request.scopes),
            user_id=g.user.id,
            expires=expires,
        )
        db.session.add(grant)
        db.session.commit()

    @oauth.tokensetter
    def set_token(token, request, *args, **kwargs):
        # In real project, a token is unique bound to user and client.
        # Which means, you don't need to create a token every time.
        tok = Token(**token)
        tok.user_id = request.user.id
        tok.client_id = request.client.client_id
        db.session.add(tok)
        db.session.commit()

    @oauth.usergetter
    def get_user(username, password, *args, **kwargs):
        # This is optional, if you don't need password credential
        # there is no need to implement this method
        return User.query.filter_by(username=username).first()

    return oauth


def prepare_app(app):
    db.init_app(app)
    db.app = app
    db.create_all()
    client1 = Client(
        name='dev', client_id='dev', client_secret='dev',
        _redirect_uris=(
            'http://localhost:8000/authorized '
            'http://localhost/authorized'
        ),
    )
    user = User(username='admin', firstname ='Panayiotis', lastname ='Moullotos', email='admin@gmail.com', password='12345')
    user2 = User(username='user', firstname ='user1', lastname='user1', email='user@gmail.com', password='123456')
  
    try:
        db.session.add(client1)
        db.session.add(client2)
        db.session.add(user)
        db.session.add(user2)
        db.session.commit()
    except:
        db.session.rollback()
    return app


def create_server(app, oauth=None):
    if not oauth:
        oauth = default_provider(app)

    app = prepare_app(app)

    @app.before_request
    def load_current_user():
        user = User.query.get(1)
        g.user = user
    
    
    @app.route('/client_signup')
    def client_signup(*args, **kwargs):
        """
        A page for clients to signup to the IdP
        """
        pass
    
    @app.route('/login')
    def login(*args, **kwargs):    
        """
        A page for the users to login
        Session management is necessary here -> flask-login might come in handy
        """
        pass

    @app.route('/signup')
    def register(*args, **kwargs):
        """
        A page with a form for users to signup to the IdP
        Get the data from the form and store it in the database
        """
        pass

    @app.route('/credential')
    def credential(*args, **kwargs):
        """
        A page for users to request credentials
        This page should be available to logged in users

        Info needed:
        SUB(Blinded) -> user's secret
        KEY -> attributes keys
        VALUE -> attributes values
        EXP -> Expiry
        Then BlindIssue() to return a credential (probably in JSON)
        """
        pass

    @app.route('/register')
    def register_pseudo(*args, **kwargs):
        """
        A page for a user to register a pseudonym for a particular RP
        Essentially a NIZK proof is received from the client (Show() Protocol).
        The IdP verifies the proof (ShowVerify()) and adds to its database the pseudonym along 
        with the RP it is issued for, the keys with the respective attributes and
        the exp time. Note that a user is not supposed to be logged in at this point
        as that violates unlinkability between the pseudonyms and the users.
        """
        pass  

    @app.route('/home')
    def home():
        return render_template('home.html')

    @app.route('/oauth/authorize', methods=['GET', 'POST'])
    @oauth.authorize_handler
    def authorize(*args, **kwargs):
        """
        The server's authorization endpoint

        For now this function implements a typical authentication for
        the user in order for the access code to be generated. 
        In UnlimitID, this function should ask the user to select 
        which attributes of his (locally blinded) credential to 
        reveal to the RP. After the IdP validates the credential,
        a database record with the revealed attributes is created.
        """
        # render a page for user to confirm the authorization
        if request.method == 'GET':
            return render_template('confirm.html')
        
        if request.method == 'HEAD':
            # if HEAD is supported properly, request parameters like
            # client_id should be validated the same way as for 'GET'
            response = make_response('', 200)
            response.headers['X-Client-ID'] = kwargs.get('client_id')
            return response
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user != None and check_password_hash(user.pwdhash, password):
            g.user = user
            return True
        else:
            return False 


    @app.route('/oauth/token', methods=['POST', 'GET'])
    @oauth.token_handler
    def access_token():
        """
        The server's access token endpoint. Returning {} makes the 
        server to just return the default access token. Anything else 
        you return gets added to the access token
        """
        return {}

    @app.route('/oauth/revoke', methods=['POST'])
    @oauth.revoke_handler
    def revoke_token():
        pass

    @app.route('/api/email')
    @oauth.require_oauth('email')
    def email_api():
        oauth = request.oauth
        return jsonify(email=oauth.user.email, username=oauth.user.username)

    @app.route('/api/client')
    @oauth.require_oauth()
    def client_api():
        oauth = request.oauth
        return jsonify(client=oauth.client.name)

    @app.route('/api/address/<city>')
    @oauth.require_oauth('address')
    def address_api(city):
        oauth = request.oauth
        return jsonify(address=city, username=oauth.user.username)

    @app.route('/api/method', methods=['GET', 'POST', 'PUT', 'DELETE'])
    @oauth.require_oauth()
    def method_api():
        return jsonify(method=request.method)

    @oauth.invalid_response
    def require_oauth_invalid(req):
        return jsonify(message=req.error_message), 401

    return app


if __name__ == '__main__':
    app = Flask(__name__)
    app.debug = True
    app.secret_key = 'development'
    app.config.update({
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///test.sqlite'
    })
    
    app = create_server(app)
    app.run()
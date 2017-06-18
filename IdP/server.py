# Flask related imports
from flask import g, render_template, request, Response, jsonify, make_response ,session
from flask_oauthlib.provider import OAuth2Provider
from flask_oauthlib.contrib.oauth2 import bind_sqlalchemy
from flask_oauthlib.contrib.oauth2 import bind_cache_grant
from flask import Flask, flash, redirect, url_for

# Timestamps
from datetime import datetime, timedelta
# Db objects
from models import db, Client, User, Token, Grant, Pseudonym
# Forms templates
from forms import SignupForm, LoginForm
# Hashes for storing passwords
from werkzeug import generate_password_hash, check_password_hash
# CredentialServer provides amacs credential functionality
from cred_server import CredentialServer
from petlib.pack import decode, encode 

# TODO: THESE SHOULD GO IN A CONFIG FILE
# pseudonym entry lifetime after a users registers it
PSEUDONYM_ENTRY_LIFETIME = 300
# The keys a user exposes to a client
ANONYMOUS_KEYS = ['name', 'gender', 'zoneinfo', 'birthdate' ]
# Credential Lifetime. Default is two weeks
CREDENTIAL_LIFETIME = 1209600

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
            expires=expires
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
        return User.query.filter_by(name=username).first()

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
        client_type = 'confidential',
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

    app = prepare_app(app)
    cs = CredentialServer()
    @app.before_request
    def load_current_user():
        if 'used_sub' in session:
            user = User.query.filter_by(id=session['user_id']).first()
        else: 
            user = {}
        g.user = user
    
    @app.route('/client_signup')
    def client_signup(*args, **kwargs):
        """
        A page for clients to signup to the IdP
        """
        return render_template('underConstruction.html')
    
    @app.route('/login', methods=['GET','POST'])
    def login(*args, **kwargs):    
        """
        A page for the users to login
        """
        form = LoginForm(request.form)
        try:
            if request.method == 'POST' and form.validate():
                email = form.email.data
                password = form.password.data
                user = User.query.filter_by(email=email).first()
                if user != None and check_password_hash(user.pwdhash, password):
                    session['logged_in'] = True
                    session['user_id'] = user.id
                    flash("Welcome {}".format(user.name))
                    return redirect(url_for('home'))
                else:
                    flash("Wrong Credential")
            return render_template('login.html', form=form)

        except Exception as e:
            print(str(e))
            
    @app.route('/signup', methods=['GET', 'POST'])
    def signup(*args, **kwargs):
        """
        A page with a form for users to signup to the IdP
        Get the data from the form and store it in the database
        """
        try:
            form = SignupForm(request.form)
            if request.method == 'POST' and form.validate():           
                name= form.username.data
                given_name = form.firstname.data
                family_name = form.lastname.data
                email = form.email.data
                gender = form.gender.data
                zoneinfo = form.zoneinfo.data
                birthdata = form.birthdate.data
                password = form.password.data
            
                user = User.query.filter_by(name=name).first()
                if user != None:
                    # Check if the username already exists
                    flash("Username already exists")
                    return render_template("signup.html", form=form)
                else:
                    user = User.query.filter_by(email=email).first()
                    if user != None:
                        flash("Email already exists")
                        return render_template("signup.html", form=form)
                    else:    
                        # Add the user to the db
                        user = User(
                            name = username, 
                            given_name = given_name, 
                            family_name = family_name,
                            email = email, 
                            gender = gender,
                            zoneinfo = zoneinfo,
                            birthdate = birthdate,
                            password = password
                            )
                        db.session.add(user)
                        db.session.commit()
                        flash("Thanks for signing up")
                        return redirect(url_for('login'))
            return render_template('signup.html', form=form)
        
        except Exception as e:
            return(str(e))
    
    @app.route('/unlimitID/.well-known/info', methods = ['POST'])
    def info():
        """
        A page that exposes the server's public parameters
        """
        return encode( cs.get_info() )

    @app.route('/unlimitID/credential', methods = ['POST'])
    def credential(*args, **kwargs):
        """
        A page for users to request credentials
        """
        try:
            email ,password, user_token  = decode(request.data)
        except Exception as e:
            print(str(e))
            return "Decode failed"
        #Checking the user's email and password
        user = User.query.filter_by(email=email).first()
        if user != None and user.check_password(password):
            # Setting values, keys and timeout for the issued credential
            values = user.get_values_by_keys(ANONYMOUS_KEYS)
            timeout_date = datetime.utcnow() + timedelta(seconds=CREDENTIAL_LIFETIME)
            timeout = timeout_date.isoformat()
            cred_issued = cs.issue_credential(user_token, ANONYMOUS_KEYS, values, timeout)
            return encode( (cred_issued, ANONYMOUS_KEYS, values, timeout) )
        else:
            return "Invalid Credentials"
                
           
    @app.route('/unlimitID/register', methods = ['POST'])
    def register_pseudo(*args, **kwargs):
        """
        A page for a user to register a pseudonym for a particular RP
        Essentially a NIZK proof is received from the client (Show() Protocol).
        The IdP verifies the proof (ShowVerify()) and adds to its database the pseudonym along 
        with the RP it is issued for, the keys with the respective attributes and
        the exp time. Note that a user is not supposed to be logged in at this point
        as that violates unlinkability between the pseudonyms and the users.
        """
        # TODO: Check if the pseudonym exists and update it. 
        try:
            creds, sig_o, sig_openID, Service_name, pseudonym, keys, values, timeout = decode(request.data)
        except Exception as e:
            print(str(e))
            return "Decode failed"
        
        # 1. Check if the credential has not expired
        if datetime.utcnow() < datetime.strptime( timeout, "%Y-%m-%dT%H:%M:%S.%f" ):
            # 2. Check if the credential is valid
            if cs.check_pseudonym_and_credential(creds, sig_o, sig_openID, Service_name, pseudonym, keys, values, timeout): 
                # 3. Check if the service name is valid
                client = Client.query.filter_by(name=Service_name).first()
                if client!= None:
                    # 4. Create a pseudonym entry containing the clients scope.
                    attr = dict(zip(keys,values))
                    scopes = client.default_scopes
                    k = []
                    v = []
                    for scope in scopes:
                        if scope not in attr:
                            return "Invalid Scope"
                        k.append(scope)
                        v.append(attr[scope])
                    new_entry = Pseudonym(
                                  pseudonym = pseudonym,
                                  client_id = client.client_id, 
                                  keys = k,
                                  values = v,
                                  timeout = timeout
                              )
                    db.session.add(new_entry)
                    db.session.commit()
                    return "Pseudonym for {} created successfully".format(Service_name)
                
                else:
                    return "Client {} not known".format(Service_name)
            else:
                return "Credential not valid"
        else:
            return "Credential Expired"


    @app.route('/')
    def index():
        return redirect(url_for('home'))

    @app.route('/home')
    def home():
        """
        Server's initial page
        """
        if g.user != {}:
            flash('You are currently logged in as {}'.format(g.user.username))
        #FIXME: Some hyperlinks in home.html would be appreciated
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
        client_id: id of the client
        scopes: a list of scope
        state: state parameter
        redirect_uri: redirect_uri parameter
        response_type: response_type parameter
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
        user = User.query.filter_by(name=username).first()
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
        return jsonify(email=oauth.user.email, username=oauth.user.name)

    @app.route('/api/client')
    @oauth.require_oauth()
    def client_api():
        oauth = request.oauth
        return jsonify(client=oauth.client.name)

    @app.route('/api/address/<city>')
    @oauth.require_oauth('address')
    def address_api(city):
        oauth = request.oauth
        return jsonify(address=city, username=oauth.user.name)

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


from .models import User, Client, Pseudonym, Credential
from .forms import SignupForm, AuthorizeForm, ClientForm
from flask import (redirect, url_for, render_template, flash,
                   session, jsonify, request)
from config import CREDENTIAL_LIFETIME
from petlib.pack import encode, decode
from datetime import date, datetime, timedelta

def setUpViews(app, oauth, db, cs):
    @app.route('/signup', methods=['GET', 'POST'])
    def signup(*args, **kwargs):
        """
        A page with a form for users to signup to the IdP
        Get the data from the form and store it in the database
        """
        form = SignupForm(request.form)
        if request.method == 'POST' and form.validate():
            name = form.username.data
            given_name = form.firstname.data
            family_name = form.lastname.data
            email = form.email.data
            gender = form.gender.data
            zoneinfo = form.zoneinfo.data
            birthdate = form.birthdate.data
            password = form.password.data
            user = User.query.filter_by(name=name).first()
            if user is not None:
                # Check if the username already exists
                flash("Username already exists")
                return render_template("signup.html", form=form)
            else:
                user = User.query.filter_by(email=email).first()
                if user is not None:
                    flash("Email already exists")
                    return render_template("signup.html", form=form)
                else:
                    # Add the user to the db
                    user = User(
                        name=name,
                        given_name=given_name,
                        family_name=family_name,
                        email=email,
                        gender=gender,
                        zoneinfo=zoneinfo,
                        birthdate=birthdate,
                        password=password
                    )
                    db.session.add(user)
                    db.session.commit()
                    flash("Thanks for signing up")
                    return redirect(url_for('home'))
        return render_template('signup.html', form=form)


    @app.route('/client_signup', methods=['GET', 'POST'])
    def client_signup():
        form = ClientForm(request.form)
        all_keys = ['name', 'given_name', 'family_name', 'email',
                    'email_verified', 'gender', 'zoneinfo', 'birthdate']
        form.scopes.choices = zip(all_keys, all_keys)
        if request.method == 'POST' and form.validate():
            name = form.name.data
            client_id = form.client_id.data
            client_secret = form.client_secret.data
            client_type = form.client_type.data
            redirect_uris = form.redirect_uris.data
            scope = form.scopes.data

            client = Client.query.filter_by(name=name).first()
            if client is not None:
                flash('Name already exists')
                return render_template('client.html', form=form)
            client = Client.query.filter_by(client_id=client_id).first()
            if client is not None:
                flash('ID already exists')
                return render_template('client.html', form=form)
            client = Client(
                name=name,
                client_id=client_id,
                client_secret=client_secret,
                client_type=client_type,
                redirect_uris=redirect_uris,
                default_scope=scope
            )
            db.session.add(client)
            db.session.commit()
            flash('Client Added Successfully')
            return redirect(url_for('home'))
        return render_template('client.html', form=form)


    @app.route('/unlimitID/.well-known/info', methods=['POST'])
    def info():
        """
        A page that exposes the server's public parameters
        """
        return encode(cs.get_info())


    @app.route('/unlimitID/credential', methods=['POST'])
    def credential(*args, **kwargs):
        """
        A page for users to request credentials
        """
        try:
            email, password, keys, user_token = decode(request.data)
        except Exception:
            return "Invalid Data in Request"
        # Checking the user's email and password
        user = User.query.filter_by(email=email.lower()).first()
        if user is not None and user.check_password(password):
            # Checking if a valid credential already exists
            cred = Credential.query.filter_by(user_id=user.id).first()
            if cred is not None:
                if (datetime.strptime(cred.timeout, "%Y-%m-%d").date() -
                        date.today() >= timedelta(days=2)):
                    # if the credential expires in more than 2 days return the
                    # existing credential
                    return encode((cred.credential_issued,
                                   cred.keys,
                                   cred.values,
                                   cred.timeout))
                else:
                    # if the credential expires in less that 2 days return a new
                    # credential
                    db.session.delete(cred)
            # Setting values, keys and timeout for the issued credential
            values = user.get_values_by_keys(keys)
            timeout_date = date.today() + timedelta(days=CREDENTIAL_LIFETIME)
            timeout = timeout_date.isoformat()
            cred_issued = cs.issue_credential(user_token, keys, values, timeout)
            cred = Credential(
                user_id=user.id,
                keys=keys,
                values=values,
                timeout=timeout,
                credential_issued=cred_issued)
            db.session.add(cred)
            db.session.commit()
            return encode((cred_issued, keys, values, timeout))
        else:
            return "Invalid email or password"


    @app.route('/')
    def index():
        return redirect(url_for('home'))


    @app.route('/home')
    def home():
        """
        Server's initial page
        """
        return render_template('home.html')


    @app.route('/oauth/authorize', methods=['GET', 'POST'])
    @oauth.authorize_handler
    def authorize(*args, **kwargs):
        """
        The server's authorization endpoint

        In UnlimitID, this function should ask the user to select
        which attributes of his (locally blinded) credential to
        reveal to the RP. After the IdP validates the credential,
        a database record with the revealed attributes is created.
        """
        form = AuthorizeForm()
        if request.method == 'GET':
            scopes = kwargs.get('scopes')
            flash('The client is requesting access to {}'.format(','.join(scopes)))
            return render_template('authorize.html', form=form)

        if request.method == 'POST':
            f = form.show.data
            (creds, sig_o, sig_openID, Service_name,
             uid, keys, values, timeout) = decode(f.read())
            f.close()
            # Checking whether the service exists
            client = Client.query.filter_by(name=Service_name).first()
            if client != None:
                # Checking if the credential is valid
                if cs.check_pseudonym_and_credential(creds, sig_o, sig_openID, Service_name, uid, keys, values, timeout):
                    # Checking if the credential expired
                    if datetime.strptime(timeout, '%Y-%m-%d').date() >= date.today():
                        attr = dict(zip(keys, values))
                        scopes = client.default_scopes
                        k = []
                        v = []
                        for scope in scopes:
                            if scope not in attr:
                                return "Attribute {} is not part of the credential provided".format(scope)
                            k.append(scope)
                            v.append(attr[scope])
                        pseudonym = Pseudonym.query.filter_by(
                            _uid=str(uid)).first()
                        if pseudonym != None:
                            db.session.delete(pseudonym)
                            db.session.commit()
                        new_entry = Pseudonym(
                            uid=uid,
                            client_id=client.client_id,
                            keys=k,
                            values=v,
                            timeout=timeout
                        )
                        db.session.add(new_entry)
                        db.session.commit()
                        session['pseudonym_id'] = new_entry.id
                        return True
                    else:
                        return "Credential expired"
                else:
                    return "Credential verification failed"
            else:
                return "Invalid Service Name"
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


    @app.route('/oauth/errors', methods=['GET'])
    def error():
        return jsonify(request.args)


    @app.route('/oauth/revoke', methods=['POST'])
    @oauth.revoke_handler
    def revoke_token():
        pass


    @app.route('/api/name')
    @oauth.require_oauth('name')
    def name_api():
        oauth = request.oauth
        attr = oauth.user.attr
        return jsonify(name=attr['name'])


    @app.route('/api/birthdate')
    @oauth.require_oauth('birthdate')
    def birthdate_api():
        oauth = request.oauth
        attr = oauth.user.attr
        return jsonify(birthdate=attr['birthdate'])


    @app.route('/api/zoneinfo')
    @oauth.require_oauth('zoneinfo')
    def zoneinfo_api():
        oauth = request.oauth
        attr = oauth.user.attr
        return jsonify(zoneinfo=attr['zoneinfo'])


    @app.route('/api/gender')
    @oauth.require_oauth('gender')
    def gender_api():
        oauth = request.oauth
        attr = oauth.user.attr
        return jsonify(gender=attr['gender'])


    @app.route('/api/client')
    @oauth.require_oauth()
    def client_api():
        oauth = request.oauth
        return jsonify(client=oauth.client.name)


    @oauth.invalid_response
    def require_oauth_invalid(req):
        return jsonify(message=req.error_message), 401

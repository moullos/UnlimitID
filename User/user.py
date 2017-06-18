from flask import Flask, redirect, render_template, url_for, session, request, jsonify, abort, flash
from flask_oauthlib.client import OAuth
from cred_user import CredentialUser
import requests
from petlib.pack import encode, decode
from forms import RegisterForm, CredentialForm


# TODO: Add this to a config file
credential_url = "http://127.0.0.1:5000/unlimitID/credential"
register_url =  "http://127.0.0.1:5000/unlimitID/register"

def create_user(app):  
    cs = CredentialUser()
    
    @app.route('/')
    def index():
        return redirect(url_for('home'))
    
    @app.route('/home')
    def home():
        return render_template('home.html')

    @app.route('/get_credential', methods= ['GET', 'POST'])
    def get_credential():
        """ 
            The page for the user to obtain credentials.
            The encrypted private attribute is given to the server
            along with the public attributes
        """
        form = CredentialForm(request.form)
        if request.method == 'POST' and form.validate():
            email = form.email.data
            password = form.password.data
            user_token = cs.get_encrypted_attribute()
            r = requests.post(
                    credential_url, 
                    data=encode( (email, password, user_token) )
                )
            cred_token  = decode(r.content)
            cs.issue_verify(cred_token, user_token)
            flash('Got a credential for you')
            return redirect(url_for('home'))
        return render_template('credential.html',form=form)

    @app.route('/register', methods = ['GET', 'POST'])    
    def register():
        """
            The page where the user registers a pseudonym for a specific
            service
        """
        try:
            cred, keys, values, timeout  = cs.get_credential_token()
        except Exception as e:
            print(str(e))
            flash('Could not load credential. Do you have one?')
            return render_template('home.html')
        form = RegisterForm(request.form)
        if request.method == 'POST' and form.validate():
            service_name = form.service_name.data
            show_proof = cs.show(cred, service_name, keys, values, timeout)
            r = requests.post(
                    register_url,
                    data = encode(show_proof)
                )
            flash(r.text)
            return redirect(url_for('home'))
        return render_template('register.html',form=form)

if __name__ == '__main__':
    import os
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    app = Flask(__name__)
    app.debug = True
    app.secret_key = 'development'
    create_user(app)
    app.run(host='localhost', port=3000)

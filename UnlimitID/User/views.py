import os
import requests
from flask import redirect, url_for, render_template, request, flash
from forms import RegisterForm, CredentialForm
from petlib.pack import encode, decode
from .amacscreds.cred_user import CredentialUser


def setUpViews(app, crypto_dir, credential_url=None, info_url=None, params=None, ipub=None):

    cs = CredentialUser(os.path.join(
        app.instance_path, 'User', crypto_dir), info_url, params , ipub)
    @app.route('/')
    def index():
        return redirect(url_for('home'))

    @app.route('/home')
    def home():
        return render_template('home.html')


    @app.route('/refresh')
    def refresh():
        return render_template('under_construction.html')


    @app.route('/get_credential', methods=['GET', 'POST'])
    def get_credential():
        """ The page for the user to obtain credentials.
            The encrypted private attribute is given to the server
            along with the public attributes
        """
        all_keys = ['name', 'given_name', 'family_name', 'email',
                    'email_verified', 'gender', 'zoneinfo', 'birthdate']
        form = CredentialForm(request.form)
        form.keys.choices = zip(all_keys, all_keys)
        if request.method == 'POST' and form.validate():
            email = form.email.data
            password = form.password.data
            keys = form.keys.data
            try:
                user_token = cs.get_encrypted_attribute()
                r = requests.post(
                    credential_url,
                    data=encode((email, password, keys, user_token))
                )
                cred_token = decode(r.content)
            except Exception:
                flash('Could not get credential')
                return redirect(url_for('home'))
            cs.issue_verify(cred_token, user_token)
            flash('Got a credential for you')
            return redirect(url_for('home'))
        return render_template('credential.html', form=form)

    @app.route('/show', methods=['GET', 'POST'])
    def show():
        try:
            cred, keys, values, timeout = cs.get_credential_token()
        except IOError:
            flash('Could not load credential. Do you have one?')
            return render_template('home.html')
        form = RegisterForm(request.form)
        if request.method == 'POST' and form.validate():
            service_name = form.service_name.data
            show_proof = cs.show(service_name, keys, values, timeout)
            filename = 'show_{}'.format(service_name)
            with open(filename, 'wb+') as f:
                f.write(encode(show_proof))
            flash("Created show for {} at {}".format(service_name, filename))
            return redirect(url_for('home'))
        return render_template('show.html', form=form)

    return app, cs


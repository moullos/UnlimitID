import unittest
import shutil
import os
from UnlimitID.IdP import create_app
from UnlimitID.IdP.models import User, Client, Credential
from UnlimitID.User.cred_user import CredentialUser
from petlib.pack import encode, decode
from cStringIO import StringIO
from datetime import date, timedelta
import tests.config_test as cfg
full_scope = ['name', 'given_name',
              'family_name', 'email', 'zoneinfo', 'gender']


class IdPTestCase(unittest.TestCase):

    def setUp(self):
        app, self.db, self.IdP_cs = create_app(
            cfg, return_all=True)
        self.app = app.test_client()
        self.testing_url = '/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost:8000/oauth/authorize&scope=name'
        self.user_cs = CredentialUser(
            'tests/user_crypto', params=self.IdP_cs.params, ipub=self.IdP_cs.ipub)
        self.db.create_all()

    def tearDown(self):
        self.db.session.remove()
        self.db.drop_all()
        os.unlink('tests/test.db')
        shutil.rmtree('tests/user_crypto')

    # /signup #
    def user_signup(self, name, email):
        return self.app.post('/signup', data=dict(
            username=name,
            firstname='test',
            lastname='test',
            email=email,
            gender='male',
            zoneinfo='test',
            birthdate='2001-01-01',
            password='test',
            confirm='test'
        ), follow_redirects=True)

    def add_user(self, name, email):
        user = User(
            name=name,
            given_name='given_name',
            family_name='family_name',
            email=email,
            email_verified=True,
            gender='Male',
            zoneinfo='UK\London',
            password='pass',
        )
        self.db.session.add(user)
        self.db.session.commit()

    def test_user_signup_get(self):
        result = self.app.get('/signup')
        self.assertEqual(result.status_code, 200)

    def test_user_signup(self):
        rv = self.user_signup('test', 'test@test.com')
        assert b'Thanks for signing up' in rv.data
        assert rv.status_code == 200

    def test_user_signup_same_name(self):
        self.add_user('admin', 'admin@test.com')
        rv = self.user_signup('admin', 'test@test.com')
        assert b'Username already exists' in rv.data
        assert rv.status_code == 200

    def test_user_signup_same_email(self):
        self.add_user('admin', 'admin@test.com')
        rv = self.user_signup('admin1', 'admin@test.com')
        assert b'Email already exists' in rv.data
        assert rv.status_code == 200

    # /client_signup #
    def client_signup(self, name, client_id):
        return self.app.post('/client_signup', data=dict(
            name=name,
            client_id=client_id,
            client_secret='test',
            confirm='test',
            client_type='confidential',
            redirect_uris='http://localhost:8000/oauth/authorize',
            scope=full_scope,
        ), follow_redirects=True)

    def add_client(self, name, client_id):
        client = Client(
            name=name,
            client_id=client_id,
            client_secret='pass',
            client_type='confidential',
            redirect_uris='http://localhost:8000/oauth/authorize',
            default_scope=full_scope
        )
        self.db.session.add(client)
        self.db.session.commit()

    def test_client_signup_get(self):
        result = self.app.get('/client_signup')
        self.assertEqual(result.status_code, 200)

    def test_client_signup(self):
        rv = self.client_signup('test', 'test')
        print rv.data
        assert b'Client Added Successfully' in rv.data
        assert rv.status_code == 200

    def test_client_signup_same_name(self):
        self.add_client('test', 'test')
        rv = self.client_signup('test', 'test1')
        assert b'Name already exists' in rv.data
        assert rv.status_code == 200

    def test_client_signup_same_id(self):
        self.add_client('test', 'test')
        rv = self.client_signup('test1', 'test')
        assert b'ID already exists' in rv.data
        assert rv.status_code == 200

    # /unlimitID/.well-known/info #
    def test_info_get(self):
        rv = self.app.get('/unlimitID/.well-known/info')
        assert rv.status_code == 405

    def test_info_post(self):
        rv = self.app.post('/unlimitID/.well-known/info')
        raised = False
        try:
            params, ipub = decode(rv.data)
        except:
            raised = True
        assert raised is False

    # /unlimitID/credential #
    def test_credential_get(self):
        rv = self.app.get('/unlimitID/credential')
        assert rv.status_code == 405

    def test_credential_post_invalid_request_data(self):
        rv = self.app.post('/unlimitID/credential', data='invalid_data')
        assert b'Invalid Data in Request' in rv.data
        assert rv.status_code == 200

    def test_credential_post_invalid_email(self):
        self.add_user('test', 'test@unlimitID.com')
        user_token = self.user_cs.get_encrypted_attribute()
        rv = self.app.post('/unlimitID/credential', data=encode((
            'invalid_email@unlimitID.com',
            'pass',
            full_scope,
            user_token
        ))
        )
        assert b'Invalid email or password' in rv.data

    def add_user_and_get_credential(self):
        self.add_user('test', 'test@unlimitID.com')
        user_token = self.user_cs.get_encrypted_attribute()
        rv = self.app.post('unlimitID/credential', data=encode((
            'test@unlimitID.com',
            'pass',
            full_scope,
            user_token
        ))
        )
        cred_token = decode(rv.data)
        self.user_cs.issue_verify(cred_token, user_token)

    def test_credential_post(self):
        self.add_user('test', 'test@unlimitID.com')
        user_token = self.user_cs.get_encrypted_attribute()
        rv = self.app.post('unlimitID/credential', data=encode((
            'test@unlimitID.com',
            'pass',
            full_scope,
            user_token
        ))
        )
        raised = False
        try:
            cred_token = decode(rv.data)
            self.user_cs.issue_verify(cred_token, user_token)
        except:
            raised = True
        assert raised is False

    def test_credential_post_already_existing_cred(self):
        # add a credential
        self.add_user('test', 'test@unlimitid.com')
        user_token = self.user_cs.get_encrypted_attribute()
        rv = self.app.post('unlimitID/credential', data=encode((
            'test@unlimitid.com',
            'pass',
            full_scope,
            user_token
        ))
        )
        cred_token1 = decode(rv.data)
        self.user_cs.issue_verify(cred_token1, user_token)
        rv = self.app.post('unlimitID/credential', data=encode((
            'test@unlimitid.com',
            'pass',
            full_scope,
            user_token ))
        )
        cred_token2 = decode(rv.data)
        self.user_cs.issue_verify(cred_token2, user_token)
        assert cred_token1 == cred_token2

    def test_credential_post_no_attr(self):
        self.add_user('test', 'test@unlimitid.com')
        user_token = self.user_cs.get_encrypted_attribute()
        rv = self.app.post('unlimitID/credential', data=encode((
            'test@unlimitid.com',
            'pass',
            [],
            user_token ))
        )
        assert b'Cannot issue credential with no attributes' in rv.data

    def test_credential_post_different_keys(self):
        cred_token = self.add_credential(timeout_date = date.today())
        user_token = self.user_cs.get_encrypted_attribute()
        rv = self.app.post('unlimitID/credential', data=encode((
            'test@unlimitid.com',
            'pass',
            ['name'],
            user_token ))
        )
        raised = False
        try:
            cred_token = decode(rv.data)
            self.user_cs.issue_verify(cred_token, user_token)
        except:
            raised = True
        assert raised is False

        


    def add_credential(self, timeout_date=None):
        if timeout_date is None:
            timeout_date = date.today() + timedelta(days=14)
        self.add_user('test', 'test@unlimitID.com')
        user_token = self.user_cs.get_user_token()
        user = User.query.filter_by(name='test').first()
        values = user.get_values_by_keys(full_scope)
        timeout = timeout_date.isoformat()
        cred_issued = self.IdP_cs.issue_credential(
            user_token, full_scope, values, timeout)
        cred_token = (cred_issued, full_scope, values, timeout)
        self.user_cs.issue_verify(cred_token, user_token)
        (_, EGenc, _) = user_token
        cred = Credential(
            user_id=user.id,
            keys=full_scope,
            values=values,
            timeout=timeout,
            credential_issued=cred_issued)
        self.db.session.add(cred)
        self.db.session.commit()
        return cred_token

    def test_credential_post_refresh_period_cred(self):
        # add a credential
        timeout_date = date.today() - timedelta(days=13)
        cred_token_old = self.add_credential(timeout_date)
        user_token = self.user_cs.get_user_token()
        rv = self.app.post('unlimitID/credential', data=encode((
            'test@unlimitID.com',
            'pass',
            full_scope,
            user_token
        ))
        )
        cred_token_new = decode(rv.data)
        self.user_cs.issue_verify(cred_token_new, user_token)
        assert cred_token_new != cred_token_old

    # / #
    def test_index_status_code(self):
        result = self.app.get('/')
        self.assertEqual(result.status_code, 302)

    # /home #
    def test_home_status_code(self):
        result = self.app.get('/home')
        self.assertEqual(result.status_code, 200)

    # /oauth/authorize #
    def prepare_authorize(self, proof_service_name, client_service_name, client_id):
        self.add_user_and_get_credential()
        cred, keys, values, timeout = self.user_cs.get_credential_token()
        self.add_client(client_service_name, client_id)
        return self.user_cs.show(proof_service_name, keys, values, timeout)

    def test_authorize_get(self):
        self.prepare_authorize(
            'Service_name', 'Service_name', 'test')
        rv = self.app.get(self.testing_url)
        assert b'The client is requesting access to name' in rv.data
        self.assertEqual(rv.status_code, 200)

    def test_authorize_post_invalid_service_name(self):
        show_proof = self.prepare_authorize(
            'Invalid_service', 'Service_name', 'test')
        rv = self.app.post(self.testing_url, data={
                           'show': (StringIO(encode(show_proof)), 'show')})
        assert b'Invalid Service Name' in rv.data

    def test_authorize_post_invalid_uid(self):
        (_, _, _, o) = self.IdP_cs.params
        show_proof = self.prepare_authorize(
            'Service_name', 'Service_name', 'test')
        creds, sig_o, sig_openID, Service_name, uid, keys, values, timeout = show_proof
        dummy_uid = o.random()
        dummy_show_proof = creds, sig_o, sig_openID, Service_name, dummy_uid, keys, values, timeout
        rv = self.app.post(self.testing_url, data={'show': (
            StringIO(encode(dummy_show_proof)), 'show')})
        assert b'EC+exception' in rv.data

    def test_authorize_post_invalid_keys(self):
        show_proof = self.prepare_authorize(
            'Service_name', 'Service_name', 'test')
        creds, sig_o, sig_openID, Service_name, uid, keys, values, timeout = show_proof
        dummy_keys = ['dummy', 'keys', 'dummy', 'keys']
        dummy_show_proof = creds, sig_o, sig_openID, Service_name, uid, dummy_keys, values, timeout
        rv = self.app.post(self.testing_url, data={'show': (
            StringIO(encode(dummy_show_proof)), 'show')})
        assert b'Credential verification failed' in rv.data

    def test_authorize_post_invalid_values(self):
        show_proof = self.prepare_authorize(
            'Service_name', 'Service_name', 'test')
        creds, sig_o, sig_openID, service_name, uid, keys, values, timeout = show_proof
        dummy_values = ['dummy', 'values', 'dummy', 'values']
        dummy_show_proof = creds, sig_o, sig_openID, service_name, uid, keys, dummy_values, timeout
        rv = self.app.post(self.testing_url, data={'show': (
            StringIO(encode(dummy_show_proof)), 'show')})
        assert b'Credential verification failed' in rv.data

    def test_authorize_post_invalid_timeout(self):
        show_proof = self.prepare_authorize(
            'Service_name', 'Service_name', 'test')
        creds, sig_o, sig_openID, service_name, uid, keys, values, timeout = show_proof
        dummy_timeout = date.today().isoformat()
        dummy_show_proof = creds, sig_o, sig_openID, service_name, uid, keys, values, dummy_timeout
        rv = self.app.post(self.testing_url, data={'show': (
            StringIO(encode(dummy_show_proof)), 'show')})
        assert b'Credential verification failed' in rv.data

    def get_expired_credential(self, proof_service_name, client_service_name, client_id):
        self.add_user('test', 'test@unlimitID.com')
        user_token = self.user_cs.get_encrypted_attribute()
        email = 'test@unlimitID.com'
        password = 'pass'
        user = User.query.filter_by(name='test').first()
        values = user.get_values_by_keys(full_scope)
        timeout_date = date.today() - timedelta(days=14)
        timeout = timeout_date.isoformat()
        cred_issued = self.IdP_cs.issue_credential(
            user_token, full_scope, values, timeout)
        cred_token = (cred_issued, full_scope, values, timeout)
        self.user_cs.issue_verify(cred_token, user_token)
        cred, keys, values, timeout = self.user_cs.get_credential_token()
        self.add_client(client_service_name, client_id)
        return self.user_cs.show(proof_service_name, keys, values, timeout)

    def test_authorized_post_expired_credential(self):
        show_proof = self.get_expired_credential(
            'Service_name', 'Service_name', 'test')
        rv = self.app.post(self.testing_url, data={
                           'show': (StringIO(encode(show_proof)), 'show')})
        assert b'Credential expired' in rv.data

    def test_authorized_post_happy_path(self):
        show_proof = self.prepare_authorize(
            'Service_name', 'Service_name', 'test')
        rv = self.app.post(self.testing_url, data={
                           'show': (StringIO(encode(show_proof)), 'show')},
                           follow_redirects = False
                           )
        print rv.data
        assert rv.status_code == 302
        assert b'http://localhost:8000/oauth/authorize?code=' in rv.headers['Location']
        

if __name__ == '__main__':
    unittest.main()

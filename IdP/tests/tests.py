import os
import unittest
from IdP import app, db, credentialserver as IdP_cs
from IdP.models import User, Client
from IdP.amacscreds.cred_user import CredentialUser
from petlib.pack import encode, decode
from cStringIO import StringIO
from datetime import datetime

class IdPTestCase(unittest.TestCase):

    def setUp(self):
        app.secret_key = 'testing'
        app.testing = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
        self.app = app.test_client()
        self.IdP_cs = IdP_cs
        self.user_cs = CredentialUser('user_crypto', params = IdP_cs.params, ipub = IdP_cs.ipub)
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
    
    
    ## /signup ##
    def user_signup(self, name, email):
        return self.app.post('/signup',data=dict(
            username=name,
            firstname = 'test',
            lastname = 'test',
            email = email,
            gender = 'male',
            zoneinfo = 'test',
            birthdate = '2001-01-01',
            password = 'test',
            confirm = 'test'
            ),follow_redirects=True)

    def add_user(self, name, email):
        user = User(
                name = name, 
                given_name ='given_name', 
                family_name ='family_name', 
                email= email, 
                email_verified = True,
                gender = 'Male',
                zoneinfo = 'UK\London',
                birthdate = '2000-10-10',
                password='pass'
              )
        db.session.add(user)
        db.session.commit()

    def test_user_signup_get(self):
        result = self.app.get('/signup')
        self.assertEqual(result.status_code, 200) 

    def test_user_signup(self):
        rv = self.user_signup('test','test@test.com')
        assert b'Thanks for signing up' in rv.data
        assert rv.status_code == 200

    def test_user_signup_same_name(self):
        self.add_user('admin','admin@test.com')
        rv = self.user_signup('admin','test@test.com')
        assert b'Username already exists' in rv.data 
        assert rv.status_code == 200

    def test_user_signup_same_email(self):
        self.add_user('admin','admin@test.com')
        rv = self.user_signup('admin1','admin@test.com')
        assert b'Email already exists' in rv.data 
        assert rv.status_code == 200
    
    ## /client_signup ##
    def client_signup(self, name, client_id):
        return self.app.post('/client_signup',data=dict(
            name = name,
            client_id = client_id,
            client_secret = 'test',
            confirm = 'test',
            client_type = 'confidential',
            redirect_uris= 'http://localhost:8000/oauth/authorize',
            scope = ['test'],
            ),follow_redirects=True)

    def add_client(self, name, client_id):
        client = Client(
                name = name, 
                client_id = client_id,
                client_secret = 'pass',
                client_type = 'confidential',
                redirect_uris= 'http://localhost:8000/oauth/authorize',
                default_scope = ['name']
              )
        db.session.add(client)
        db.session.commit()
    
    def test_client_signup_get(self):
        result = self.app.get('/client_signup')
        self.assertEqual(result.status_code, 200) 

    def test_client_signup(self):
        rv = self.client_signup('test','test')
        assert b'Client Added Successfully' in rv.data
        assert rv.status_code == 200

        
    def test_client_signup_same_name(self):
        self.add_client('test','test')
        rv = self.client_signup('test','test1')
        assert b'Name already exists' in rv.data
        assert rv.status_code == 200

    def test_client_signup_same_id(self):
        self.add_client('test','test')
        rv = self.client_signup('test1','test')
        assert b'ID already exists' in rv.data
        assert rv.status_code == 200

    ## /unlimitID/.well-known/info ##
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
        assert raised == False
        
    ## /unlimitID/credential ##
    def test_credential_get(self):
        rv = self.app.get('/unlimitID/credential')
        assert rv.status_code == 405
    
    def test_credential_post_invalid_request_data(self):
        rv = self.app.post('/unlimitID/credential', data = 'invalid_data')
        assert b'Invalid Data in Request' in rv.data
        assert rv.status_code == 200
    
    def test_credential_post_invalid_email(self):
        self.add_user('test','test@unlimitID.com')
        user_token = self.user_cs.get_encrypted_attribute()
        rv = self.app.post('/unlimitID/credential', data = encode ((
                                                            'invalid_email@unlimitID.com', 
                                                            'pass',
                                                             user_token
                                                        ))
                                                    )
        assert b'Invalid email or password' in rv.data

    def test_credential_post_invalid_email(self):
        self.add_user('test','test@unlimitID.com')
        user_token = self.user_cs.get_encrypted_attribute()
        rv = self.app.post('/unlimitID/credential', data = encode ((
                                                            'test@unlimitID', 
                                                            'wrongpassword',
                                                             user_token
                                                        ))
                                                    )
        assert b'Invalid email or password' in rv.data

    def add_user_and_get_credential(self):
        self.add_user('test','test@unlimitID.com')
        user_token = self.user_cs.get_encrypted_attribute()
        rv = self.app.post('unlimitID/credential', data = encode ((
                                                            'test@unlimitID.com',
                                                            'pass',
                                                            user_token
                                                        ))
                                                    )
        cred_token = decode(rv.data)
        self.user_cs.issue_verify( cred_token, user_token) 

    def test_credential_post(self):
        self.add_user('test','test@unlimitID.com')
        user_token = self.user_cs.get_encrypted_attribute()
        rv = self.app.post('unlimitID/credential', data = encode ((
                                                            'test@unlimitID.com',
                                                            'pass',
                                                            user_token
                                                        ))
                                                    )
        raised = False
        try:
            cred_token = decode(rv.data)
            self.user_cs.issue_verify(cred_token, user_token)
        except:
            raised = True
        assert raised == False
        
   
    ## / ##
    def test_index_status_code(self):
        result = self.app.get('/')
        self.assertEqual(result.status_code, 302) 

    ## /home ##
    def test_home_status_code(self):
        result = self.app.get('/home')
        self.assertEqual(result.status_code, 200 )

    ## /oauth/authorize ##
    def prepare_authorize(self, proof_service_name, client_service_name, client_id ):
        self.add_user_and_get_credential()
        cred, keys, values, timeout  = self.user_cs.get_credential_token()
        self.add_client(client_service_name, client_id)
        return self.user_cs.show(proof_service_name, keys, values, timeout)
   
    def test_authorize_post_invalid_service_name(self):
        show_proof = self.prepare_authorize('Invalid_service','Service_name', 'test')
        rv = self.app.post('/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost:8000/oauth/authorize&scope=name',data = {'show' : (StringIO(encode(show_proof)), 'show')})
        assert b'Invalid Service Name' in rv.data
  
    def test_authorize_post_invalid_uid(self):
        (_, _, _, o) = self.IdP_cs.params
        show_proof = self.prepare_authorize('Service_name','Service_name', 'test')
        creds, sig_o, sig_openID, Service_name, uid, keys, values, timeout = show_proof
        dummy_uid = o.random()
        dummy_show_proof = creds, sig_o, sig_openID, Service_name, dummy_uid , keys, values, timeout 
        rv = self.app.post('/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost:8000/oauth/authorize&scope=name',data = {'show' : (StringIO(encode(dummy_show_proof)), 'show')})
        assert b'EC+exception' in rv.data

    def test_authorize_post_invalid_keys(self):
        show_proof = self.prepare_authorize('Service_name','Service_name', 'test')
        creds, sig_o, sig_openID, Service_name, uid, keys, values, timeout = show_proof
        dummy_keys = ['dummy', 'keys', 'dummy', 'keys']
        dummy_show_proof = creds, sig_o, sig_openID, Service_name, uid , dummy_keys, values, timeout 
        rv = self.app.post('/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost:8000/oauth/authorize&scope=name',data = {'show' : (StringIO(encode(dummy_show_proof)), 'show')})
        assert b'Credential verification failed' in rv.data
    
    def test_authorize_post_invalid_values(self):
        show_proof = self.prepare_authorize('Service_name','Service_name', 'test')
        creds, sig_o, sig_openID, service_name, uid, keys, values, timeout = show_proof
        dummy_values = ['dummy', 'values', 'dummy', 'values']
        dummy_show_proof = creds, sig_o, sig_openID, service_name, uid , keys, dummy_values, timeout 
        rv = self.app.post('/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost:8000/oauth/authorize&scope=name',data = {'show' : (StringIO(encode(dummy_show_proof)), 'show')})
        assert b'Credential verification failed' in rv.data

    def test_authorize_post_invalid_timeout(self):
        show_proof = self.prepare_authorize('Service_name','Service_name', 'test')
        creds, sig_o, sig_openID, service_name, uid, keys, values, timeout = show_proof
        dummy_timeout = datetime.utcnow().isoformat()
        dummy_show_proof = creds, sig_o, sig_openID, service_name, uid , keys, values, dummy_timeout 
        rv = self.app.post('/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost:8000/oauth/authorize&scope=name',data = {'show' : (StringIO(encode(dummy_show_proof)), 'show')})
        assert b'Credential verification failed' in rv.data


if __name__ == '__main__':
    unittest.main()

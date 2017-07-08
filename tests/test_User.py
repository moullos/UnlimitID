import os
import unittest
import shutil
from UnlimitID.User import create_app
from UnlimitID.IdP.amacscreds.cred_server import CredentialServer
from datetime import date
from petlib.pack import encode, decode


class UserTestCase(unittest.TestCase):

    def setUp(self):
        CRYPTO_DIR = 'tests/user_crypto'
        CREDENTIAL_URL = 'test'
        self.IdP_cs = CredentialServer('tests/idp_crypto')
        app, cs = create_app(CRYPTO_DIR, CREDENTIAL_URL,
                             params=self.IdP_cs.params, ipub=self.IdP_cs.ipub, user_cs=True)
        self.temp_dir = app.instance_path
        app.secret_key = 'testing'
        app.testing = True
        self.User_cs = cs
        self.app = app.test_client()

    def tearDown(self):
        shutil.rmtree(os.path.join(self.temp_dir, 'User', 'tests/user_crypto'))
        shutil.rmtree('tests/idp_crypto')

    ## helpers ##
    def create_credential(self):
        user_token = self.User_cs.get_encrypted_attribute()
        keys = ['name']
        values = ['test']
        timeout_date = date.today()
        timeout = timeout_date.isoformat()
        cred_token = self.IdP_cs.issue_credential(
            user_token, keys, values, timeout)
        self.User_cs.issue_verify(
            (cred_token, keys, values, timeout), user_token)

    def test_index_get(self):
        rv = self.app.get('/')
        self.assertEqual(rv.status_code, 302)

    def test_home_get(self):
        rv = self.app.get('/home')
        self.assertEqual(rv.status_code, 200)

    def test_credential_get(self):
        rv = self.app.get('/get_credential')
        self.assertEqual(rv.status_code, 200)

    def test_credential_post(self):
        rv = self.app.post('/get_credential', data=dict(
            email='test@UnlimitID.com',
            password='12345',
            keys=['name']
        ),
            follow_redirects=True
        )
        self.assertEqual(rv.status_code, 200)
        print rv.data
        assert b'Could not get credential' in rv.data

    def test_show_get_no_credential(self):
        rv = self.app.get('/show')
        print rv.data
        assert b'Could not load credential. Do you have one?' in rv.data

    def test_show_get_with_credential(self):
        self.create_credential()
        rv = self.app.get('/show')
        assert rv.status_code == 200

    def test_show_post_with_credential(self):
        self.create_credential()
        rv = self.app.post('/show',
                           data=dict(service_name='test'),
                           follow_redirects=True)
        print rv.data
        assert b'Created show for test at show_test' in rv.data
        assert rv.status_code == 200
        os.unlink('show_test')


if __name__ == '__main__':
    unittest.main()
# General imports
import os
import random
import string
from datetime import date, datetime
# Crypto imports
from petlib.pack import encode, decode
from petlib.bn import Bn
from UnlimitID.User.amacscreds.amacscreds import (cred_UserKeyge,
                                                  cred_secret_issue_user,
                                                  cred_secret_issue_user_decrypt, cred_show)
from UnlimitID.User.amacscreds.genzkp import *
from hashlib import sha512


class CredentialUser():
    """
    A class to take care of all the needs the client has for credentials
    """

    def __init__(self, crypto_dir, info_url=None, params=None, ipub=None):
        """
        Loads long term values from files.
        If the server's public values are missing an Exception is raised.
        If any of the client's public values are missing, they are created.
        """

        self.crypto_dir = crypto_dir
        if not os.path.exists(crypto_dir):
            os.makedirs(crypto_dir)
        self.delete_expired_credentials()
        if params is not None and ipub is not None:
            self.params = params
            self.ipub = ipub
        else:
            import requests
            if info_url is not None:
                try:
                    r = requests.post(info_url)
                    if r.status_code == 200:
                        self.params, self.ipub = decode(r.content)
                    else:
                        raise Exception("Could not access {}".format(info_url))
                except:
                    raise Exception("Could not access {}".format(info_url))

        try:
            with open(self.crypto_dir + '/keypair', 'rb') as f:
                self.keypair = decode(f.read())
        except IOError:
            self.keypair = cred_UserKeyge(self.params)
            with open(self.crypto_dir + '/keypair', 'wb+') as f:
                f.write(encode(self.keypair))
        try:
            with open(self.crypto_dir + '/private_attr', 'rb') as f:
                self.private_attr = decode(f.read())
        except IOError:
            (_, _, _, o) = self.params
            self.private_attr = [o.random()]
            with open(self.crypto_dir + '/private_attr', 'wb+') as f:
                f.write(encode(self.private_attr))
        try:
            with open(self.crypto_dir + '/user_token', 'rb') as f:
                self.user_token = decode(f.read())
        except IOError:
            self.user_token = cred_secret_issue_user(
                self.params, self.keypair,  self.private_attr)
            self.save_user_token(self.user_token)

    def attr_to_bn(self, k, v, t):
        " Transforms attr to Bn"
        (_, _, _, o) = self.params
        key = Bn.from_binary(sha512("".join(k)).digest()) % o
        value = Bn.from_binary(sha512("".join(v)).digest()) % o
        timeout = Bn.from_binary(sha512(str(t)).digest()) % o
        return key, value, timeout

    def get_encrypted_attribute(self):
        return self.user_token

    def save_user_token(self, user_token):
        with open(self.crypto_dir + '/user_token', 'wb+') as f:
            f.write(encode(self.user_token))

    def get_user_token(self):
        return self.user_token

    def save_credential_token_and_mac(self, cred, mac):
        id = self.random_id()
        with open(self.crypto_dir + '/cred_{}'.format(id), 'wb+') as f:
            f.write(encode(cred))
        with open(self.crypto_dir + '/mac_{}'.format(id), 'wb+') as f:
            f.write(encode(mac))

    def get_credential_token_and_mac(self, id):
        with open(self.crypto_dir + '/cred_{}'.format(id), 'rb') as f:
            cred = decode(f.read())
        with open(self.crypto_dir + '/mac_{}'.format(id), 'rb') as f:
            mac = decode(f.read())
        return (cred, mac)

    def list_credential_tokens(self):
        creds = []
        for filename in os.listdir(self.crypto_dir):
            if filename.startswith("cred_"):
                cred_id = filename.split('_')[1]
                with open(self.crypto_dir + '/' + filename, 'rb') as f:
                    cred = decode(f.read())
                    _, k, v, t = cred
                    attr = ['{}={}'.format(key, value)
                            for key, value in zip(k, v)]
                    creds.append((cred_id,
                                  'Attributes: {}\n Timeout: {}'.format(', '.join(attr), t)))
        return creds

    def delete_expired_credentials(self):
        for filename in os.listdir(self.crypto_dir):
            if filename.startswith("cred_"):
                with open(self.crypto_dir +'/'+ filename, 'rb') as f:
                    cred = decode(f.read())
                    _, _, _, timeout = cred
                    if datetime.strptime(timeout, '%Y-%m-%d').date() < date.today():
                        os.unlink(self.crypto_dir +'/'+ filename)
                        cred_id = filename.split('_')[1]
                        os.unlink(self.crypto_dir + '/mac_'+cred_id)
        return

    def delete_all_credentials(self):
        for filename in os.listdir(self.crypto_dir):
            if filename.startswith("cred_") or filename.startswith("mac_"):
                os.unlink(self.crypto_dir +'/'+ filename)
        return





    def get_mac(self, id):
        try:
            with open(self.crypto_dir + '/mac_{}'.format(id), 'rb') as f:
                return(decode(f.read()))
        except IOError:
            raise exception('Opening the file failed')

    def issue_verify(self, cred_token, user_token):
        cred_issued, k, v, t = cred_token
        (u, EncE, sig_s) = cred_issued
        (_, EGenc, _) = user_token
        keys, values, timeout = self.attr_to_bn(k, v, t)
        public_attr = [keys, values, timeout]
        mac = cred_secret_issue_user_decrypt(
            self.params, self.keypair, u, EncE,
            self.ipub, public_attr, EGenc, sig_s)
        self.save_credential_token_and_mac(cred_token, mac)

    def show(self, Service_name, cred_id):
        """
          TO BE USED FROM REGISTERING
          Returns the ZK proofs and all the data you have to sent to the server
          to validate your previously issued credential
        """
        (G, g, h, o) = self.params
        (cred, mac) = self.get_credential_token_and_mac(cred_id)
        (_, EGenc, _) = self.get_user_token()
        (u, EncE, sig_s), k, v, t = cred
        key, value, timeout = self.attr_to_bn(k, v, t)
        public_attr = [key, value, timeout]
        (creds, sig_o, zis) = cred_show(self.params, self.ipub, mac,
                                        sig_s, public_attr + self.private_attr,
                                        export_zi=True)

        [LT_user_ID] = self.private_attr

        # The credential contains a number of commitments to the attributes
        (u, Cmis, Cup) = creds

        assert len(Cmis) == 4
        assert Cmis[0] == key * u + zis[0] * h
        assert Cmis[1] == value * u + zis[1] * h
        assert Cmis[2] == timeout * u + zis[2] * h

        assert Cmis[3] == LT_user_ID * u + zis[3] * h

        # Derive a service specific User ID
        Gid = G.hash_to_point(Service_name)
        Uid = LT_user_ID * Gid

        # Define the statements to be proved
        zk = define_proof(G)

        # Define the proof environemnt
        env = ZKEnv(zk)
        env.u, env.h = u, h

        env.Cm0p = Cmis[0] - (key * u)
        env.Cm1p = Cmis[1] - (value * u)
        env.Cm2p = Cmis[2] - (timeout * u)

        env.Cm3 = Cmis[3]

        env.Uid, env.Gid = Uid, Gid
        env.LT_ID = LT_user_ID
        env.z0, env.z1, env.z2, env.z3 = zis[0], zis[1], zis[2], zis[3]

        sig_openID = zk.build_proof(env.get())

        return (creds, sig_o, sig_openID, Service_name, Uid, k, v, t)


    def random_id(self):
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(10))


def define_proof(G):
    zk = ZKProof(G)
    u, h = zk.get(ConstGen, ["u", "h"])
    LT_ID, z0, z1, z2, z3 = zk.get(Sec, ["LT_ID", "z0", "z1", "z2", "z3"])
    Cm0p = zk.get(ConstGen, "Cm0p")
    Cm1p = zk.get(ConstGen, "Cm1p")
    Cm2p = zk.get(ConstGen, "Cm2p")

    Cm3 = zk.get(ConstGen, "Cm3")
    Uid = zk.get(ConstGen, "Uid")
    Gid = zk.get(ConstGen, "Gid")

    zk.add_proof(Cm0p, z0 * h)
    zk.add_proof(Cm1p, z1 * h)
    zk.add_proof(Cm2p, z2 * h)

    zk.add_proof(Cm3, LT_ID*u + z3 * h)
    zk.add_proof(Uid, LT_ID * Gid)

    return zk

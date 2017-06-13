# General imports
import sys
sys.path += ["amacscreds"]

# Crypto imports
from petlib.pack import encode, decode
from amacscreds import cred_setup, cred_CredKeyge, cred_UserKeyge, cred_secret_issue_user, cred_secret_issue, cred_secret_issue_user_decrypt, cred_show, cred_show_check, cred_secret_issue_user_check
from genzkp import *


class CredentialClient():
    """
    A class to take care of all the needs the client has for credentials
    """
    def __init__(self):
        """
        Loads long term values from files.
        If the server's public values are missing an Exception is raised.
        If any of the client's public values are missing, they are created.
        """ 
        import requests
        r = requests.post("http://127.0.0.1:5000/unlimitID/.well-known/info")
        if r.status_code == 200:
            self.params, self.ipub = decode(r.content)
        elif r.status_code == 404:
            raise Exception("Page not found")

        try:
            with open('keypair','rb') as f:
                self.keypair = decode( f.read() )
        except IOError:
            self.keypair = cred_UserKeyge(self.params)
            with open('keypair','wb+') as f:
                f.write( encode(self.keypair))
        try:
            with open('private_attr','rb') as f:
                self.private_attr = decode( f.read() )
        except IOError: 
            (_, _, _, o) = self.params
            self.private_attr = o.random()
            with open('private_attr','wb+') as f:
                f.write( encode(self.private_attr))
        try:
            with open('public_attr','rb') as f:
                self.keypair = decode( f.read() )
        except IOError:
            self.keypair = cred_UserKeyge(self.params)
            with open('keypair','wb+') as f:
                f.write( encode(self.keypair))
        # Just for testing
        self.public_attr = [100, 200, 300]
   
    def get_encrypted_attribute(self):
        """ 
            TO BE USED FROM CREDENTIAL GETTER
            public_attr = [key, value, timeout]
            (pub, EGenc, sig_u) = user_token
        """
        user_token =  cred_secret_issue_user(self.params, self.keypair, [ self.private_attr ])
        return user_token

    def get_mac(self, cred, user_token):
        (_, EGenc, _) = user_token
        (u, EncE, sig_s) = cred
        mac = cred_secret_issue_user_decrypt(self.params, self.keypair, u, EncE, self.ipub, self.public_attr, EGenc, sig_s)
        return mac

    def show(self, mac, cred, Service_name):
        """
          TO BE USED FROM REGISTERING
          Returns the ZK proofs are alla the data you have to sent to the server 
          to validate your previously issued credential
        """
        (G, g, h ,o) = self.params
        (_, _, sig_s) = cred
        (creds, sig_o, zis) = cred_show(self.params, self.ipub, mac, sig_s, public_attr + private_attr, export_zi= True)
    
        [ LT_user_ID ] = self.private_attr
        [ key, value, timeout ] = self.public_attr

        ## The credential contains a number of commitments to the attributes
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
        env.z0, env.z1, env.z2, env.z3  = zis[0], zis[1], zis[2], zis[3]

        sig_openID = zk.build_proof(env.get())

        return encode( (creds, sig_o, sig_openID, Service_name, Uid , public_attr) )

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

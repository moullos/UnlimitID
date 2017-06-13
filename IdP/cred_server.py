# General imports
import sys
sys.path += ["amacscreds"]

from amacscreds import cred_setup, cred_CredKeyge, cred_UserKeyge, cred_secret_issue_user, cred_secret_issue, cred_secret_issue_user_decrypt, cred_show, cred_show_check, cred_secret_issue_user_check
from genzkp import *
from petlib.pack import encode, decode



class CredentialServer():
    def __init__(self, num_pub = 3, num_priv =1):
        
        """
            __init__ imports the long term required values from files
        """
        self.n = num_pub + num_priv
        try:
            with open('params', 'rb') as f: 
                self.params = decode(f.read())
        except IOError:
            self.params = cred_setup()
            with open('params', 'wb+') as f:
                f.write( encode(self.params) )
        try:
            with open('isec', 'rb') as f:
                self.isec = decode(f.read())
            with open('ipub', 'rb') as f: 
                self.ipub = decode(f.read())
        except IOError:
            self.ipub, self.isec = cred_CredKeyge(self.params, self.n)
            with open('isec', 'wb+') as f:
                f.write( encode(self.isec) )
            
            with open('ipub', 'wb+') as f:
                f.write( encode(self.ipub) )


    def get_info(self):
        return (self.params, self.ipub)
    
    def issue_credential(self, (pub, EGenc, sig_u), public_attr):
        """
            TO BE USED FROM THE CREDENTIAL ISSUING ENDPOINT
            pub : users public key
            EGenc : encrypted secret
            sig_u : Proof of valid encryption
            public_attr: (key, value, timeout)
            
        """
        try:
            k, v, timeout = public_attr

            # Testing using ZK if the user has knowledge of the secret
            if not cred_secret_issue_user_check(self.params, pub, EGenc, sig_u):
                raise Exception("Error: Issuing checks failed")

            cred_issued = cred_secret_issue(self.params, pub, EGenc, self.ipub, self.isec, public_attr)
            return cred_issued

        except Exception as e:
            print(e)
    
    def check_pseudonym_and_credential(self, creds, sig_o, sig_openID, Service_name, Uid, public_attr):
        """
            TO BE USED FROM THE PSEUDONYM REGISTRATION ENDPOINT
            creds: the credential
            sig_o: proof of valid aMac
            sig_openID: proof of valid pseudonym
            Service_name: RPs unique identifier (probably its URL)
            Uid: the pseudonym
            public_attr : key, value, timeout
        """
        (G, g, h, o) = self.params
        (u, Cmis, Cup) = creds

        [ key, value, timeout ] = public_attr

        if not cred_show_check(self.params, self.ipub, self.isec, creds, sig_o):
            raise ExceptionE("Error: aMac failed")
        
        # Execute the verification on the proof 'sig_openID'
        Gid = G.hash_to_point(Service_name)
        zk = define_proof(G)
        env2 = ZKEnv(zk)
        env2.u, env2.h = u, h
        env2.Cm0p = Cmis[0] - (key * u)
        env2.Cm1p = Cmis[1] - (value * u)
        env2.Cm2p = Cmis[2] - (timeout * u)

        env2.Cm3 = Cmis[3]

        assert len(Cmis) == 4
        env2.Uid, env2.Gid = Uid, Gid

        return zk.verify_proof(env2.get(), sig_openID)


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


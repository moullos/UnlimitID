from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from werkzeug import generate_password_hash, check_password_hash
from petlib.ec import EcPt
from binascii import unhexlify
db = SQLAlchemy()

class User(db.Model):
    # https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True,
                         nullable=False)
    given_name = db.Column(db.String(100), nullable=False)
    family_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120),unique=True, 
                        index=True, nullable=True)
    email_verified = db.Column(db.Boolean())
    gender = db.Column(db.String(20))
    zoneinfo = db.Column(db.String(50))
    pwdhash = db.Column(db.String(54), nullable=False)
    birthdate = db.Column(db.String(20))
    def __init__(self, **kwargs):
        
        _email = kwargs.pop('email')
        self.email = _email.lower()
        password = kwargs.pop('password')
        self.set_password(password)
        for k, v in kwargs.items():
            setattr(self, k, v)

    def set_password(self, password):
        self.pwdhash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.pwdhash, password)
    
    def get_values_by_keys(self, keys):
        result = []
        for k in keys:
            result.append(getattr(self,k,None))
        return result

class Client(db.Model):
    # id = db.Column(db.Integer, primary_key=True)
    # human readable name
    name = db.Column(db.String(40), nullable=False)
    client_id = db.Column(db.String(40), primary_key=True,
                            nullable=False)
    client_secret = db.Column(db.String(55), unique=True,
                              nullable=False)
    client_type = db.Column(db.String(20), default='public')
    _redirect_uris = db.Column(db.Text)
    default_scope = db.Column(db.Text, default='name gender zoneinfo birthdate')


    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self.default_scope:
            return self.default_scope.split()
        return []

    @property
    def allowed_grant_types(self):
        return ['authorization_code', 'password', 'client_credentials',
                'refresh_token']


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.String, db.ForeignKey('pseudonym.id', ondelete='CASCADE')
    )
    user = relationship('Pseudonym')

    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    client = relationship('Client')
    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    scope = db.Column(db.Text)
    expires = db.Column(db.DateTime)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return None


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey('pseudonym.id', ondelete='CASCADE')
    )
    user = relationship('Pseudonym')
    client = relationship('Client')
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255))
    refresh_token = db.Column(db.String(255))
    expires = db.Column(db.DateTime)
    scope = db.Column(db.Text)

    def __init__(self, **kwargs):
        expires_in = kwargs.pop('expires_in', None)
        if expires_in is not None:
            self.expires = datetime.utcnow() + timedelta(seconds=expires_in)

        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return []

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

class Pseudonym(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # The client the pseudonym is giving access to
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    client = relationship('Client')
    _uid = db.Column(db.String(70), nullable=False, unique=True)
    _keys = db.Column(db.String(255), nullable=False)
    _values = db.Column(db.String(255), nullable=False)
    def __init__(self, **kwargs):
        
        uid = kwargs.pop('uid')
        self._uid = str(uid)
        
        keys = kwargs.pop('keys')
        self._keys = ','.join(keys)
        
        values = kwargs.pop('values')
        self._values = ','.join(values)

        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def uid(self):
        return EcPt.from_binary(unhexlify(self.uid))

    @property
    def keys(self):
        return self._keys.split(',')

    @property
    def values(self):
        return self._values.split(',')
    @property
    def attr(self):
        return(dict(zip(self.keys,self.values)))

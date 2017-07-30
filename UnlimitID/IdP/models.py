from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from werkzeug import generate_password_hash, check_password_hash
from petlib.ec import EcPt
from petlib.pack import encode, decode
from binascii import hexlify, unhexlify

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True,
                     nullable=False)
    given_name = db.Column(db.String(100), nullable=False)
    family_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True,
                      index=True, nullable=True)
    gender = db.Column(db.String(20), nullable=False)
    zoneinfo = db.Column(db.String(50), nullable=False)
    pwdhash = db.Column(db.String(54), nullable=False)
    birthdate = db.Column(db.String(20), nullable=False)
    _enc_secret = db.Column(db.Text)

    def __init__(self, **kwargs):
        _email = kwargs.pop('email')
        self.email = _email.lower()

        password = kwargs.pop('password')
        self.set_password(password)

        if 'enc_secret' in kwargs:
            enc_secret = kwargs.pop('enc_secret')
            self._enc_secret = hexlify(encode(enc_secret))
        else:
            self._enc_secret = None

        for k, v in kwargs.items():
            setattr(self, k, v)

    def set_password(self, password):
        self.pwdhash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.pwdhash, password)

    def get_values_by_keys(self, keys):
        result = []
        for k in keys:
            result.append(getattr(self, k, None))
        return result

    def check_enc_secret(self, enc_secret):
        _enc_secret = hexlify(encode(enc_secret))
        if self._enc_secret is None:
            self._enc_secret = _enc_secret
            db.session.commit()
            return True
        elif self._enc_secret == _enc_secret:
            return True
        else:
            return False

    @property
    def enc_clients_secret(self):
        return decode(unhexlify(self._enc_clients_secret))


class Client(db.Model):
    name = db.Column(db.String(40), nullable=False)
    client_id = db.Column(db.String(40), primary_key=True,
                          nullable=False, unique=True)
    client_secret = db.Column(db.String(55), nullable=False)
    client_type = db.Column(db.String(20), nullable=False)
    _redirect_uris = db.Column(db.Text, nullable=False)
    _default_scope = db.Column(db.Text)

    def __init__(self, **kwargs):
        redirect_uris = kwargs.pop('redirect_uris').splitlines()
        self._redirect_uris = ' '.join(redirect_uris)
        default_scope = kwargs.pop('default_scope')
        self._default_scope = ' '.join(default_scope)
        for k, v in kwargs.items():
            setattr(self, k, v)

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
        if self._default_scope:
            return self._default_scope.split()
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
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    client = relationship('Client')
    _uid = db.Column(db.String(70), nullable=False)
    _keys = db.Column(db.String(255), nullable=False)
    _values = db.Column(db.String(255), nullable=False)
    timeout = db.Column(db.String(12), nullable=False)

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
        return EcPt.from_binary(unhexlify(self._uid))

    @property
    def keys(self):
        return self._keys.split(',')

    @property
    def values(self):
        return self._values.split(',')

    @property
    def attr(self):
        return(dict(zip(self.keys, self.values)))

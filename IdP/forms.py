from models import db, Client

from wtforms import Form, BooleanField, StringField, PasswordField, validators

class SignupForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    firstname = StringField('Firstname',[validators.Length(min=4, max=25)])
    lastname = StringField('Lastname', [validators.Length(min=4,max=25)])
    email = StringField('Email Address', [validators.Email("Please enter your email address")])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')

class LoginForm(Form):
    email = StringField('Email', [validators.Email("Please enter a valid email")])
    password = PasswordField('Password', [validators.DataRequired()])

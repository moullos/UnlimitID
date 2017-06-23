from models import db, Client

from wtforms import Form, BooleanField, SelectField, StringField, PasswordField, validators

from wtforms.fields.html5 import DateField
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired

class SignupForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    firstname = StringField('Firstname',[validators.Length(min=4, max=25)])
    lastname = StringField('Lastname', [validators.Length(min=4,max=25)])
    email = StringField('Email Address', [validators.Email("Please enter a valid email address")])
    gender = SelectField('Gender', choices = [('male','Male'),('female','Female'), ('other','Other')])
    zoneinfo = StringField('Zoneinfo', [validators.DataRequired()])
    birthdate = DateField('Birthday', [validators.DataRequired()])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')

class LoginForm(Form):
    email = StringField('Email', [validators.Email("Please enter a valid email")])
    password = PasswordField('Password', [validators.DataRequired()])

class AuthorizeForm(FlaskForm):
    show = FileField(validators=[FileRequired()])


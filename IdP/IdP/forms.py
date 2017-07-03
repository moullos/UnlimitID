from wtforms import (Form, SelectField, StringField, PasswordField,
                     TextAreaField, validators, widgets, SelectMultipleField,
                     FileField)
from wtforms.fields.html5 import DateField
from flask_wtf import FlaskForm
from flask_wtf.file import FileRequired


class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class SignupForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    firstname = StringField('Firstname', [validators.Length(min=4, max=25)])
    lastname = StringField('Lastname', [validators.Length(min=4, max=25)])
    email = StringField('Email Address', [validators.Email(
        "Please enter a valid email address")])
    gender = SelectField('Gender', choices=[
                ('male', 'Male'), ('female', 'Female'), ('other', 'Other')])
    zoneinfo = StringField('Zoneinfo', [validators.DataRequired()])
    birthdate = DateField('Birthday', [validators.DataRequired()])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')


class LoginForm(Form):
    email = StringField(
        'Email', [validators.Email("Please enter a valid email")])
    password = PasswordField('Password', [validators.DataRequired()])


class AuthorizeForm(FlaskForm):
    show = FileField(validators=[FileRequired()])


class ClientForm(Form):
    name = StringField('Name', [validators.DataRequired()])
    client_id = StringField('ID', [validators.DataRequired()])
    client_secret = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    client_type = SelectField('Type', choices=[
        ('public', 'Public'), ('confidential', 'Confidential')])
    redirect_uris = TextAreaField('Redirect URIS', [
                                    validators.DataRequired(),
                                    validators.length(max=200)])
    scopes = MultiCheckboxField('Scope')

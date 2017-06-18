from wtforms import Form, widgets ,SelectMultipleField, StringField, PasswordField, validators


class RegisterForm(Form):
    
    service_name = StringField('Service Name', [validators.DataRequired()])

class CredentialForm(Form):
    email = StringField('Email', [validators.Email("Please enter a valid email")])
    password = PasswordField('Password', [validators.DataRequired()])     

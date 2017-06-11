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

"""
class AuthorizationForm(Form):
  email = TextField("Email",  [validators.Required("Please enter your email address."), validators.Email("Please enter your email address.")])
  password = PasswordField('Password', [validators.Required("Please enter a password.")])
  submit = SubmitField("Authorize")
   
  def __init__(self, *args, **kwargs):
    Form.__init__(self, *args, **kwargs)
 
  def validate(self):
    if not Form.validate(self):
      return False
     
    user = User.query.filter_by(email = self.email.data.lower()).first()
    if user and user.check_password(self.password.data):
      return True
    else:
      self.email.errors.append("Invalid e-mail or password")
      return False

"""

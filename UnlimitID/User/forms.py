from wtforms import Form, widgets ,SelectMultipleField, StringField, PasswordField, validators, widgets, SelectMultipleField

class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()

class RegisterForm(Form):
    service_name = StringField('Service Name', [validators.DataRequired()])

class CredentialForm(Form):
    email = StringField('Email', [validators.Email("Please enter a valid email")])
    password = PasswordField('Password', [validators.DataRequired()])
    attr = MultiCheckboxField('Attributes in the credential')


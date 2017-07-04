from flask import Flask
import os
app = Flask(__name__)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
app.debug = True
app.secret_key = 'development'
from .views import *

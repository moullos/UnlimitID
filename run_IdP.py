from UnlimitID.IdP import create_app
app = create_app('crypto_idp')
app.run(debug=True)

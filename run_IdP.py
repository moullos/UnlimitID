from UnlimitID.IdP import create_app
import config_IdP as cfg
app, db, cs = create_app(cfg, return_all=True)
if __name__ == '__main__':
    app.run(debug=True)

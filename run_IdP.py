from UnlimitID.IdP import create_app
import config_IdP as cfg
app = create_app(cfg)
if __name__ == '__main__':
    app.run()

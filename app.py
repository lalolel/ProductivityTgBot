import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
# create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.environ.get("SECRET_KEY", "default_secret_key"))
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1) # needed for url_for to generate with https

# configure the database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# initialize the app with the extension, flask-sqlalchemy >= 3.0.x
db.init_app(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/')
def index():
    """Landing page for the password manager web interface."""
    return render_template('index.html')

@app.route('/about')
def about():
    """About page."""
    return render_template('about.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import google.auth.transport.requests
import google.oauth2.id_token
import datetime
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


app.config["JWT_SECRET_KEY"] = "d63e7c2b0f722bf9250d7cd0cc3c888d1fd1675a88d7b53c6a2c1f74bb2c2d09"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(minutes=15)  # Expiration en 15 min
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = datetime.timedelta(days=30)  # Expiration en 30 jours


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Fichier de base de données SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Désactive la modification de suivi
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

jwt = JWTManager(app)


GOOGLE_CLIENT_ID = "865121288275-es745lvsgj1jkdv6e3ugt693ieq0fs8u.apps.googleusercontent.com"



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


with app.app_context():
    db.create_all()

def verify_google_token(token):

    try:
        request_adapter = google.auth.transport.requests.Request()
        id_info = google.oauth2.id_token.verify_oauth2_token(token, request_adapter, GOOGLE_CLIENT_ID)
        return id_info  # Contient email, name, sub (Google User ID)
    except Exception as e:
        return None

@app.route("/auth/register", methods=["POST"])
def register():

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400


    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400


    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')


    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully"}), 201

@app.route("/auth/login", methods=["POST"])
def basic_login():

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")


    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)
        return jsonify({"access_token": access_token, "refresh_token": refresh_token, "user": user.username})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route("/auth/google", methods=["POST"])
def google_login():

    data = request.get_json()
    token = data.get("id_token")

    user_info = verify_google_token(token)
    if not user_info:
        return jsonify({"error": "Invalid Google Token"}), 401

    email = user_info["email"]


    if not User.query.filter_by(username=email).first():
        new_user = User(username=email, password="")
        db.session.add(new_user)
        db.session.commit()


    access_token = create_access_token(identity=email)
    refresh_token = create_refresh_token(identity=email)

    return jsonify({"access_token": access_token, "refresh_token": refresh_token, "user": user_info})


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():

    username = get_jwt_identity()
    new_access_token = create_access_token(identity=username)
    return jsonify({"access_token": new_access_token})


@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    
    username = get_jwt_identity()
    return jsonify({"message": "Access granted", "user": username})


if __name__ == "__main__":
    app.run(debug=True)

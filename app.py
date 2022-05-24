import os
import jwt
import json
import psycopg2
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, make_response

load_dotenv()

app = Flask(__name__)
app.config["DEBUG"] = True

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://spencer:password@localhost/jwt_learning'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class User(db.Model):
    __table_name = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    date_registered = db.Column(db.DateTime, default=datetime.utcnow())


def encode_token(user_id):
    payload = {
        'exp': datetime.utcnow() + timedelta(days=0, seconds=5),
        'iat': datetime.utcnow(),
        'sub': user_id
    }
    token = jwt.encode(payload, os.getenv('SECRET_KEY'),
                       algorithm='HS256').decode("utf-8")
    return token


@app.route('/')
def hello_world():
    return 'Welcome to JWT Tokens'


@app.route('/register', methods=['POST'])
def register_user():
    email = request.form['email']
    password = request.form['password']

    user = User.query.filter_by(email=email).first()

    if not user:
        try:

            hashed_password = generate_password_hash(password)
            user = User(email=email, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            resp = {
                "status": "success",
                "message": "User successfully registered",
            }
            return make_response(jsonify(resp)), 201

        except Exception as e:
            print(e)
            resp = {
                "status": "Error",
                "message": " Error occured, user registration failed"
            }
            return make_response(jsonify(resp)), 401
    else:
        resp = {
            "status": "error",
            "message": "User already exists"
        }
        return make_response(jsonify(resp)), 202


@app.route('/login', methods=['POST'])
def post():
    email = request.form['email']
    password = request.form['password']

    try:

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password) == True:
            auth_token = encode_token(user.id)
            resp = {
                "status": "success",
                "message": "Successfully logged in",
                'auth_token': auth_token
            }
            return make_response(jsonify(resp)), 200
        else:
            resp = {
                "status": "Error",
                "message": "User does not exist"
            }
            return make_response(jsonify(resp)), 404

    except Exception as e:
        print(e)
        resp = {
            "Status": "error",
            "Message": "User login failed"
        }
        return make_response(jsonify(resp)), 404


if __name__ == '__main__':
    db.create_all()
    app.run(port=5002)

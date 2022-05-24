import os
import jwt
from functools import wraps
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
        'exp': datetime.utcnow() + timedelta(days=1),
        'iat': datetime.utcnow(),
        'sub': user_id
    }
    token = jwt.encode(payload, os.getenv('SECRET_KEY'),
                       algorithm='HS256').decode("utf-8")
    return token


@app.route('/')
def hello_world():
    return jsonify(hello='world')


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


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]

        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            data = jwt.decode(
                token, os.getenv('SECRET_KEY'), algorithms=["HS256"])
            current_user = User.query.filter_by(
                id=data['sub']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/protected', methods=['GET'])
@token_required
def protected(f):
    resp = {"message": "you are viewing a protected route"}
    return make_response(jsonify(resp)), 404

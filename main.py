from flask import Flask, request, jsonify, session
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']

# Configure MongoDB
app.config['MONGO_URI'] = os.getenv('MONGO_URI')  # Load MongoDB URI from environment variable
mongo = PyMongo(app)

# Initialize Bcrypt
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Enable CORS for your app with specific origins
CORS(app)
jwt_blacklist = set()

@app.route('/check', methods=['GET'])
def check():
    return jsonify({'message': 'Backend is running'}), 200

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Store the user in MongoDB (you should have a 'users' collection)
    users = mongo.db.User1
    existing_user = users.find_one({'username': username})

    if existing_user:
        return jsonify({'message': 'User already exists'})
    
    try:
        # Insert the user with username, email, and hashed_password
        users.insert_one({'username': username, 'email': email, 'password': hashed_password})
        return jsonify({'message': 'Signup successful'})
    except Exception as e:
        return jsonify({'message': 'Error during signup', 'error': str(e)})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Fetch the user from MongoDB (you should have a 'users' collection)
    users = mongo.db.User1
    user = users.find_one({'username': username})

    if not user:
        return jsonify({'message': 'User not found'}), 401

    hashed_password = user['password']

    if bcrypt.check_password_hash(hashed_password, password):
        access_token = create_access_token(identity=username)
        return jsonify({'message': 'Login successful', 'access_token': access_token}), 200
    else:
        return jsonify({'message': 'Login failed', 'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['GET'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    jwt_blacklist.add(jti)

    return jsonify({'message': 'Logout successful'})

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    jti = get_jwt()['jti']

    # Check if the token is in the blacklist
    if jti in jwt_blacklist:
        return jsonify({'message': 'Token has been revoked'}), 401
    
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':
    app.run(debug=True)

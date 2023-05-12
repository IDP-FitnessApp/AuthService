"""
• This is a simple authentication service that allows users to register, login, and verify their identity.
• I've used Flask and MongoDB to build this service.

The service has three endpoints:

- /auth/register: accepts a POST request with the user's first name, last name, email, phone, address, and password. It then creates a new user in the database.
-- The register route checks if a user with the provided email already exists in the database. If not, it generates a salt and hashes the password using bcrypt before inserting the user to the database.


- /auth/login: accepts a POST request with the user's email and password. It then creates a new session for the user and returns a token.
-- The login route finds the user by email and checks if the provided password matches the hashed password in the database. If the credentials are correct, it generates a random token, saves the session to the database, and returns the token.

- /auth/verify: accepts a POST request with the user's token. It then verifies the token and returns the user's ID.
-- The verify route finds the session by token and returns the associated userId if it exists in the database.
"""
from flask import Flask, jsonify, request
from pymongo import MongoClient
import bcrypt
import uuid

app = Flask(__name__)

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['auth_service']
users = db['users']
sessions = db['sessions']

"""
register() function:
- first, I've used Flask to get the request data and check if any required field is missing.
- after, I've used MongoDB to check if the email already exists.
- then, I've used bcrypt to hash the password.
- finally, I've added the user to the database.
- I've used Flask to return the response with the appropriate status code.
"""
@app.route('/auth/register', methods=['POST'])
def register():
    # Get request data
    req_data = request.get_json()
    if not req_data:
        return jsonify({'error': 'Request data is missing'}), 400

    # Check if any required field is missing
    required_fields = ['first_name', 'last_name', 'email', 'phone', 'address', 'password']
    for field in required_fields:
        if field not in req_data:
            return jsonify({'error': f'{field} is missing'}), 400

    # Validate email format
    email = req_data['email']
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400

    # Check if email already exists
    if users.find_one({'email': email}):
        return jsonify({'error': 'Email already exists'}), 409

    # Hash password
    password = req_data['password'].encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password, salt)

    # Add user to database
    user = {
        'first_name': req_data['first_name'],
        'last_name': req_data['last_name'],
        'email': email,
        'phone': req_data['phone'],
        'address': req_data['address'],
        'password': hashed_password,
    }
    users.insert_one(user)

    return jsonify({'success': True}), 201

"""
login() function:
- first, I've used Flask to get the request data and check if any required field is missing.
- after, I've used MongoDB to find the user by email and check if the user exists.
- then, I've used bcrypt to check the password.
- finally, I've created a session for the user and returned a token.
- I've used Flask to return the response with the appropriate status code.

"""
@app.route('/auth/login', methods=['POST'])
def login():
    # Get request data
    req_data = request.get_json()
    if not req_data:
        return jsonify({'error': 'Request data is missing'}), 400
    email = req_data.get('email')
    password = req_data.get('password')

    # Check if any required field is missing
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    # Find user by email
    user = users.find_one({'email': email})
    if user is None:
        return jsonify({'error': 'Invalid email or password'}), 401

    # Check password
    hashed_password = user['password']
    if not bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        return jsonify({'error': 'Invalid email or password'}), 401

    # Create session
    token = str(uuid.uuid4())
    session = {'token': token, 'userId': str(user['_id'])}
    sessions.insert_one(session)

    return jsonify({'token': token}), 200


"""
verify() function:

- Proper error handling: for example, checking if the request data is missing, required fields are missing, or if a user already exists.

- Input validation: for example, validating the email format and making sure all required fields are present.

- Security measures: using bcrypt to hash and compare passwords, generating random UUID tokens for sessions, and checking the token against the sessions database.

Extra : added a separate function to validate the email format using a regular expression.

"""
@app.route('/auth/verify', methods=['POST'])
def verify():
    # Get request data
    req_data = request.get_json()
    if not req_data:
        return jsonify({'error': 'Request data is missing'}), 400
    token = req_data.get('token')

    # Check if any required field is missing
    if not token:
        return jsonify({'error': 'One or more required fields are missing'}), 400

    # Find session by token
    session = sessions.find_one({'token': token})

    # Check if session exists
    if session is None:
        return jsonify({'error': 'Invalid token'}), 401

    # Get user id from session
    user_id = session['userId']

    return jsonify({'userId': user_id}), 200

"""
validate_email() function:

- Using a regular expression to validate the email format.

"""
def validate_email(email):
    # Source: https://stackoverflow.com/questions/8022530/how-to-check-for-valid-email-address
    import re
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email) is not None


if __name__ == '__main__':
    app.run(debug=True)

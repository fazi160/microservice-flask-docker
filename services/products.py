import requests
from flask import Flask, jsonify, request, make_response
import jwt
from functools import wraps
import json
import os
from jwt.exceptions import DecodeError
app = Flask(__name__)
port = int(os.environ.get('PORT', 5000))
app.config['SECRET_KEY'] = os.urandom(24)


app = Flask(__name__)
port = int(os.environ.get('PORT', 5000))
app.config['SECRET_KEY'] = os.urandom(24)

# Define user data directly within the script
users = [
    {
        "id": 1,
        "username": "admin",
        "password": "admin"
    }
]


@app.route('/auth', methods=['POST'])
def authenticate_user():
    if request.headers['Content-Type'] != 'application/json':
        return jsonify({'error': 'Unsupported Media Type'}), 415
    username = request.json.get('username')
    password = request.json.get('password')
    for user in users:
        if user['username'] == username and user['password'] == password:
            token = jwt.encode(
                {'user_id': user['id']}, app.config['SECRET_KEY'], algorithm="HS256")
            response = make_response(
                jsonify({'message': f'Authentication successful: {token}'}))
            response.set_cookie('token', token)
            return response, 200
    return jsonify({'error': 'Invalid username or password'}), 401





def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({'error': 'Authorization token is missing'}), 401
        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id']
        except DecodeError:
            return jsonify({'error': 'Authorization token is invalid'}), 401
        return f(current_user_id, *args, **kwargs)
    return decorated


@app.route("/")
def home():
    return "Hello, this is a Flask Microservice"


BASE_URL = 'https://dummyjson.com'


@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user_id):
    response = requests.get(f"{BASE_URL}/products")
    if response.status_code != 200:
        return jsonify({'error': response.json()['message']}), response.status_code

    products_arr = []
    for products in response.json()['products']:
        print(products)
        product_data = {
            'id': products['id'],
            'title': products['title'],
            'brand': products['brand'],
            'price': products['price'],
            'description': products['description']
        }
        products_arr.append(product_data)
    return jsonify({'data': products_arr}), 200 if products_arr else 204


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=port)

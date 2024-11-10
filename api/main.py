import json

import bcrypt
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from jsonschema import validate, ValidationError
from bson import ObjectId

from db.db import Connection

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "warehouse"
jwt = JWTManager(app)
CORS(app)

db = Connection('warehouse')
products_collection = db.products

# Load JSON schema from external file
def load_schema(file_name):
    with open(f'../schema/{file_name}', 'r') as schema_file:
        return json.load(schema_file)


# Load the schemas
user_schema = load_schema('user.json')
login_schema = load_schema('login.json')


# User registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Validate the data against the JSON schema
    try:
        validate(instance=data, schema=user_schema)
    except ValidationError as e:
        return jsonify({"msg": f"Validation error: {e.message}"}), 400

    users = db.users

    # Check if the email already exists
    if users.find_one({"email": data["email"]}):
        return jsonify({"msg": "Email already exists"}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(data["password"].encode('utf-8'), bcrypt.gensalt())

    # Set isApproved based on role
    is_approved = True if data["role"] == "customer" else False

    # Insert the user with top-level attributes only
    user_data = {
        "email": data["email"],
        "password": hashed_password,
        "role": data["role"],
        "isProfileComplete": False,
        "isApproved": is_approved  # False for admin, True for customers
    }

    users.insert_one(user_data)
    return jsonify({"msg": "User registered successfully"}), 200


# User login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    # Validate the login data against the JSON schema
    try:
        validate(instance=data, schema=login_schema)
    except ValidationError as e:
        return jsonify({"msg": f"Validation error: {e.message}"}), 400

    users = db.users
    user = users.find_one({"email": data["email"]})

    # Check if the user exists and verify password
    if user and bcrypt.checkpw(data["password"].encode('utf-8'), user["password"]):
        # Check if admin is approved
        if user["role"] == "admin" and not user["isApproved"]:
            return jsonify({"msg": "Your account is pending approval by an admin."}), 403

        access_token = create_access_token(identity=user["email"],
                                           additional_claims={"email": user["email"], "role": user["role"]})
        return jsonify({"access_token": access_token}), 200
    return jsonify({"msg": "Invalid credentials"}), 401


# Admin-only product management (CRUD)
@app.route('/products', methods=['POST'])
@jwt_required()
def add_product():
    identity = get_jwt_identity()
    if identity["role"] != "admin":
        return jsonify({"msg": "Admins only!"}), 403
    data = request.get_json()
    db.products.insert_one(data)
    return jsonify({"msg": "Product added"}), 201

# Route to retrieve all products (GET)
@app.route('/products', methods=['GET'])
def get_all_movies():
    try:
        # Fetch products and return selected fields
        products = products_collection.find({}, {
             "_id": 1, "name": 1, "description": 1, "price": 1, "category": 1,
            "imageUrl": 1, "quantity": 1
        }).limit(20)
        product_list = []
        for product in products:
            if '_id' in product and isinstance(product['_id'], ObjectId):
                product['_id'] = str(product['_id'])  # Convert ObjectId to string
            product_list.append(product)

        return jsonify(product_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    # Run the application on all available IPs on port 8888
    app.run(host='0.0.0.0', port=8888)

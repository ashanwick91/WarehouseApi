import datetime
import json
import logging

import bcrypt
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from jsonschema import validate, ValidationError

from db.db import Connection

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "warehouse"
jwt = JWTManager(app)
CORS(app)

db = Connection('warehouse')


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


# Admin-only endpoint for financial reporting
@app.route('/reports', methods=['GET'])
def get_financial_report():
    report_type = request.args.get("reportType", "Monthly")

    # Step 1: Calculate the total sales amount across all items
    total_sales = list(db.order.aggregate([
        { "$unwind": "$items" },
        {
            "$group": {
                "_id": None,
                "totalSales": {"$sum": "$items.salesAmount"}
            }
        }
    ]))

    # Extract the total sales value
    total_sales_amount = total_sales[0]["totalSales"] if total_sales else 1  # Avoid division by zero if no sales data

    # Step 2: Calculate the percentage of sales for each category
    sales_data_category = list(db.order.aggregate([
        { "$unwind": "$items" },
        {
            "$group": {
                "_id": "$items.category",
                "categorySales": {"$sum": "$items.salesAmount"},
                "totalProfitCategory": {"$sum": "$items.profitAmount"}
            }
        },
        {
            "$addFields": {
                "totalSalesCategory": {
                    "$multiply": [{"$divide": ["$categorySales", total_sales_amount]}, 100]
                }
            }
        },
        {
            "$project": {
                "category": "$_id",
                "totalSalesCategory": 1,  # This now shows the percentage
                "totalProfitCategory": 1,
                "_id": 0
            }
        }
    ]))

    # Retrieve sales data by product, including all products
    sales_data_product = list(db.order.aggregate([
        { "$unwind": "$items" },
        {
            "$group": {
                "_id": "$items.productName",
                "totalSalesProduct": {"$sum": "$items.salesAmount"},
                "totalProfitProduct": {"$sum": "$items.profitAmount"}
            }
        },
        {
            "$project": {
                "product": "$_id",
                "totalSalesProduct": 1,
                "totalProfitProduct": 1,
                "_id": 0
            }
        }
    ]))

    # Structure the financial report
    financial_report = {
        "reportType": report_type,
        "salesDataCategory": sales_data_category,
        "salesDataProduct": sales_data_product,
        "reportGeneratedAt": datetime.datetime.now().isoformat()
    }

    return jsonify(financial_report), 200


if __name__ == '__main__':
    # Run the application on all available IPs on port 8888
    app.run(host='0.0.0.0', port=8888)
import datetime
import json
from datetime import datetime, timedelta

import bcrypt
from bson import ObjectId
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from jsonschema import validate, ValidationError
from pymongo import ASCENDING, DESCENDING

from db.db import Connection

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "warehouse"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=30)
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


# Route to retrieve products (GET)
@app.route('/products', methods=['GET'])
def get_products():
    name = request.args.get('name')
    description = request.args.get('description')
    category = request.args.get('category')
    sort = request.args.get('sort')

    query = {"isDeleted": {"$ne": True}}

    # Prepare the $or condition list if needed
    or_conditions = []

    if name:
        or_conditions.append({"name": {"$regex": name, "$options": "i"}})
    if description:
        or_conditions.append({"description": {"$regex": description, "$options": "i"}})
    if category:
        or_conditions.append({"category": {"$regex": category, "$options": "i"}})

    # If there are conditions in or_conditions, add $or to the query
    if or_conditions:
        query["$or"] = or_conditions

    fields_required = {
        "_id": 1, "name": 1, "description": 1, "price": 1, "category": 1, "imageUrl": 1, "quantity": 1
    }

    try:
        if sort:
            # Parse the sort parameter
            sort_field, sort_direction = sort.split(":")
            sort_order = ASCENDING if sort_direction == "asc" else DESCENDING

            # Apply sorting only if sort_param is present
            products = db.products.find(query, fields_required).sort(sort_field, sort_order)
        else:
            products = db.products.find(query, fields_required)

        product_list = []
        for product in products:
            if '_id' in product and isinstance(product['_id'], ObjectId):
                product['_id'] = str(product['_id'])  # Convert ObjectId to string
            product_list.append(product)

        return jsonify(product_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Endpoint to delete a product by its ID
@app.route('/products/<string:product_id>', methods=['DELETE'])
@jwt_required()
def soft_delete_product(product_id):
    claims = get_jwt()  # Gets the entire JWT, including additional claims

    # Access custom claims
    role = claims.get("role")

    # Check if the current user is an admin
    if role != "admin":
        return jsonify({"msg": "Access denied: Only admins can delete products"}), 403

    products = db.products
    result = products.update_one({"_id": ObjectId(product_id)}, {"$set": {"isDeleted": True}})

    if result.matched_count == 1:
        return jsonify({"msg": "Product deleted successfully"}), 200
    else:
        return jsonify({"msg": "Product not found"}), 404


# Admin-only endpoint for financial reporting
@app.route('/reports', methods=['GET'])
def get_financial_report():
    report_type = request.args.get("reportType", "Monthly")
    filter_month = request.args.get("filterMonth")
    filter_date = request.args.get("filterDate")

    # Prepare date filter condition
    date_filter = {}

    if filter_date:
        # If a specific date is provided, use it to filter
        try:
            specific_date = datetime.strptime(filter_date, "%Y-%m-%d")
            start_date = datetime(specific_date.year, specific_date.month, specific_date.day, 0, 0, 0)
            end_date = datetime(specific_date.year, specific_date.month, specific_date.day, 23, 59, 59)
            date_filter["orderDate"] = {"$gte": start_date, "$lte": end_date}
        except ValueError:
            return jsonify({"msg": "Invalid date format, expected YYYY-MM-DD"}), 400

    elif filter_month:
        # If a month is provided, use it to filter
        try:
            year, month = map(int, filter_month.split("-"))
            start_date = datetime(year, month, 1)
            if month == 12:
                end_date = datetime(year + 1, 1, 1)
            else:
                end_date = datetime(year, month + 1, 1)
            date_filter["orderDate"] = {"$gte": start_date, "$lt": end_date}
        except ValueError:
            return jsonify({"msg": "Invalid month format, expected YYYY-MM"}), 400

    else:
        # Default to current month
        now = datetime.now()
        start_date = datetime(now.year, now.month, 1)
        if now.month == 12:
            end_date = datetime(now.year + 1, 1, 1)
        else:
            end_date = datetime(now.year, now.month + 1, 1)
        date_filter["orderDate"] = {"$gte": start_date, "$lt": end_date}

    # Debugging log to confirm the date filter
    print(f"Date Filter Applied: {date_filter}")

    # Step 1: Calculate the total sales amount across all items
    total_sales = list(db.order.aggregate([
        {"$match": date_filter},
        {"$unwind": "$items"},
        {
            "$group": {
                "_id": None,
                "totalSales": {"$sum": "$items.salesAmount"}
            }
        }
    ]))

    # Debugging log to confirm total sales aggregation result
    print(f"Total Sales Aggregation Result: {total_sales}")

    total_sales_amount = total_sales[0]["totalSales"] if total_sales else 1  # Avoid division by zero if no sales data

    # Step 2: Calculate the percentage of sales for each category
    sales_data_category = list(db.order.aggregate([
        {"$match": date_filter},
        {"$unwind": "$items"},
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
                "totalSalesCategory": 1,
                "totalProfitCategory": 1,
                "_id": 0
            }
        }
    ]))

    # Debugging log to confirm sales by category
    print(f"Sales Data by Category: {sales_data_category}")

    # Step 3: Retrieve sales data by product
    sales_data_product = list(db.order.aggregate([
        {"$match": date_filter},
        {"$unwind": "$items"},
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

    # Debugging log to confirm sales data by product
    print(f"Sales Data by Product: {sales_data_product}")

    financial_report = {
        "reportType": report_type,
        "salesDataCategory": sales_data_category,
        "salesDataProduct": sales_data_product,
        "reportGeneratedAt": datetime.now().isoformat()
    }

    return jsonify(financial_report), 200


if __name__ == '__main__':
    # Run the application on all available IPs on port 8888
    app.run(host='0.0.0.0', port=8888)

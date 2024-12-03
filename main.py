import datetime
import json
from datetime import datetime, timedelta

import bcrypt
from bson.objectid import ObjectId
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt
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
    with open(f'schema/{file_name}', 'r') as schema_file:
        return json.load(schema_file)


# Load the schemas
user_schema = load_schema('user.json')
login_schema = load_schema('login.json')
product_schema = load_schema('product.json')


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
        "isApproved": is_approved,  # False for admin, True for customers
        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow()
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
                                           additional_claims={"email": user["email"], "role": user["role"],
                                                              "_id": str(user["_id"])})
        return jsonify({"access_token": access_token}), 200
    return jsonify({"msg": "Invalid credentials"}), 401


@app.route('/products', methods=['POST'])
@jwt_required()
def add_product():
    claims = get_jwt()  # Gets the entire JWT, including additional claims

    # Access custom claims
    role = claims.get("role")

    # Check if the current user is an admin
    if role != "admin":
        return jsonify({"msg": "Access denied: Only admins can add products"}), 403

    # Parse JSON request
    data = request.get_json()

    # Validate JSON payload against the schema
    try:
        validate(instance=data, schema=product_schema)
    except ValidationError as e:
        return jsonify({"msg": f"Validation error: {e.message}"}), 400

    # Populate createdAt and updatedAt fields
    product = {
        "name": data["name"],
        "description": data["description"],
        "price": data["price"],
        "originalPrice": data["originalPrice"],
        "category": data["category"],
        "imageUrl": data["imageUrl"],
        "quantity": data["quantity"],
        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow()
    }

    # Insert product into the database
    db.products.insert_one(product)
    return jsonify({"msg": "Product created successfully"}), 201


@app.route('/products/<product_id>', methods=['PUT'])
@jwt_required()
def edit_product(product_id):
    claims = get_jwt()  # Gets the entire JWT, including additional claims

    # Access custom claims
    role = claims.get("role")

    # Check if the current user is an admin
    if role != "admin":
        return jsonify({"msg": "Access denied: Only admins can update products"}), 403

    # Parse JSON request
    data = request.get_json()

    # Validate JSON payload against the schema
    try:
        validate(instance=data, schema=product_schema)
    except ValidationError as e:
        return jsonify({"msg": f"Validation error: {e.message}"}), 400

    # Check if the product exists
    if not db.products.find_one({"_id": ObjectId(product_id)}):
        return jsonify({"msg": "Product not found"}), 404

    # Update the product
    update_data = {
        "name": data["name"],
        "description": data["description"],
        "price": data["price"],
        "originalPrice": data["originalPrice"],
        "category": data["category"],
        "imageUrl": data["imageUrl"],
        "quantity": data["quantity"],
        "updatedAt": datetime.utcnow()
    }

    db.products.update_one({"_id": ObjectId(product_id)}, {"$set": update_data})
    return jsonify({"msg": "Product updated successfully"}), 200


# Route to retrieve products (GET)
@app.route('/products', methods=['GET'])
def get_products():
    name = request.args.get('name')
    description = request.args.get('description')
    category = request.args.get('category')
    sort = request.args.get('sort')

    min_price = request.args.get('minPrice', type=float)
    max_price = request.args.get('maxPrice', type=float)

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
    if category:
        query["category"] = {"$regex": category, "$options": "i"}

        # Add price range filter (new)
    if min_price is not None or max_price is not None:
        price_filter = {}
        if min_price is not None:
            price_filter["$gte"] = min_price
        if max_price is not None:
            price_filter["$lte"] = max_price
        query["price"] = price_filter

    fields_required = {
        "_id": 1, "name": 1, "description": 1, "price": 1, "originalPrice": 1, "category": 1, "imageUrl": 1, "quantity": 1
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


@app.route('/categories', methods=['GET'])
@jwt_required()
def get_categories():
    claims = get_jwt()  # Gets the entire JWT, including additional claims

    # Access custom claims
    role = claims.get("role")

    # Check if the current user is an admin
    if role != "admin":
        return jsonify({"msg": "Access denied: Only admins can retrieve product categories"}), 403

    # Fetch only the names of all categories from the database
    categories = db.categories.find({}, {"_id": 0, "name": 1})
    category_names = [category["name"] for category in categories]

    return jsonify(category_names), 200


@app.route('/categories', methods=['POST'])
@jwt_required()
def add_category():
    claims = get_jwt()  # Gets the entire JWT, including additional claims

    # Access custom claims
    role = claims.get("role")

    # Check if the current user is an admin
    if role != "admin":
        return jsonify({"msg": "Access denied: Only admins can add product categories"}), 403

    data = request.get_json()
    category_name = data.get("name")

    if not category_name:
        return jsonify({"msg": "Category name is required"}), 400

    # Check if the category already exists
    existing_category = db.categories.find_one({"name": category_name})
    if existing_category:
        return jsonify({"msg": f"Category '{category_name}' already exists"}), 409

    # Add category to the database
    db.categories.insert_one({"name": category_name})
    return jsonify({"msg": "Category added successfully"}), 201


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
            "$lookup": {
                "from": "products",
                "let": {"productId": {"$toObjectId": "$items.productId"}},  # Convert to ObjectId
                "pipeline": [
                    {"$match": {"$expr": {"$eq": ["$_id", "$$productId"]}}}
                ],
                "as": "productDetails"
            }
        },
        {"$unwind": "$productDetails"},  # Unwind productDetails array
        {
            "$addFields": {  # Calculate profit dynamically
                "items.profitAmount": {
                    "$subtract": ["$items.price", "$productDetails.originalPrice"]
                }
            }
        },
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


@app.route('/order', methods=['POST'])
def add_order():
    data = request.get_json()

    # Ensure that the data contains the required fields
    required_fields = {"customerId", "items", "orderTotal", "status", "orderDate", "createdAt"}
    if not data or not required_fields.issubset(data):
        return jsonify({"msg": "Missing order data"}), 400

    # Structure the order items
    order_items = []
    for item in data["items"]:
        required_item_fields = {"productId", "productName", "category", "salesAmount", "quantitySold", "price",
                                "quantity", "transactionDate"}
        if not required_item_fields.issubset(item):
            return jsonify({"msg": "Incomplete order item data"}), 400

        order_item = {
            "productId": item["productId"],
            "productName": item["productName"],
            "category": item["category"],
            "salesAmount": item["salesAmount"],
            "quantitySold": item["quantitySold"],
            "price": item["price"],
            "quantity": item["quantity"],
            "transactionDate": datetime.utcnow(),
        }
        order_items.append(order_item)

    # Structure the order data
    order_data = {
        "customerId": data["customerId"],
        "items": order_items,
        "orderTotal": data["orderTotal"],
        "status": data["status"],
        "orderDate": datetime.utcnow(),
        "createdAt": datetime.utcnow(),
    }

    # Insert the order into the database
    result = db.order.insert_one(order_data)

    return jsonify({"msg": "Order created successfully", "orderId": str(result.inserted_id)}), 201


def convert_objectid_to_str(data):
    """Recursively convert ObjectId instances to strings."""
    if isinstance(data, dict):
        return {key: convert_objectid_to_str(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_objectid_to_str(item) for item in data]
    elif isinstance(data, ObjectId):
        return str(data)
    return data


@app.route('/order/<string:orderId>', methods=['GET'])
def get_order_details(orderId):
    try:
        # Validate the orderId format
        if not ObjectId.is_valid(orderId):
            return jsonify({"msg": "Invalid order ID format"}), 400

        # Query to find the specific order by orderId
        order = db.order.find_one({"_id": ObjectId(orderId)})

        if not order:
            return jsonify({"msg": "Order not found"}), 404

        # Recursively convert all ObjectId instances to strings
        order = convert_objectid_to_str(order)

        # Return the order details
        return jsonify(order), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/orders/<string:customer_id>', methods=['GET'])
def get_orders_by_customer(customer_id):
    try:
        # Query to find orders for the given customerId and sort by orderDate (descending)
        query_filter = {"customerId": customer_id}
        sort_criteria = [("orderDate", -1)]  # Sort by orderDate in descending order

        # Fetch all orders for the customer, sorted by orderDate
        orders_cursor = db.order.find(query_filter).sort(sort_criteria)
        orders_list = []

        for order in orders_cursor:
            # Convert ObjectId to string
            order["_id"] = str(order["_id"])

            # Convert datetime fields to string format
            if "orderDate" in order and isinstance(order["orderDate"], datetime):
                order["orderDate"] = order["orderDate"].strftime("%a, %d %b %Y")

            if "createdAt" in order and isinstance(order["createdAt"], datetime):
                order["createdAt"] = order["createdAt"].strftime("%a, %d %b %Y")

            # Format datetime fields in items
            for item in order.get("items", []):
                if "transactionDate" in item and isinstance(item["transactionDate"], datetime):
                    item["transactionDate"] = item["transactionDate"].strftime("%a, %d %b %Y")

            orders_list.append(order)

        # Create response with the list of orders
        response = {
            "orders": orders_list
        }

        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    claims = get_jwt()  # Gets the entire JWT, including additional claims

    # Access custom claims
    role = claims.get("role")

    # Check if the current user is an admin
    if role != "admin":
        return jsonify({"msg": "Access denied: Only admins can retrieve users"}), 403

    role = request.args.get('role')
    query = {"role": role}

    fields_required = {
        "_id": 1, "email": 1, "isApproved": 1, "createdAt": 1,"profile": 1
    }

    try:
        users = db.users.find(query, fields_required)

        users_list = []
        for user in users:
            if '_id' in user and isinstance(user['_id'], ObjectId):
                user['id'] = str(user['_id'])  # Convert ObjectId to string
                del user['_id']
            users_list.append(user)

        return jsonify(users_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Endpoint to fetch user profile data by user ID
@app.route('/users/<string:user_id>', methods=['GET'])
@jwt_required()
def get_user_profile(user_id):
    claims = get_jwt()
    current_user_id = claims.get("_id")

    if current_user_id != user_id:
        return jsonify({"msg": "Access denied: You can only access your profile"}), 403

    user = db.users.find_one({"_id": ObjectId(user_id)}, {"password": 0})  # Exclude password for security
    if not user:
        return jsonify({"msg": "User not found"}), 404

    user["_id"] = str(user["_id"])
    return jsonify(user), 200


# Endpoint to update user profile
@app.route('/users/<string:user_id>', methods=['PUT'])
@jwt_required()
def update_user_profile(user_id):
    claims = get_jwt()  # Retrieve the JWT claims

    # Verify that the user is accessing their own profile or is an admin
    current_user_id = claims.get("_id")
    if current_user_id != user_id:
        return jsonify({"msg": "Access denied: You can only update your profile"}), 403

    # Parse the incoming JSON request
    data = request.get_json()
    data["updatedAt"] = datetime.utcnow()

    # Ensure 'password' is not required for updates
    if "password" in data and data["password"]:
        # Hash the password if it's being updated
        data["password"] = bcrypt.hashpw(data["password"].encode('utf-8'), bcrypt.gensalt())
    elif "password" in data:
        # Remove empty password from data to avoid validation errors
        del data["password"]

    # Use $set to update only provided fields
    result = db.users.update_one({"_id": ObjectId(user_id)}, {"$set": data})
    if result.matched_count == 0:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({"msg": "User profile updated successfully"}), 200


@app.route('/users/<user_id>/approve', methods=['PUT'])
@jwt_required()
def approve_user(user_id):
    claims = get_jwt()  # Gets the entire JWT, including additional claims

    # Access custom claims
    role = claims.get("role")

    # Check if the current user is an admin
    if role != "admin":
        return jsonify({"msg": "Access denied: Only admins can approve users"}), 403

    # Check if the user exists
    if not db.users.find_one({"_id": ObjectId(user_id)}):
        return jsonify({"msg": "User not found"}), 404

    # Update the user
    update_data = {
        "isApproved": True
    }

    db.users.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})
    return jsonify({"msg": "User approved successfully"}), 200

# Add activity log
@app.route('/activity-log', methods=['POST'])
@jwt_required()
def log_activity():
    data = request.get_json()
    user_id = get_jwt().get("_id")

    log = {
        "userId": user_id,
        "action": data.get("action"),
        "details": data.get("details"),
        "timestamp": datetime.utcnow(),
        "metadata": data.get("metadata", {})
    }

    db.activity_logs.insert_one(log)
    return jsonify({"msg": "Activity logged successfully"}), 201


# Retrieve all activity logs for admin
@app.route('/activity-log', methods=['GET'])
@jwt_required()
def get_activity_logs():
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"msg": "Access denied: Only admins can access activity logs"}), 403

    logs = list(db.activity_logs.find())
    for log in logs:
        log["_id"] = str(log["_id"])

    return jsonify(logs), 200
  

if __name__ == '__main__':
    # Run the application on all available IPs on port 8888
    app.run(host='0.0.0.0', port=8888)

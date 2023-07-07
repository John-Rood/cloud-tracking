# TODO Create template in sendgrid + link domain ✅
# TODO Add sign up function in main code that allows them to sign up by calling this cloud run ✅
# TODO Test email registration process ✅
# TODO Create credit system by reviewing charges in gcloud plus pinecone ✅
# TODO Count every usage and then deduct from their credits ✅
# TODO Create not_enough_credits function and use it to return url for them to pay me ✅
# TODO Set up payments with Stripe ✅

# User Registration:
# The user submits their details via a POST request to the '/register' endpoint.
# The 'register' function checks if the provided email is already in use and if the email format is valid. 
# If not, it proceeds to generate a unique user_id and API key for the user.
# If so, return message saying "nah bro.."
# User's bucket is created
# User's password is hashed and user details are saved in the 'vv-users' bucket.
# A hashed version of the API key is also saved in the same 'vv-users' bucket but under the user's unique directory '/user_id/apis'.
# Finally, the API key is sent to the user's email.


from flask import Flask, request, jsonify
from flask_cors import CORS
from google.cloud import storage
from datetime import datetime
import hashlib
import time
import json
import uuid
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import urllib.parse

app = Flask(__name__)

cors = CORS(app, resources={r"/register": {"origins": "*", "methods": "POST"}})

storage_client = storage.Client()

EXPECTED_AUTHORIZATION_CODE ='expected_authorization_code'  # Replace this with your expected authorization code


from firebase_admin import credentials, db, initialize_app
# Initialize the app with a service account, granting admin privileges
fb_app = initialize_app(credentials.ApplicationDefault(), {
    'databaseURL': 'https://vectorvault-361ab-default-rtdb.firebaseio.com/'
})

def get_user_data(user):
    # Reference to the root of the database
    ref = db.reference('users')
    # Get a reference to the user with given customer_id
    user_ref = ref.child(user)
    # Get the data
    user_data = user_ref.get()
    return user_data

def save_to_db(user, user_data):
    # Reference to the root of the database
    ref = db.reference()
    # Reference to the user's data
    user_ref = ref.child('users').child(user)
    # Update data for the user
    user_ref.update(user_data)

def save_tag_to_db(user_id, tag_id, tag_data):
    # Reference to the root of the database
    ref = db.reference()
    # Reference to the user's tags data
    tags_ref = ref.child('users').child(user_id).child('tags').child(tag_id)
    # Set data for the tag
    tags_ref.set(tag_data)

def get_user_tags_data(user_id):
    # Reference to the root of the database
    ref = db.reference()
    # Get a reference to the user's tags data
    tags_ref = ref.child(user_id).child('tags')
    # Get the data
    tags_data = tags_ref.get()
    return tags_data

def user_exists(user_id):
    # Reference to the root of the database
    ref = db.reference('users')
    # Get a reference to the user with given user_id
    user_ref = ref.child(user_id)
    # Get the data
    user_data = user_ref.get()
    # Check if user_data exists
    if user_data:
        return True
    else:
        return False

def generate_api_key():
    return str(uuid.uuid4()).replace('-', '_')

def create_hash(api_key):
    return hashlib.sha256(api_key.encode()).hexdigest()

def create_bucket_if_not_exists(user):
    # Check if the bucket exists
    bucket = storage_client.bucket(user)
    if not bucket.exists():
        # If not, create the bucket
        storage_client.create_bucket(user)

def send_email(user_email, api_key):
    # Your data
    dynamic_template_data = {
        'Sender_Name': 'Vector Vault',
        'Sender_Address': '123 Main St',
        'Sender_City': 'San Francisco',
        'Sender_State': 'CA',
        'Sender_Zip': '94101',
        'api_key': api_key,
        'user': user_email
    }
    message = Mail(
        from_email='noreply@vectorvault.io', 
        to_emails=user_email,
        subject='Your Vector Vault API Key')

    # Add the dynamic data
    message.dynamic_template_data = dynamic_template_data
    message.template_id = 'd-5cbe86f323d7400393219a03ec678fdf'  # Your SendGrid Template ID

    try:
        sg = SendGridAPIClient('SendGridAPIKEY')   # Your SendGrid API Key
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e.message)


def upload_to_cloud(user, data, api=None):
    if api:
        # Upload the api to the user's api directory
        bucket = storage_client.bucket('vv-users')
        blob = bucket.blob(f'{user}/apis/{api}')
        blob.upload_from_string(data)
    else:
        # Upload the user data to the user bucket
        bucket = storage_client.bucket('vv-users')
        blob = bucket.blob(f'{user}')
        blob.upload_from_string(data)

def add_user_to_cloud(user_id, first, last, email, password, tags):
    # Create the user's personal bucket
    create_bucket_if_not_exists(user_id)

    new_user = {
        'fname': first,
        'lname': last,
        'email': email,
        'password': create_hash(password),
        'plan': 'free',
        'requests': 0,
        'bytes_uploaded': 0,
        'bytes_total': 0,
        'signup_day': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        'reset_day': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    }
    upload_to_cloud(user_id, json.dumps(new_user))

    # Save the new user data to the database
    save_to_db(user_id, new_user)

    # Save the tags to the database
    for tag in tags:
        save_tag_to_db(user_id, tag['tag'], {'timestamp': tag['timestamp']})
        

@app.route('/register', methods=['POST'])
def register():
    # Check the provided authorization code
    authorization_code = request.headers.get('Authorization')
    if authorization_code != EXPECTED_AUTHORIZATION_CODE:
        return jsonify({"status": "failure", "message": "Invalid authorization code"}), 401

    # Get user details
    first = request.json['first']
    last = request.json['last']
    email = strip_email(request.json['email'])
    password = request.json['password']
    tags = request.json.get('tags', [])

    if good_email(email) == False:
        raise "Provide a valid email"

    # Generate the user_id
    user_id = get_user_id(email)

    # Check whether or not they have signed up before and end registration if so
    if user_exists(user_id):
        return jsonify({"status": "failure", "message": 'User already exists'}), 400

    # Generate api key
    api_key = generate_api_key()

    # Add the user to the cloud
    result = add_user_to_cloud(user_id, first, last, email, password, tags)
    if result:
        return jsonify({"status": "failure", "message": result}), 400

    # Generate the hashed key
    hashed_key = create_hash(api_key)

    # Generate the metadata
    metadata = json.dumps({"created_at": time.time()})

    # Store the hashed key in the user's bucket
    api = f'{hashed_key}'
    upload_to_cloud(user_id, metadata, api)

    # Send the user_id and api_key to the user's email
    send_email(email, api_key)
    return jsonify({"status": "success", "message": "Registration successful. Your API key has been sent to your email"}), 200


@app.route('/generate_new_key', methods=['POST'])
def generate_new_key():
    # Extract user_id and password from request data
    email = strip_email(request.form['email'])
    user_id = get_user_id(email)
    password = request.form['password']
    # Get user data from Firebase
    user_data = get_user_data(user_id)
    if user_data is None:
        return jsonify({"status": "failure", "message": "User not found"}), 404
    # Check if the password is correct
    if create_hash(password) != user_data['password']:
        return jsonify({"status": "failure", "message": "Incorrect password"}), 401
    # Generate new API key
    new_api_key = generate_api_key()
    hashed_key = create_hash(new_api_key)
    # Store the hashed key in the user's bucket
    metadata = json.dumps({"created_at": time.time()})
    api = f'{hashed_key}'
    upload_to_cloud(user_id, metadata, api)
    # Send the new API key to the user's email
    send_email(user_data['email'], new_api_key)
    return jsonify({"status": "success", "message": "New API key generated and sent to your email"}), 200


@app.route('/delete_key', methods=['POST'])
def delete_key():
    # Extract user_id and api_key from request data
    email = strip_email(request.form['email'])
    user_id = get_user_id(email)
    api_key = request.form['api_key']
    # Get user data from Firebase
    user_data = get_user_data(user_id)
    if user_data is None:
        return jsonify({"status": "failure", "message": "User not found"}), 404
    # Check if the API key is correct
    hashed_key = create_hash(api_key)
    try:
        # Delete the hashed key from the user's bucket
        bucket = storage_client.bucket('vv-users')
        blob = bucket.blob(f'{user_id}/apis/{hashed_key}')
        blob.delete()
    except:
        return jsonify({"status": "failure", "message": "Incorrect API key"}), 401

    return jsonify({"status": "success", "message": "API key deleted successfully"}), 200

def get_user_id(input_string):
    return input_string.replace(" ", "").replace("@", "_at_").replace(".", "_dot_").lower() + '_vvclient'

def strip_email(email):
    email = email.replace(" ", "").lower()  # remove any whitespace and lowercases
    local, domain = email.split('@')
    local = local.split('+')[0]
    return local + '@' + domain

def good_email(email):
    bad_domains = [
        'example.com',
        'tempmail.com',
        'mailinator.com',
        'guerrillamail.com',
        '10minutemail.com',
        '20minutemail.com',
        '30minutemail.com',
        'maildrop.cc',
        'trashmail.com',
        'yopmail.com',
        'getnada.com',
        'mytemp.email',
        'spamgourmet.com',
        'mintemail.com',
        'dispostable.com',
        'mailnesia.com',
        'spamgourmet.net',
        'spamgourmet.org',
        'spamex.com',
        'temp-mail.org',
        'mailcatch.com',
        'moakt.com',
        'fakeinbox.com',
        'safetymail.info',
        'tempmail.space',
        'dropmail.me',
        'emailondeck.com',
        'mailforspam.com',
        'tempail.com',
        'mohmal.com',
        'emailtemporar.ro',
        'sharklasers.com',
        'guerrillamailblock.com',
        'pokemail.net',
        'spam4.me',
        'grr.la',
        'burnermail.io',
    ]
    domain = email.split('@')[-1]
    # is the email good?...
    if domain in bad_domains:
        return False
    else:
        return True

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)


# gcloud run deploy vv-register --image gcr.io/vectorvault-361ab/vv-register --region us-central1 --platform managed --allow-unauthenticated 
# gcloud builds submit --config cloudbuild.yaml .

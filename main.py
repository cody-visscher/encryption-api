from google.cloud import kms, storage
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pymysql
import sqlalchemy
import os
import json
import secrets

# Grab database authentication values from environment variables
db_user = os.getenv("DB_USER")
db_pass = os.getenv("DB_PASS")
db_name = os.getenv("DB_NAME")

# Create the connection string/url
database_url = f"mysql+pymysql://{db_user}:{db_pass}@34.45.111.85:3306/{db_name}"
# Create an engine (database interface) for connections to the database
engine = sqlalchemy.create_engine(database_url)

# Function to dispose engine connection so it can be disposed at any point in the process
def dispose_db_connection():
    engine.dispose()
    print("Connection closed.")

project_name = 'visscher-semester-project'
region_name = 'us-central1'
keyring_name = 'visscher-semester-project-keyring'
bucket_name = 'visscher-semester-project-public-keys'

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
    # Receive client data in JSON format
    data = request.get_json()
    # Input validation
    if list(data.keys()) == ['pub_key', 'signature']:
        # PEM string
        new_pub_key = data['pub_key']
        # Convert to bytes from the hex string sent by client
        signature = bytes.fromhex(data['signature'])
        # load public key
        public_key = serialization.load_pem_public_key(new_pub_key.encode())
        try:
            # Pulled from cryptography's documentation: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
            # Listed under header "Signing" - I reuse this code throughout the API
            public_key.verify(
                signature,
                b'vcrypt!!',
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # Generate a new blob name
            # 'a' at the front guarantees it starts with a character (this may not be a requirement)
            # secrets.token_hex generates a random hex string; doesn't require a seed -> 8 is just a random int that I liked, it can be anything < 150
            pub_key_blob_name = 'a'+secrets.token_hex(8)
            # verify the blob name is unique so we are not overwriting another client's public key for authentication
            unique_blob_name = False
            while not unique_blob_name:
                # Following three lines based on: https://stackoverflow.com/questions/13525482/how-to-check-if-file-exists-in-google-cloud-storage
                storage_client = storage.Client(project=project_name)
                bucket = storage_client.bucket(bucket_name)
                stats = storage.Blob(bucket=bucket, name=pub_key_blob_name).exists(storage_client)
                if stats:
                    pub_key_blob_name = 'a'+secrets.token_hex(8)
                else:
                    unique_blob_name = True
            
            # Upload process pulled from Google AI overview
            client = storage.Client(project=project_name)
            bucket = client.get_bucket(bucket_name)
            blob = storage.Blob(pub_key_blob_name, bucket)
            blob.upload_from_string(new_pub_key)

            # Generate a new API key for this user
            new_api_key = secrets.token_hex(16)
            # verify that the api key is unique as it is a primary key of the authentication.request database
            unique_api_key = False
            while not unique_api_key:
                with engine.connect() as connection:
                    # SQL prepared statement using sqlalchemy engine
                    query = sqlalchemy.text("SELECT * FROM request WHERE api_key = :api_key;")
                    params = {'api_key': new_api_key}
                    result = connection.execute(query, params)
                    # Check if the query returned anything
                    if len(result.all()) != 0:
                        new_api_key = secrets.token_hex(16)
                    else:
                        unique_api_key = True
            
            with engine.connect() as connection:
                query = sqlalchemy.text("INSERT INTO request (api_key, pub_key) values(:api_key, :pub_key);")
                params = {
                    "api_key": new_api_key,
                    "pub_key": pub_key_blob_name
                }
                connection.execute(query, params)
                connection.commit()

            # Generate symmetric encryption key to be used for encrypt operations
            private_encryption_key = AESGCM.generate_key(bit_length=128)
            # Encrypt the private key that was generated
            kms_client = kms.KeyManagementServiceClient()
            key_name = kms_client.crypto_key_path(project_name, region_name, keyring_name, 'aes-encryption')
            encrypt_response = kms_client.encrypt(
                request={
                    "name": key_name,
                    "plaintext": private_encryption_key
                }
            )
            encrypted_private_key = encrypt_response.ciphertext.hex()

            # Insert encrypted private key into the MySQL database
            with engine.connect() as connection:
                query = sqlalchemy.text("INSERT INTO private_keys (api_key, private_key) values (:api_key, :private_key);")
                params = {
                    "api_key": new_api_key,
                    "private_key": encrypted_private_key
                }
                connection.execute(query, params)
                connection.commit()

            dispose_db_connection()
            return jsonify(api_key=new_api_key), 200
        except Exception as e:
            # For debugging purposes
            dispose_db_connection()
            return jsonify(error=f"An exception occurred: {e}"), 500
            # TODO return 401
    else:
        dispose_db_connection()
        return 401

@app.route('/generate-token', methods=['POST'])
def generate_token():
    data = request.get_json()
    # Input validation
    if list(data.keys()) == ['api_key']:
        api_key = data['api_key']
        # generate random token
        nonce = os.urandom(12)
        try:
            with engine.connect() as connection:
                # Delete any tokens for this client if they exist - attempting to prevent replay and brute-force attacks
                query = sqlalchemy.text("DELETE FROM tokens WHERE api_key = :api_key;")
                params = {'api_key': api_key}
                connection.execute(query, params)
                connection.commit()
                # insert the new token
                query = sqlalchemy.text("INSERT INTO tokens (api_key, token) values (:api_key, :token);")
                params = {
                    "api_key": api_key,
                    "token": nonce.hex()
                }
                connection.execute(query, params)
                connection.commit()
                # grab the client's public key
                query = sqlalchemy.text("SELECT pub_key FROM request WHERE api_key = :api_key;")
                params = {'api_key': api_key}
                result = connection.execute(query, params)
                pub_key_blob_name = result.fetchone()[0]
            
            # Retrive public_key information from cloud storage
            blob_client = storage.Client(project=project_name)
            bucket = blob_client.get_bucket(bucket_name)
            blob = bucket.get_blob(pub_key_blob_name)
            public_key_data = blob.download_as_string()
            # Convert public_key_data to crytography library rsa public key
            public_key = serialization.load_pem_public_key(public_key_data)
            # Encrypt the token (nonce) for sending to the client
            ciphertext = public_key.encrypt(
                nonce,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Generate and return json to Client
            dispose_db_connection()
            return jsonify(encrypted_token=ciphertext.hex()), 200
        except Exception as e:
            dispose_db_connection()
            return jsonify(error=f"An error occurred: {e}"), 500
    else:
        dispose_db_connection()
        return 401

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    # Input validation
    if list(data.keys()) == ['api_key', 'token', 'file_bytes']:
        try:
            api_key = data['api_key']
            token = data['token']
            file_bytes = bytes.fromhex(data['file_bytes'])

            # Finds the public key's blob name
            with engine.connect() as connection:
                query = sqlalchemy.text("SELECT pub_key FROM request WHERE api_key = :api_key;")
                params = {'api_key': api_key}
                result = connection.execute(query, params)
                pub_key_blob_name = result.fetchone()[0]
                # finds the token associated with the client's api key
                query = sqlalchemy.text("SELECT token FROM tokens WHERE api_key = :api_key;")
                result = connection.execute(query, params)
                original_token = result.fetchone()[0]
                # Remove the token associated with the client's api key
                query = sqlalchemy.text("DELETE FROM tokens WHERE api_key = :api_key;")
                connection.execute(query, params)
                connection.commit()
            
            # Grab the content of the public key blob
            blob_client = storage.Client(project=project_name)
            bucket = blob_client.get_bucket(bucket_name)
            blob = bucket.get_blob(pub_key_blob_name)
            public_key_data = blob.download_as_string()
            # Conver the PEM data to the key
            public_key = serialization.load_pem_public_key(public_key_data)

            # Authenticate - will throw an error if the signature cannot be verified
            public_key.verify(
                bytes.fromhex(token),
                bytes.fromhex(original_token),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            with engine.connect() as connection:
                # Grab the private_key
                query = sqlalchemy.text("SELECT private_key FROM private_keys WHERE api_key = :api_key")
                params = {"api_key": api_key}
                result = connection.execute(query, params)
                encrypted_private_key = result.fetchone()[0]
            
            # Decrypt the private key
            kms_client = kms.KeyManagementServiceClient()
            private_key = kms_client.decrypt(
                request={
                    'name': kms_client.crypto_key_path(project_name, region_name, keyring_name, 'aes-encryption'),
                    'ciphertext': bytes.fromhex(encrypted_private_key)
                }
            ).plaintext

            # Encrypt the file contents
            aes = AESGCM(private_key)
            nonce = os.urandom(12)
            ciphertext = aes.encrypt(
                nonce,
                file_bytes,
                api_key.encode()
            )

            dispose_db_connection()
            return jsonify(content=(nonce+ciphertext).hex()), 200

        except Exception as e:
            dispose_db_connection()
            return jsonify(error=f"An error occurred: {e}"), 500    

    else:
        dispose_db_connection()
        print('Unauthorized')
        return 'Unauthorized', 401

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    # Input validation
    if list(data.keys()) == ['api_key', 'token', 'file_bytes']:
        api_key = data['api_key']
        token = data['token']
        file_bytes = bytes.fromhex(data['file_bytes'])

        try:
            with engine.connect() as connection:
                # Grab the public key
                query = sqlalchemy.text("SELECT pub_key FROM request WHERE api_key = :api_key;")
                params = {'api_key': api_key}
                result = connection.execute(query, params)
                pub_key_blob_name = result.fetchone()[0]
                # Grab the token
                query = sqlalchemy.text("SELECT token FROM tokens WHERE api_key = :api_key;")
                result = connection.execute(query, params)
                original_token = result.fetchone()[0]
                # Delete the token
                query = sqlalchemy.text("DELETE FROM tokens WHERE api_key = :api_key;")
                connection.execute(query, params)
                connection.commit()

            # load the public key from blob storage
            blob_client = storage.Client(project=project_name)
            bucket = blob_client.get_bucket(bucket_name)
            blob = bucket.get_blob(pub_key_blob_name)
            public_key_data = blob.download_as_string()
            # Convert the PEM data to the key
            public_key = serialization.load_pem_public_key(public_key_data)

            # authenticate
            public_key.verify(
                bytes.fromhex(token),
                bytes.fromhex(original_token),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Grab encrypted private key
            with engine.connect() as connection:
                query = sqlalchemy.text("SELECT private_key FROM private_keys WHERE api_key = :api_key;")
                params = {'api_key': api_key}
                result = connection.execute(query, params)
                encrypted_private_key = result.fetchone()[0]
            
            # Decrypt private key
            kms_client = kms.KeyManagementServiceClient()
            private_key = kms_client.decrypt(
                request={
                    'name': kms_client.crypto_key_path(project_name, region_name, keyring_name, 'aes-encryption'),
                    'ciphertext': bytes.fromhex(encrypted_private_key)
                }
            ).plaintext

            # Decrypt the file_bytes
            aes = AESGCM(private_key)
            nonce = file_bytes[:12]
            encrypted_content = file_bytes[12:]
            plaintext = aes.decrypt(
                nonce,
                encrypted_content,
                api_key.encode()
            )

            dispose_db_connection
            return jsonify(content=plaintext.hex()), 200

        except Exception as e:
            dispose_db_connection()
            return jsonify(error=f'An error occurred: {e}'), 500
    else:
        dispose_db_connection()
        return 401
        
if __name__ == "__main__":
    app.run(debug=True)
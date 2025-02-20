import argparse
from getpass import getpass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import json
import os
import requests
import sys

def configure() -> None:
    if os.path.exists('.vcrypt'):
        print('vcrypt is already configured in this directory.')
        sys.exit(0)
    password = getpass('Create password: ')
    verify = getpass('Re-enter password: ')
    if (password != verify):
        print('Passwords do not match.')
        sys.exit(0)
    os.mkdir('.vcrypt')
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    with open('.vcrypt/private.key', 'wb') as file:
        file.write(private_pem)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signature = private_key.sign(
        b'vcrypt!!',
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    url = 'https://encryption-api-80072796207.us-central1.run.app/register'
    data = {
        'pub_key': public_pem.decode(),
        'signature': signature.hex()
    }
    request = requests.post(url, json=data)
    data = request.json()
    with open('.vcrypt/config.json', 'w') as file:
        json.dump(data, file)

def read_configurations():
    password = getpass('Password: ')
    priv_key_file = '.vcrypt/private.key'
    with open(priv_key_file, 'rb') as key_file:
        try:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode()
            )
        except:
            print('Invalid password')
            sys.exit(0)
    with open('.vcrypt/config.json', 'r') as file:
        data = json.load(file)
    return data['api_key'], private_key

def authenticate() -> str:
    api_key, private_key = read_configurations()
    data = {'api_key': api_key}
    url = 'https://encryption-api-80072796207.us-central1.run.app/generate-token'
    request = requests.post(url, json=data)
    response = request.json()
    encrypted_nonce = bytes.fromhex(response['encrypted_token'])
    plain_nonce = private_key.decrypt(
        encrypted_nonce,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    signature = private_key.sign(
        plain_nonce,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex(), api_key

def encrypt(filename: str) -> None:
    signature, api_key = authenticate()
    with open(filename, 'rb') as file:
        file_bytes = file.read().hex()
    data = {
        'api_key': api_key,
        'token': signature,
        'file_bytes': file_bytes
    }
    url = 'https://encryption-api-80072796207.us-central1.run.app/encrypt'
    request = requests.post(url, json=data)
    return_data = request.json()
    encrypted_bytes = bytes.fromhex(return_data['content'])
    with open(f'{filename}.enc', 'wb') as file:
        file.write(encrypted_bytes)

def decrypt(filename: str) -> None:
    signature, api_key = authenticate()
    with open(filename, 'rb') as file:
        file_bytes = file.read().hex()
    data = {
        'api_key': api_key,
        'token': signature,
        'file_bytes': file_bytes
    }
    url = 'https://encryption-api-80072796207.us-central1.run.app/decrypt'
    request = requests.post(url, json=data)
    return_data = request.json()
    if (list(return_data.keys()) == ['error']):
        print(return_data['error'])
        sys.exit(0)
    decrypted_bytes = bytes.fromhex(return_data['content'])
    with open(f'{filename}.dec', 'wb') as file:
        file.write(decrypted_bytes)
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Arguments')
    operations = parser.add_subparsers(dest='command', required=True)

    configure_parser = operations.add_parser('configure', help='Configure a new account. Do not use if you have already configured an account in the current directory.')

    encrypt_parser = operations.add_parser('encrypt', help='Encrypt a file.')
    encrypt_parser.add_argument('-f', '--file', required=True, type=str, action='store', help='Specify the file that you would like to encrypt')

    decrypt_parser = operations.add_parser('decrypt', help='Decrypt a file.')
    decrypt_parser.add_argument('-f', '--file', required=True, type=str, action='store', help='Specify the file that you would like to decrypt')

    args = parser.parse_args()

    if args.command == 'configure':
        configure()
    elif args.command == 'encrypt':
        filename = args.file
        encrypt(filename)
    elif args.command == 'decrypt':
        filename = args.file
        decrypt(filename)
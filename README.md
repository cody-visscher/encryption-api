# encryption-api

## Building The API

<p>
  When I originally started on this project, I built the API using a combination of GCP Services including Cloud Run, Cloud SQL, Cloud KMS, and Cloud Storage. This project still contains references to these resources, but they no longer exist and never contained any sensitive data.
</p>

## How does the API work?

My goal in creating this API was to come up with a solution that would perform encryption and decryption operations without ever exposing the symmetric AES key to the client. This is intended to solve the issue of how to store encryption and decryption keys.

To use the API, you must have the client program, **vcrypt.py** installed on the device containing the files that you would like to encrypt. For more instructions on how to use vcrypt.py, you can run the following commands:
- Windows: python vcrypt.py -h
- Linux: python3 vcrypt.py -h


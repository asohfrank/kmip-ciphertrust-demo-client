# KMIP Client for Basic Key Management and File Encryption

This KMIP client based on pykmip enables a simple demo where, an AES-256 key is securely created via a KMIP server (CipherTrust Manager) and used to test file encryption/decryption.
On every startup, the program automatically creates key if not exist and encrypts file if not encrypted.

## Features

- **Key Management**:
  - Automatically checks if a key exists using its UID.
  - Creates and activates keys if not already present.
  - Supports revocation and destruction of keys, with proper error handling for active keys.

- **File Encryption and Decryption**:
  - Encrypts files using AES-256 in CBC mode, securely padding data to fit block sizes.
  - Decrypts files, validating the padding and ensuring data integrity.
  - Detects if a file is already encrypted to avoid re-encryption.
  - Provides informative error messages if a decryption attempt fails.

- **Dynamic Key Cache**:
  - Caches the cryptographic key locally during runtime to minimize KMIP server requests.
  - Allows clearing of the key cache for security testing purposes.

- **Interactive Menu**:
  - User-friendly menu system for managing keys, encrypting/decrypting files, and exiting the program.
  - Includes clear prompts and detailed instructions for actions like revocation reasons and date inputs.

## Getting Started

### Prerequisites

- Python ***3.7.9*** (later versions have a wrap_socket issue as a result of some changes that our dependent library kmip hasnt be updated to)
- Required libraries:
  - `pykmip`
  - `cryptography`
  - `configparser`

Install the required libraries using pip:

```bash
pip install pykmip cryptography configparser
```

### Configuration

1. Create a CipherTrust KMIP interface with the approriate SSL configuration (default mode is : TLS, verify client cert, user name taken from client cert, auth request is optional)
2. Create a client certificate keypair (the CN if the certificate should match the username of CipherTrust Manager you want to authenticate to)
3. Download the CipherTrust CA cert
4. Create a conf/pykmip.conf file with the following structure:

```
[client]
host = <KMIP server address, this is your CipherTrust Manager or any other KMIP compliant server>
port = <KMIP server port, this is your KMIP interface on CipherTrust Manager>
certfile = <Path to client certificate>
keyfile = <Path to client key>
ca_certs = <Path to CA certificate>
cert_reqs = CERT_REQUIRED
ssl_version = PROTOCOL_TLSv1_2
do_handshake_on_connect = True
suppress_ragged_eofs = True
key_name = PythonAESKMIPKey <This is the name of the existing key (or key to be created) on CipherTrust Manager>
key_uid = <UID of the key to manage, if the key UID does not exist on CipherTrust Manager, a new key will be automatically created and this file will be updated with new UID>
username = <use only if ssl mode is set to : TLS, verify client cert, password is needed, user name in cert must match user name in authentication request>
password = <use only if ssl mode is set to : TLS, verify client cert, password is needed, user name in cert must match user name in authentication request>
```
2. Create a data/confidential.txt file for testing encryption and decryption (dummy data in file).

### Usage

Run the script:
```
python KMIPclient.py
```

**Follow the on-screen menu to:**

- Clear Key Cache
- Read & Decrypt file in memory
- Decrypt File (Write as plaintext)
- Manage Key (revoke/destroy)
- Close Connection and Exit
  
### Error Handling

**Active Key Destruction:**

If an attempt to destroy an active key is made, the program automatically redirects the user to revoke the key first.

**Decryption Errors:**

If a file decryption fails due to invalid padding, the program informs the user that the file may be corrupted or encrypted with a missing key.

### Directory Structure
```
.
├── conf/
│   └── pykmip.conf         # Configuration file for KMIP client
├── data/
│   └── confidential.txt    # File for testing encryption and decryption
├── KMIPclient.py           # Main script
├── README.md               # Project documentation
```


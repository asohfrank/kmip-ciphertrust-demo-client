import os
import base64
import configparser
from kmip.pie import client
from kmip import enums
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import warnings
import time
from datetime import datetime
from kmip.core.factories import attributes

# Suppress warning about 32-bit Python
warnings.filterwarnings("ignore", category=UserWarning, module='cryptography')

# Paths
CONFIG_FILE = os.path.expanduser("conf/pykmip.conf")
DATA_FILE = os.path.expanduser("data/confidential.txt")

# Globals
gconfig = None
cached_key = None
kmip_client = None

def load_config():
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    client_config = {
        "host": config.get("client", "host"),
        "port": config.getint("client", "port"),
        "certfile": config.get("client", "certfile"),
        "keyfile": config.get("client", "keyfile"),
        "ca_certs": config.get("client", "ca_certs"),
        "cert_reqs": config.get("client", "cert_reqs"),
        "ssl_version": config.get("client", "ssl_version"),
        "do_handshake_on_connect": config.getboolean("client", "do_handshake_on_connect"),
        "suppress_ragged_eofs": config.getboolean("client", "suppress_ragged_eofs"),
        "key_name": config.get("client", "key_name"),  # Load Key_Name from config
        "key_uid": config.get("client", "Key_UID"),  # Load Key_UID from config
    }
    return client_config


def init_kmip_client():
    global kmip_client
    global gconfig 
    gconfig = load_config()
    kmip_client = client.ProxyKmipClient(config_file=CONFIG_FILE)
    kmip_client.open()

def get_keyUID_ByName():
    f = attributes.AttributeFactory()
    keyuid = kmip_client.locate(
        attributes=[
            f.create_attribute(
                enums.AttributeType.NAME,   
                gconfig["key_name"]                     
            )
        ]
    )
    if keyuid:
        return keyuid[0]
    else:
        return None

def KeyExists():
    global cached_key
    global gconfig
    key_uid = gconfig["key_uid"]
    key_name = gconfig["key_name"]

    # Attempt to fetch the key using the UID
    try:
        print(f"\nAttempting to fetch key with UID: {key_uid}")
        key = kmip_client.get(key_uid)
        cached_key = key.value  # Cache the key bytes
        print(f"\nKey with UID {key_uid} fetched and cached successfully.\n")
        return True
    except Exception as e:
        if "ITEM_NOT_FOUND" in str(e):
            print(f"\nKey with UID {key_uid} not found. Attempting to fetch by name {key_name}.\n")
            searchedkeyUID = get_keyUID_ByName()
            if searchedkeyUID:
                key = kmip_client.get(searchedkeyUID)
                cached_key = key.value
                # Update the Key_UID in the configuration file
                config = configparser.ConfigParser()
                config.read(CONFIG_FILE)
                config.set("client", "Key_UID", searchedkeyUID)
                with open(CONFIG_FILE, "w") as configfile:
                        config.write(configfile)
                        print(f"\nKey_UID {searchedkeyUID} updated in configuration file.\n")
                #reload config
                
                gconfig = load_config()
                return True  
            else: 
                print(f"Key does not exist with UID {key_uid}")
                return False       
        else:
            print(f"Key does not exist with UID {key_uid}: {e}")
            return False

def activate_key():
    key_uid = gconfig["key_uid"]
    try:
        print(f"\nActivating key: {key_uid} from Pre-Active - Active State")
        kmip_client.activate(key_uid)
        print("\nKey activation successful")
    except Exception as e:
        print(f"Error activating key: {e}")

def create_key():
    global cached_key
    global gconfig
    key_name = gconfig["key_name"]
    if not key_name:
        key_name = "PythonAESKMIPKey"  # Hardcoded name for the key
    try:
        key_uid = kmip_client.create(
            enums.CryptographicAlgorithm.AES,
            256,
            name=key_name,
            cryptographic_usage_mask=[
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT
            ]
        )
        print(f"\nCreated new AES256 key with UID: {key_uid}")

        # Add key to cache 
        key = kmip_client.get(key_uid)
        cached_key = key.value  # Cache the key bytes
        # Update the Key_UID in the configuration file
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        config.set("client", "Key_UID", key_uid)
        with open(CONFIG_FILE, "w") as configfile:
            config.write(configfile)
        #reload config
        
        gconfig = load_config()
        print(f"\nKey_UID {key_uid} saved to configuration file.")

        activate_key()  # Activate key   
        
    except Exception as e:
        print(f"Error creating key: {e}")
        raise e


def encrypt_file():
    if not os.path.exists(DATA_FILE):
        print(f"{DATA_FILE} not found!")
        return

    with open(DATA_FILE, "rb") as f:
        file_content = f.read()

    # Check if the file has been encrypted (simple header check)
    if file_content.startswith(b"ENCRYPTED"):
        print(f"\nFile {DATA_FILE} already encrypted.")
        return

    # Encrypt the file content
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(cached_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_content) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(DATA_FILE, "wb") as f:
        f.write(b"ENCRYPTED" + iv + ciphertext)

    print(f"File {DATA_FILE} encrypted.")


def decrypt_file():
    try:
        with open(DATA_FILE, "rb") as f:
            file_content = f.read()

        if not file_content.startswith(b"ENCRYPTED"):
            print("File is not encrypted.")
            return

        iv = file_content[9:25]
        ciphertext = file_content[25:]

        cipher = Cipher(algorithms.AES(cached_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
        print("\n********************************************************")
        print("\t\tDecrypted Content")
        print("********************************************************\n")
        print(plaintext.decode())
    except Exception as e:
        if "Invalid padding bytes" in str(e):
            print("\nError: The file is either corrupted or it was encrypted with a key that no longer exists on CipherTrust Manager.\n")
        else:
            print(f"Error: {e}")

def clear_key_cache():
    global cached_key
    cached_key = None
    print("\nKey cache cleared.\n")


def manage_key(action):
    key_uid = gconfig["key_uid"]
    
    if action == "1":  # Revoke Key
        # Prompt for revocation reason
        print("\n--- Revocation Reasons ---")
        print("1. CESSATION_OF_OPERATION")
        print("2. KEY_COMPROMISE")
        print("3. AFFILIATION_CHANGED")
        print("4. SUPERSCEDING_KEY")
        reason = input("\nSelect the reason for revocation (1-4): ")

        reason_map = {
            "1": enums.RevocationReasonCode.CESSATION_OF_OPERATION,
            "2": enums.RevocationReasonCode.KEY_COMPROMISE,
            "3": enums.RevocationReasonCode.AFFILIATION_CHANGED,
            "4": enums.RevocationReasonCode.SUPERSEDED
        }

        if reason in reason_map:
            selected_reason = reason_map[reason]

            # If KEY_COMPROMISE, prompt for compromise occurrence date
            if selected_reason == enums.RevocationReasonCode.KEY_COMPROMISE:
                date_str = input("Enter compromise occurrence date (YYYY-MM-DD): ")
                try:
                    # Convert the date string to a Unix timestamp (integer)
                    compromise_date = datetime.strptime(date_str, "%Y-%m-%d")
                    timestamp = int(time.mktime(compromise_date.timetuple()))
                    kmip_client.revoke(selected_reason, key_uid, compromise_occurrence_date=timestamp)
                    print(f"\nKey with UID {key_uid} has been revoked for reason: {selected_reason.name}.")
                except ValueError:
                    print("\nInvalid date format. Revocation aborted.")
            else:
                kmip_client.revoke(selected_reason, key_uid)
                print(f"\nKey with UID {key_uid} has been revoked for reason: {selected_reason.name}.")
        else:
            print("\nInvalid reason selected. Revocation aborted.")

    elif action == "2":  # Destroy Key
        try:
            kmip_client.destroy(key_uid)
            print(f"\nKey with UID {key_uid} has been destroyed.")
        except Exception as e:
            if "PERMISSION_DENIED" in str(e):
                print("\nError: Key is in an active state and cannot be destroyed. Redirecting to revoke the key first.")
                manage_key("1")  # Automatically prompt for revocation
            else:
                print(f"\nError destroying key: {e}")


def menu():
    while True:
        print("\n------------ KMIP Client Menu ------------")
        print("1. Clear Key Cache")
        print("2. Read & Decrypt File")
        print("3. Manage Key (revoke/destroy)")
        print("4. Close Connection and Exit")
        choice = input("\nEnter your choice: ")

        if choice == "1":
            clear_key_cache()
        elif choice == "2":
            if cached_key is None:
                if KeyExists():
                    print("\n********************************************************")
                    print("\t\tEncrypted content from file")
                    print("********************************************************\n")
                    with open(DATA_FILE, 'rb') as file:
                        print(base64.b64encode(file.read()).decode())
                    decrypt_file()
                else:
                    print("\n Unable to decrypt file")
                    break
        elif choice == "3":
            if cached_key is None:
                KeyExists()
            print("\n--- Manage Key ---")
            print("1. Revoke Key")
            print("2. Destroy Key (must revoke before destroy)")
            action = input("\nSelect action (1-2): ")
            if action in ["1", "2"]:
                manage_key(action)
            else:
                print("\nInvalid selection!")
        elif choice == "4":
            clear_key_cache()
            kmip_client.close()
            print("\nConnection closed. Exiting.")
            break
        else:
            print("\nInvalid choice! Please try again.")

if __name__ == "__main__":
    try:
        init_kmip_client()
        if not KeyExists():
             create_key()
        encrypt_file()  # Encrypt the file if necessary
        menu()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if kmip_client is not None:
            kmip_client.close()
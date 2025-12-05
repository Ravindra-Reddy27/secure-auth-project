import base64
from subprocess import run, PIPE
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Helper Functions (as specified) ---

def sign_message(message: str, private_key: rsa.RSAPrivateNumbers) -> bytes:
    """
    Sign a message using RSA-PSS with SHA-256
    """
    # CRITICAL: Sign the ASCII string, NOT binary hex!
    message_bytes = message.encode('utf-8')
    
    signer = private_key.public_key().key_size
    
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            # Salt Length: Maximum (PSS.MAX_LENGTH)
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def encrypt_with_public_key(data: bytes, public_key: rsa.RSAPublicNumbers) -> bytes:
    """
    Encrypt data using RSA/OAEP with public key
    """
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# --- Main Proof Generation Logic ---

def generate_commit_proof(student_priv_path: str, instructor_pub_path: str) -> dict:
    # 1. Get current commit hash
    print("1. Getting current commit hash...")
    try:
        # Execute 'git log -1 --format=%H'
        result = run(['git', 'log', '-1', '--format=%H'], capture_output=True, text=True, check=True)
        commit_hash = result.stdout.strip()
        if len(commit_hash) != 40:
             raise ValueError("Commit hash is not 40 characters long.")
        print(f"   -> Commit Hash: {commit_hash}")
    except Exception as e:
        print(f"   -> ERROR getting commit hash. Ensure you are in a Git repository and have committed changes.")
        raise e

    # 2. Load student private key
    print("2. Loading student private key...")
    with open(student_priv_path, "rb") as key_file:
        student_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None, # Assuming no password
            backend=default_backend()
        )

    # 3. Sign commit hash with student private key
    print("3. Signing commit hash with student private key (RSA-PSS-SHA256)...")
    # The sign method requires the key to be an instance of RSAPrivateKey, not RSAPrivateNumbers
    # We'll rely on load_pem_private_key returning the correct type.
    signature_bytes = sign_message(commit_hash, student_private_key)
    
    print(f"   -> Signature Length: {len(signature_bytes)} bytes")


    # 4. Load instructor public key
    print("4. Loading instructor public key...")
    with open(instructor_pub_path, "rb") as key_file:
        instructor_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # 5. Encrypt signature with instructor public key
    print("5. Encrypting signature with instructor public key (RSA/OAEP-SHA256)...")
    encrypted_signature = encrypt_with_public_key(signature_bytes, instructor_public_key)
    print(f"   -> Encrypted Signature Length: {len(encrypted_signature)} bytes")


    # 6. Base64 encode encrypted signature
    print("6. Base64 encoding encrypted signature...")
    # Base64 encode the binary bytes
    base64_encoded = base64.b64encode(encrypted_signature)
    # Decode to a string (single line) for final output
    base64_string = base64_encoded.decode('utf-8')

    return {
        "Commit Hash": commit_hash,
        "Encrypted Signature": base64_string
    }

if __name__ == "__main__":
    # --- Configuration ---
    STUDENT_PRIVATE_KEY_FILE = "student_private.pem"
    INSTRUCTOR_PUBLIC_KEY_FILE = "instructor_public.pem"
    # ---------------------

    try:
        # NOTE: Commit all code to Git BEFORE running this script!
        print("--- STARTING PROOF GENERATION ---")
        proof = generate_commit_proof(STUDENT_PRIVATE_KEY_FILE, INSTRUCTOR_PUBLIC_KEY_FILE)
        
        print("\n--- FINAL OUTPUT ---")
        print(f"Commit Hash: {proof['Commit Hash']}")
        print(f"Encrypted Signature: {proof['Encrypted Signature']}")
        print("--------------------")
        
    except FileNotFoundError as e:
        print(f"\n[FATAL ERROR] Key file not found: {e.filename}")
        print("Make sure 'student_private.pem' and 'instructor_public.pem' are in the same directory.")
    except Exception as e:
        print(f"\n[FATAL ERROR] An unexpected error occurred: {e}")
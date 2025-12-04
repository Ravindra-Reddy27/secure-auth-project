from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair(key_size: int = 4096):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # Serialize private key (PEM format)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Generate public key
    public_key = private_key.public_key()

    # Serialize public key (PEM format)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


if __name__ == "__main__":
    private, public = generate_rsa_keypair()

    with open("student_private.pem", "wb") as f:
        f.write(private)

    with open("student_public.pem", "wb") as f:
        f.write(public)

    print("Keys generated:")
    print("student_private.pem")
    print("student_public.pem")
 
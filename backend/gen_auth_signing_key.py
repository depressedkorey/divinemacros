from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64


private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

private_raw = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
public_raw = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)

print("AUTH_RESPONSE_SIGNING_KEY=" + base64.b64encode(private_raw).decode("ascii"))
print("AUTH_RESPONSE_PUBLIC_KEY=" + base64.b64encode(public_raw).decode("ascii"))

import time
import requests
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509

# Define the API endpoint
url = "https://cwmsica01.cwlabs.xyz:8443/api/cert/enroll"

# Load CSR from a file or static string
csr = "MIIDYjCCAkoCAQAwHTEbMBkGA1UEAwwSdGVzdEFQSS5jd2xhYnMueHl6MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtJFzUNViEw0C2SweXRhKDr3Q9hlbSLaUgEWDIuROLzlcQDf2qYhZ6hLJW5h8DfuNi1E9nDn0dYHT5Ygq3Rr9rkLDYKEV6H6e3m0IFXwgduF1vDhEda6LGnJrioitg8/Kl0CcpUlzwRMZDYoaHNsMtt4KZWFSq70I9n3EXVAe6GpZ185wUWSrfFLIL0Sda4hovmc3f/hhMihNhPgVreHdO8c+BSHztVFZEaL1lNe/bFXnxzUDVXj0vU+chQTAdGLgMDe7GIQTezBTj1rW9Fg0aHt8ek0HvZ/GFKmp7PNHob9/DuYU10ILd3huKUxkxTQhDBL5MabHQL7x5XYKZStyjQIDAQABoIH/MBwGCisGAQQBgjcNAgMxDhYMMTAuMC4yMDM0OC4yMC4GCSqGSIb3DQEJDjEhMB8wHQYDVR0OBBYEFPaAlI5DRNyUTreicMmi1Y6+Td/fMEcGCSsGAQQBgjcVFDE6MDgCAQUMFGN3bXNpY2EwMS5jd2xhYnMueHl6DBRDV0xBQlNcYWRtaW5pc3RyYXRvcgwHTU1DLkVYRTBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBAQADfflULGK5QAxoxczWxBBk2rUEszGb/sVvLADbRwxZBTF999UViKl9WLcOsaAKYXoHUPa6f5G+6jBfK7iM6d/PZQaltyOe59ZC+UFi6nCr6qionq30kMZodlZ1AxA/q6wxxbuWxCQLLUO3bPN4gg2qQHgk/gIuj0wRHkNgWZ28D1bglco4pb3Vtb19Dx/I9ubPTzUZwbKd3GNnzBGMUBFwEirfAjJCDBGA/BIoiwW3byODEb/BO7pBz3zCXP4QmqUaJrEa+mscEzOohiE9tJRAo901PZFEFaXaqsyb6DPTk6oZM9Sq1eYpx+5L5YwZ6uaWvKMhcdRBBrQbVsmQFIAW"  # Replace with your actual CSR

# Load the private key from a file
private_key_path = "/var/www/acme2certifier/acme_srv/private-key.pem"
with open(private_key_path, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Define the data to sign (can be any string that the server expects to verify authenticity)
#data_to_sign = "string"  # Replace with the specific data the server expects to validate

# Get the current time in UTC as epoch time (in seconds)
epoch_time = int(time.time())

# Convert the epoch time to a string
data_to_sign = str(epoch_time)

# Sign the data
data_to_sign_bytes = data_to_sign.encode("utf-8")
signed_data = private_key.sign(
    data_to_sign_bytes,
    padding.PKCS1v15(),
    hashes.SHA256()
)

# Encode the signed data in Base64 for the API
signed_data_base64 = base64.b64encode(signed_data).decode("utf-8")

# Load the client certificate and retrieve its thumbprint
cert_path = "/var/www/acme2certifier/acme_srv/signingCert.pem"
with open(cert_path, "rb") as cert_file:
    cert_data = cert_file.read()

# Parse the certificate using cryptography
cert = x509.load_pem_x509_certificate(cert_data, default_backend())

# Export certificate in DER format using serialization.Encoding.DER
der_cert_data = cert.public_bytes(serialization.Encoding.DER)

# Calculate the SHA-1 hash (thumbprint) of the DER-encoded certificate
cert_thumbprint = hashlib.sha1(der_cert_data).hexdigest().upper()
# Calculate the thumbprint (SHA-1) of the certificate
#cert_thumbprint = hashlib.sha1(cert_data).hexdigest().upper()

# Create the JSON payload for the request
payload = {
    "csr": csr,
    "includeChain": False,
    "dataToSign": data_to_sign,
    "signedData": signed_data_base64,
    "certThumbprint": cert_thumbprint
}

print(payload)

# Send the POST request to the API
headers = {"Content-Type": "application/json"}
response = requests.post(url, json=payload, headers=headers)

# Print the response from the server
if response.status_code == 200:
    print("Certificate Enrolled Successfully:")
    print(response.json()["certificate"])
else:
    print(f"Error: {response.status_code}")
    print(response.text)
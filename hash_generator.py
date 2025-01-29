import hashlib

# Your security key
security_key = "8BvoQAgHsGfyboEKUN-x4kzi5jEnRFmrSQm-OMC_coQ="

# Generate hash
access_hash = hashlib.sha256(security_key.encode()).hexdigest()

# Display results
print("Your ACCESS_HASH is:")
print(access_hash)
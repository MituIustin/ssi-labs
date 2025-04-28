import secrets
import string
import hmac
import bcrypt

def generate_password(length=10): 
    alphabet_lower = string.ascii_lowercase
    alphabet_upper = string.ascii_uppercase
    digits = string.digits
    special_characters = '.!$@'
    
    password = [
        secrets.choice(alphabet_lower),
        secrets.choice(alphabet_upper),
        secrets.choice(digits),
        secrets.choice(special_characters)
    ]
    
    all_characters = alphabet_lower + alphabet_upper + digits + special_characters
    password += [secrets.choice(all_characters) for _ in range(length - 4)]
    
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

def generate_url_safe_string(length=32):
    return secrets.token_urlsafe(length)

def generate_hex_token(length=32):
    return secrets.token_hex(length)

def secure_compare(val1, val2):
    return hmac.compare_digest(val1, val2)

def generate_binary_key(length=32):
    return secrets.token_bytes(length)



def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

def check_password(stored_hash, password):
    return bcrypt.checkpw(password.encode(), stored_hash)

password = generate_password(12)
print(f"generated password: {password}")

url_safe_string = generate_url_safe_string()
print(f"url safe: {url_safe_string}")

hex_token = generate_hex_token()
print(f"hex token: {hex_token}")

secret1 = "parola1"
secret2 = "parola1"
result = secure_compare(secret1, secret2)
print(f"password1 == password2 ? {result}")

binary_key = generate_binary_key()
print(f"binary key : {binary_key}")




password = "password"
hashed_password = hash_password(password)
print(f"hash {hashed_password}")

equals = check_password(hashed_password, "password")
print(f"correct password ? {equals}")



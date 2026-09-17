import os
import subprocess
import pickle
import hashlib

SECRET_KEY = "super-secret-token-abcdef1234567890"

def get_user(cursor, user_id):
    # SQL Injection
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")

def run_command(user_cmd):
    # Command Injection
    subprocess.Popen(user_cmd, shell=True)

def load_session(untrusted_payload):
    # Insecure Deserialization
    return pickle.loads(untrusted_payload)

def hash_password(password):
    # Weak Cryptography
    return hashlib.md5(password.encode()).hexdigest()

def read_file(user_path):
    # Path Traversal
    return open(f"/var/data/{user_path}").read()

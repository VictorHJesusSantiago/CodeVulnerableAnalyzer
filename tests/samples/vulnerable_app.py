"""Sample vulnerable Python application for testing the analyzer."""
import subprocess
import pickle
import hashlib
import random
import yaml
import sqlite3

SECRET_KEY = "super_secret_key_12345"
API_KEY = "apikey=sk-abcdef1234567890abcdef1234567890"
DB_PASSWORD = "password=MyHardcodedPass!2024"

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def run_command(cmd):
    result = subprocess.run(cmd, shell=True)
    return result

def load_data(data_bytes):
    return pickle.loads(data_bytes)

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    return str(random.randint(100000, 999999))

def load_config(config_str):
    return yaml.load(config_str)

def get_file(filename):
    with open(f"/var/www/uploads/{filename}") as f:
        return f.read()

def evaluate_expression(expr):
    return eval(expr)

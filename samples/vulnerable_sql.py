import os
import sqlite3

# VULNERABILITY 1: Hardcoded AWS Credentials
AWS_ACCESS_KEY = "AKIA1111222233334444"

# VULNERABILITY 2: Hardcoded OpenAI API Key
OPENAI_KEY = "sk-abcdef1234567890abcdef1234567890"

# VULNERABILITY 3: Active Debug Code in Production
debug = True


def get_user_profile(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # VULNERABILITY 4: SQL Injection via f-string interpolation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    try:
        data = cursor.fetchone()
        return data
    except:
        # VULNERABILITY 5: Silent Exception Swallowing
        pass


def execute_diagnostic(ping_target):
    # VULNERABILITY 6: Dangerous Command Injection via os.system
    os.system(f"ping -c 1 {ping_target}")

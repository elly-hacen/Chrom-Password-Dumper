# Passwords Extraction Tool for Google Chrome 🔑

This Python script is a tool that can be used to extract saved login credentials from Google Chrome's SQLite database file and decrypt the encrypted passwords using the user's encryption key.

## Prerequisites

- Python 3.x
- Required Python module: `pycryptodome==3.17`

You can install the module using pip: `pip install -r requirements.txt`

## Usage

1. Download the repo `https://github.com/elly-hacen/chrome-password-dumper.git`
2. Run the script in a Python environment (e.g. command prompt, terminal) using the command: `python chrome.py`
3. The script will generate a file named `temp.txt` in the same directory where the program executed.
4. The `temp.txt` file will contain the origin URL, username, password, and creation date for each saved login credential.

## Important Note 🚨

Using this tool to access other people's saved login credentials without their consent is unethical and potentially illegal. This tool should only be used for password management and recovery purposes for the user's own saved login credentials.
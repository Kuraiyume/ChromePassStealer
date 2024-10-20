# ChromePassStealer

The **Chrome Pass Stealer** script is designed to retrieve and decrypt saved passwords from Google Chrome's login database. It utilizes the Windows Data Protection API (DPAPI) to extract and decrypt the encryption key used to protect the saved passwords. The script demonstrates the use of SQLite to access the Chrome login database and AES encryption for decrypting the passwords.

## Prerequisites
To run this script, ensure that you have the following dependencies installed:

- Python 3.x
- PyCryptodome
- pyWin32

## Usage
- Clone the repository
- Install the required libraries
- Run the script

## Important Notes
- This script exploits existing weaknesses in the Chrome password management system. It should only be used in a controlled environment for ethical hacking purposes, such as security testing with proper authorization.
- Ensure you have access to a Windows environment where Chrome is installed and that you have permission to access the user's data.

## Author
- Kuraiyume (A1SBERG)

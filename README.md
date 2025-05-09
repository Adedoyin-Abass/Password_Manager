# Secure Password_Manager
A Password Manager i made using python and cryprography libraries to securely store and generate passwors.

Key Features
1. Password generation with customizable length.
2. Password storage for both the website domain name and password using Fernet keys.
3. Password retrieval
5. RSA key pair generation for encryption of the Fernet keys.
7. User-friendly menu-driven interface.
8. Master password -> PBKDF2HMAC -> Derived key -> Decrypt encrypted Fernet key (using RSA private key) -> Fernet key -> Decrypt password data

![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/Final%20Result.png)

Installation
To run this project, you'll need to install the following dependecies:
  1. Cryptography library
     I used zsh, so you use pip install cryptography. You can use it bash too or any other linux shell
  2. Python
     To run this on linux, you should use the script sudo apt install python3
     To run on macOS use brew install python

How It Works
1. Derives a key from Master Password using PBKDF2, which is hashed by HMAC
2. Encrypts Password with fernet, stores it in a file and salts it.
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/01.png)
3. Generates RSA key pair to securely exchange Fernet key
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/02.png)
4. Encrypts Fernet Key using RSA public key
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/03.png)
5. Retrieves passwords by decrypting the stored data using the master key
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/04.png)
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/05.png)
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/06.png)
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/07.png)

Usage
1. Run the script and enter your master password
2. Choose to add a new password or retrieve an existing one
3. Follow the prompts to generate or enter new password

Security Measures
1. Uses Fernet symmetric encryption for password storage
2. RSA key pair for encrypting Fernet keys
4. Salt generation for added security

Requirements
Python and Cryptography Library

Limitations 
Please note that this password manager is a simple project and not a production-ready solution. It's not recommended to use this for storing sensitive information in a real-world scenario, as it lacks the complexity and robustness of established password managers.

Takeaway: This project demonstrates the potential of cryptography in building secure applications. I'm proud to have completed it, and I'm excited to continue exploring the world of cybersecurity.

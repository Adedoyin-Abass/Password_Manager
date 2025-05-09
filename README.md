# Secure Password_Manager
A Password Manager i made using python and cryprography libraries to securely store and generate passwors.

Key Features
1. Password generation with customizable length.
2. Password storage for both the website domain name and password using Fernet keys.
3. Password retrieval, and using the master password to derive the key through PBKDF2HMAC which hashes the derived key and encrypts it and sends it to Fernet.
4. RSA key pair generation for encryption of the Fernet keys.
5. At a point, I wanted to add a challenge-based MFA, but I decided to keep it simple and keep the creation timeframe to 24 hours.
6. User-friendly menu-driven interface.

![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/Final%20Result.png)

How It Works
1. Derives a key from Master Password using PBKDF2, which is hashed by HMAC
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/1.png)
2. Encrypts Password with fernet, stores it in a file and salts it.
3. Generates RSA key pair to securely exchange Fernet key
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/2.png)
4. Encrypts Fernet Key using RSA public key
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/3.png)
5. Retrieves passwords by decrypting the stored data using the master key
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/4.png)
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/5.png)
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/6.png)
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/7.png)
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/8.png)


Usage
1. Run the script and enter your master password
2. Choose to add a new password or retrieve an existing one
3. Follow the prompts to generate or enter new password

Security Measures
1. Uses Fernet symmetric encryption for password storage
2. RSA key pair for encrypting Fernet keys
3. PBKDF2 key derivation for password protection
4. Salt generation for added security

Requirements
Pythin and Cryptography Library

Limitations 
Please note that this password manager is a simple project and not a production-ready solution. It's not recommended to use this for storing sensitive information in a real-world scenario, as it lacks the complexity and robustness of established password managers.

Takeaway: This project demonstrates the potential of cryptography in building secure applications. I'm proud to have completed it, and I'm excited to continue exploring the world of cybersecurity.

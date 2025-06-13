# Secure Password_Manager
A Password Manager i made using python and cryprography libraries to securely store and generate passwors.

## Key Features
1. Password generation with customizable length.
2. Password storage for both the website domain name and password using Fernet keys.
3. Password retrieval
5. RSA key pair generation for encryption of the Fernet keys.
7. User-friendly menu-driven interface.
8. `Master password` -> `PBKDF2HMAC` -> `Derived key` -> `Decrypt encrypted Fernet key (using RSA private key)` -> `Fernet key` -> `Decrypt password data`

![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/Final%20Result.png)

## Installation
To run this project, you'll need to install the following dependencies:
  1. Python:
     To run this on `Linux`, you should use the script `sudo apt install python3`.
     To run on `macOS`, use `brew install python`.
  3. Cryptography library:
     In your terminal, use `pip install cryptography`.

## How It Works
1. Derives a key from the Master Password using `PBKDF2`, which is hashed by `HMAC`
2. Encrypts the password with `fernet`, stores it in a file, and salts it.
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/1.png)
3. Generates an `RSA key pair` to securely exchange a `Fernet key`
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/2.png)
4. Encrypts the `Fernet Key` using the `RSA public key`
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/3.png)
5. Retrieves passwords by decrypting the stored data using the master key
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/4.png)
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/5.png)
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/6.png)
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/7.png)
![Alt text](https://github.com/Ubuntu-Dekiru/Password_Manager/blob/main/screenshots/8.png)

## Usage
1. Run the script and enter your master password
2. Choose to add a new password or retrieve an existing one
3. Follow the prompts to generate or enter a new password

## Security Measures
1. Uses `Fernet` symmetric encryption for password storage
2. `RSA key pair` for encrypting `Fernet keys`
4. Salt generation for added security

## Requirements
`Python` and `Cryptography` Library

## Limitations 
Please note that this password manager is a simple project and not a production-ready solution. It's not recommended to use this for storing sensitive information in a real-world scenario, as it lacks the complexity and robustness of established password managers.

## Takeaway
This project demonstrates the potential of cryptography in building secure applications. I'm proud to have completed it, and I'm excited to continue exploring the world of cybersecurity.

## Contributing
Feel free to fork this repository, make improvements, and submit pull requests. Any contributions are welcome!

## License
This project is open source and available under the MIT License.

## Author
Adedoyin Abass / https://github.com/Ubuntu-Dekiru

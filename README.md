# Password_Manager
I created a simple password manager within 20 hours
I'm excited to share my latest project - a simple yet secure password manager that I built using Python! This project showcases the power of cryptography in protecting sensitive information. 

So my motivation began some time ago after picking up myself and cybersecurity back up, which I had brushed aside because of my time-consuming job role with Chivita. I decided I needed to do more projects and have more hands-on practicals. Hence this.😁
My motivation for creating this password manager was to learn about secure data storage and encryption. I wanted to understand how it works and put it into practice. I'm passionate about cybersecurity, and this project was a great opportunity to dive deeper into the world of encryption.

Why I chose Fernet and RSA
I chose Fernet for the symmetric encryption because it's fast and secure with very little fuss. However, I realized that using only symmetric encryption wouldn't be enough, and it would be too simple, as the key exchange would be a vulnerability. That's why I decided to use RSA asymmetric encryption to exchange the symmetric key securely. This way, I can leverage the speed of symmetric encryption while ensuring the security of the key exchange.

Key Features
It includes password regeneration, password storage for both the website domain name and password, password retrieval, and using the master password to derive the key through PBKDF2HMAC which hashes the derived key and encrypts and sends it to Fernet. At a point, I wanted to add a challenge-based MFA, but I decided to keep it simple and keep the creation timeframe to 24 hours.

How it Works
1. Enter a master password to unlock the system.
2. Choose an option:
 1. Add a password: Enter a website name and password (or generate one).
 2. Retrieve a password: Enter a website name to retrieve its password.
 3. Exit: Quit the program.

Relevant Code Snippets

- Deriving a key from the master password: key = derive_key_from_password(master_password, salt)
- This code uses PBKDF2HMAC to derive a key from the master password and salt.
- Encrypting the symmetric key with RSA: encrypted_fernet_key = encrypt_fernet_key(fernet_key, public_key)
- This code uses RSA encryption to exchange the symmetric key securely.
- Encrypting and decrypting passwords: encrypted_data = encrypt_data(data_to_encrypt, decrypted_fernet_key) and decrypted_pair = decrypt_data(encrypted_pair, decrypted_fernet_key)
- These codes use Fernet symmetric encryption to protect passwords.

Limitations 
Please note that this password manager is a simple project and not a production-ready solution. It's not recommended to use this for storing sensitive information in a real-world scenario, as it lacks the complexity and robustness of established password managers.

Takeaway: This project demonstrates the potential of cryptography in building secure applications. I'm proud to have completed it, and I'm excited to continue exploring the world of cybersecurity. Well, as regards the timeline, if I add the time for the research, it would probably be 23 hours, but...😎😁

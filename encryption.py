from base64 import urlsafe_b64encode
from hashlib import sha3_512
from secrets import compare_digest, token_hex
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Encryption:
    """
    classes for encryption, decryption, login, registration and key derivation
    """
    def __init__(self):
        """
        variables used for the password-manager
        """
        self.salt = ""
        self.hashedpasswordsalt = ""
        self.key = ""
        self.current_user = ""

    # Salt and Hash must be stored as strings
    def login(self, salt, password, stored_hash):
        """
        Creates Login using following variables.

        :param salt: random generated string
        :param password: user chosen master-password
        :param stored_hash: stored hash from the database (password + salt)
        :return: True or False wether the master-password + salt hashed is the same as the already saved one
        """

        # collect values from DB+Table needed.
        try:
            passwordsalt = password + salt
            hashedpasswordsalt = sha3_512(passwordsalt.encode('utf-8')).hexdigest()
            return compare_digest(stored_hash, hashedpasswordsalt)
        except TypeError:
            print("Master-Password and Salt could not be concatenated.")
            return False

    def signup(self, password):
        """
        creates salt + hashed password (with salt) and returns it

        :param password: user chosen master-password
        :return: True or false wether username is already taken
        """
        try:
            salt = token_hex(16)
            passwordsalt = password + salt
            hashedpasswordsalt = sha3_512(passwordsalt.encode('utf-8')).hexdigest()
            return salt, hashedpasswordsalt
        except TypeError:
            print("Salt and Master-Password can not be concatenated.")
            return False

    def derive_key(self, password, salt):
        """
        derives the key from password and salt
        salt and password must be encoded as bytes, otherwise the kdf.derive / PBKDF2HMAC functions won't work!

        :param password: master-password chosen by the user
        :param salt: random generated string
        :return:
        """
        try:
            saltbytes = bytes.fromhex(salt)
            passwordbytes = bytes(password, "utf-8")

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA3_512(),
                length=32,
                salt=saltbytes,
                iterations=1000001
            )
            key = urlsafe_b64encode(kdf.derive(passwordbytes))
            return key
        except ValueError:
            print("Salt or Master-Password can not be converted to bytes.")
            return False

    def encrypt(self, key, plaintext):
        """
        encrypts input plaintext like: email, username, password, notes
        :param key: generated key from derive key function != to master-password
        :param plaintext: plaintext being encrypted are: email, username, password, notes
        :return:
        """
        try:
            fernetkey = Fernet(key)
            ciphertext = fernetkey.encrypt(bytes(plaintext, "utf-8"))
            return ciphertext.decode()
        except ValueError:
            print("Key is not correctly encoded.")
            return False
        except TypeError:
            print("Plaintext has no valid Datatype.")
            return False

    def decrypt(self, key, ciphertext):
        """
        decrypts input plaintext like: email, username, password, notes
        :param key: generated key from derive key function != to master-password
        :param ciphertext: ciphertext being decrypted are: email, username, password, notes
        :return:
        """
        try:
            fernetkey = Fernet(key)
            plaintext = fernetkey.decrypt(bytes(ciphertext, "utf-8"))
            return plaintext.decode()
        except InvalidToken:
            print("Token is invalid.")
            return False
        except ValueError:
            print("Key is not correctly encoded.")
            return False

from getpass import getpass
from secrets import choice, compare_digest
from string import ascii_letters, digits, punctuation
from os import system, name
from time import sleep
from pyotp import TOTP
from encryption import Encryption
import db

current_encryption = Encryption()
entries_desc = ["id", "entryname", "username", "email", "password", "notes", "common_secret"]


def check_rockyou(password):
    """
    Search for password in rockyou.txt
    Return True if NOT found
    NOTE: rockyou.txt contained lines, that were not properly UTF-8 encoded.
    File was converted using iconv.
    :param: user typed password
    :return True: password was not found
    :return False: password was found
    """
    try:
        with open("rockyou_utf-8.txt", encoding="utf-8") as search:
            for line in search:
                line = line.rstrip()
                if line == password:
                    return False
            return True
    except FileNotFoundError:
        print("rockyou_utf-8.txt not found")
        return False


def generate_password(length):
    """
    generate_password generate a password with letters, digits and special_chars
    (at least one special_char and two digits).
    :param length: the length from the password, at least 8 characters!
    :return: the password.
    """
    # check if length is an int and < 7
    if isinstance(length, int) and (length > 7):
        # define the alphabet
        alphabet = ascii_letters + digits + punctuation
        # generate the password
        while True:
            password = ''
            for _ in range(length):
                password += ''.join(choice(alphabet))
            # check that the password have at least one punctuation and two digits
            if (any(char in punctuation for char in password) and sum(char in digits for char in password) >= 2) and \
                    check_rockyou(password):
                break
        return password
    # return False if length is no int or < 7
    return False


def login():
    """
    Uses entered username and passwort to check for username +  calculates hash (using salt which is stored in db)
    and compares with stored hash - if True -> key will be generated to encrypt/decrypt entries. If successful
    Master-Password is deleted from memory.

    var: current_encryption.current_user -> username of the user
    var: current_encryption.password -> master-password of the user (only in memory as long as needed)
    var: saltdb -> salt from the secrets database
    var: hashdb -> hash from the secrets database
    var: key -> AES KEY FOR ENCRYPTION AND DECRYPTION
    :return: True if username and password is correct
    :return: False if username or password is wrong
    """
    current_encryption.current_user = input("Please type in your Username: ")
    password = getpass()
    if not db.check_username(current_encryption.current_user):
        saltdb = db.query_secrets_entry_column(current_encryption.current_user, "salt")
        hashdb = db.query_secrets_entry_column(current_encryption.current_user, "hash")
        if current_encryption.login(saltdb, password, hashdb):
            current_encryption.key = current_encryption.derive_key(password, saltdb)
            del password
            return True
        del password
        sleep(1)
        print("Username or Master-Password is wrong.")
        sleep(1)
        return False
    sleep(1)
    print("Username or Master-Password is wrong.")
    sleep(1)
    return False


def register():
    """
    creates user using username and password, creates DB and derives key for encription/decription
    compares it with rockyou.txt and reports an error if theres a match
    :return: True if username and master-password, master-password is hashed, deleted and saved into the secrets.db
             and if user.db is created
    """

    # user is prompted to choose master-password at least 12 characters long. no further restrictions are given,
    # because master-passwords are mostly passphrases and not highly complex passwords
    while True:
        current_encryption.current_user = input("Please choose your username: ")
        if not db.check_username(current_encryption.current_user):
            print("Username already exists! Please choose another.")
            continue
        break
    while True:
        choose_password = getpass(prompt="Enter your Master-Password. It needs at least 12 characters: ")
        if len(choose_password) < 12:
            print("\nPassword is too short. It needs at least 12 characters.")
            del choose_password
            continue
        confirm_password = getpass(prompt="Re-Enter your Password: ")
        try:
            # master-password has to be put in twice by the user and is then compared if it is the same. if not user
            # is prompted again to reenter the master-password two times
            if not compare_digest(bytes(choose_password, 'utf-8'), bytes(confirm_password, 'utf-8')):
                print("Passwords do not match. Please try again")
                del choose_password, confirm_password
                continue
            # master-password is then compared to the rockyou.txt if it is listed there. if yes the user informed
            # about this and must put in another master-password
            if not check_rockyou(choose_password):
                print("Password is listed in a public password file. Please choose another.")
                del choose_password, confirm_password
                continue
        except TypeError:
            # both input passwords are deleted from memory, because it is sensitive information and should not be in
            # memory longer than necessary
            del choose_password, confirm_password
        break
        # chosen master-password is salted and hashed for save-keeping in the database
    salt_hash = current_encryption.signup(choose_password)
    # username, salt and hash added to the secrets.db
    # user-database is created
    if db.add_secrets_entry(current_encryption.current_user, salt_hash[0], salt_hash[1]):
        db.create_user_db(current_encryption.current_user)
        current_encryption.key = current_encryption.derive_key(choose_password, salt_hash[0])
        del choose_password, confirm_password
        print("New User has been registered")
        return True
    del choose_password, confirm_password
    print("Registration failed.")


def generate_or_type_pass(prompt):
    """
    you can either generate a password or choose it yourself. The password must be at least 6 characters if you
    let it generate. For choosing it yourself there are no restrictions.
    :param prompt: either for add() or change() specific prompts
    :return password: given
    """
    #
    while True:
        pwgen = input("Do you want to generate a password? (y/n): ")
        match pwgen.lower():
            case "y" | "yes":
                try:
                    length = int(input("How long should the generated password be? (Minimum is 8): "))
                except ValueError:
                    print("Please enter an integer.")
                    continue
                if length < 8:
                    print("Please enter a number >= 8.")
                    continue
                password = current_encryption.encrypt(current_encryption.key, generate_password(length))
                break
            case "n" | "no":
                if pwgen.lower() in ["n", "no"]:
                    password = current_encryption.encrypt(current_encryption.key, getpass(prompt=prompt))
                    break
            case _:
                print("Please enter 'y' or 'n'.")
    return password


def add():
    """
       allows you to add entries with entryname, username, email, password and notes. These entries are then encrypted
       (except the entryname) and then they are saved into the user database
       :return: True if user-entry can be created correctly
       :return: False if user-entry cannot be created
       """
    while True:
        # input entryname (cannot be empty)
        entryname = input("Entryname: ")
        if not entryname:
            print("Entryname cannot be empty")
            continue
        break

    entryname = current_encryption.encrypt(current_encryption.key, entryname)
    # you can type in username, email, both or nothing
    username = current_encryption.encrypt(current_encryption.key, input("Username: "))
    email = current_encryption.encrypt(current_encryption.key, input("E-Mail: "))

    # you can either generate a password or choose it yourself. The password must be at least 6 characters if you
    # let it generate. For choosing it yourself there are no restrictions.
    password = generate_or_type_pass("Password: ")
    # notes can be empty or filled.
    note = current_encryption.encrypt(current_encryption.key, input("Notes: "))
    # for timed one-time-passwords
    while True:
        totp = input("Secret for 2FA (Enter without spaces): ")
        if not generate_totp(totp):
            print("Invalid secret. Please try again.")
            continue
        totp = current_encryption.encrypt(current_encryption.key, totp)
        break
    # all entries are added to the user database
    db.add_user_entry(current_encryption.current_user, entryname, username, email, password, note, totp)
    # the entries are deleted from memory
    del entryname, username, email, password, note
    return True


def change():
    """
    with this function entries can be changed by the user
    :return: True if user-entry can be created correctly
    :return: False if something goes wrong or the change is cancelled
    """
    id_list = ["q"]
    for entry in db.list_user_entries(current_encryption.current_user):
        print(str(entry[0]) + "\t" + current_encryption.decrypt(current_encryption.key, entry[1]))
        id_list.append(str(entry[0]))
    entry_id = input("\nChoose the id of the entry you want to change or q to quit: ")
    while entry_id not in id_list:
        print(INVALID_MSG)
        entry_id = input("\nChoose the id of the entry you want to change or q to quit: ")
    if entry_id.lower() in ["q", "quit"]:
        clearterm()
        return False
    print("\n")
    for index, value in enumerate(db.query_user_entry(current_encryption.current_user, entry_id)):
        # match index
        # case 0: would display ID of the database entry, therefore gets ignored
        # case 1: the chosen entryname of the user entry
        # case 2 | 3 | 5: username, email or notes. have to be decrypted to be shown in plaintext
        # case 4: password of the entry. '***' are a placeholders
        # case 6: common_secret of the entry. '***' are placeholders
        match index:
            case 0:
                continue
            case 1 | 2 | 3 | 5:
                print(str(index) + "\t" + (entries_desc[index].capitalize() + ":\t" + str(
                    current_encryption.decrypt(current_encryption.key, value))).expandtabs(16))
            case 4 | 6:
                print(str(index) + "\t" + (entries_desc[index].capitalize() + ":\t" + "**********").expandtabs(16))
    id_columns = ["q", "1", "2", "3", "4", "5", "6"]
    column = input("\nChoose the id of the field you want to change or type 'q' to quit: ")
    while column not in id_columns:
        print(INVALID_MSG)
        column = input("\nChoose the id of the field you want to change or type 'q' to quit: ")
    if column == "q":
        return True
    match int(column):
        case 1 | 2 | 3 | 5:
            new_value = input(CHANGE_PROMPT + entries_desc[int(column)] + ": ")
            db.change_user_entry(current_encryption.current_user, entry_id, entries_desc[int(column)],
                                 current_encryption.encrypt(current_encryption.key, new_value))
        case 4:
            new_value = generate_or_type_pass(CHANGE_PROMPT + entries_desc[int(column)] + ": ")
            db.change_user_entry(current_encryption.current_user, entry_id, entries_desc[int(column)], new_value)
        case 6:
            while True:
                new_value = input(CHANGE_PROMPT + entries_desc[int(column)] + ": ")
                if not generate_totp(new_value):
                    print("Invalid secret. Please try again.")
                    continue
                break
            db.change_user_entry(current_encryption.current_user, entry_id, entries_desc[int(column)],
                                 current_encryption.encrypt(current_encryption.key, new_value))
    del new_value


def delete():
    """
    Delete a user entry.
    :return: return true or false
    """
    while True:
        check_user_entry_exits()
        entry_id = input("Choose the id of the entry you want to delete (press q to quit the delete function): ")
        if entry_id.lower() in ["q", "quit"]:
            clearterm()
            return False
        if db.query_user_entry(current_encryption.current_user, entry_id) == "":
            print(INVALID_MSG)
            sleep(1.0)
            clearterm()
        else:
            deleted_entry = db.query_user_entry_column(current_encryption.current_user, entry_id, 'entryname')
            db.delete_user_entry(current_encryption.current_user, entry_id)
            print(f"Entry \"{current_encryption.decrypt(current_encryption.key, deleted_entry)}\" successful deleted!")
            sleep(2.0)
            clearterm()
            return True


def delete_user():
    """
    deletes userdb and secretstable entry
    :return True: User was deleted
    :return False: anything went wrong or the user said 'no'
    """
    del_user = input("You are about to delete your useraccount. All your passwords will be lost! y/n ")
    while True:
        match del_user.lower():
            case "y" | "yes":
                del_user = input("Type 'Yes, do as I say!' to DELETE your account or 'n' to cancel! ")
            case "yes, do as i say!":
                db.delete_secrets_entry(current_encryption.current_user)
                db.delete_user_table(current_encryption.current_user)
                if not db.delete_user_file(current_encryption.current_user):
                    return True
                print("Account successfully deleted.")
                return True
            case "n" | "no":
                clearterm()
                return False
            case _:
                print(INVALID_MSG)
                sleep(2)
                clearterm()
                del_user = input("You are about to delete your useraccount. All your passwords will be lost! y/n ")


def show():
    """
    shows the selected entry
    :return True: everything went right
    :return False: something went wrong
    """
    # Return to main menu if there aren't any entries
    check_user_entry_exits()
    print("\n")
    while True:
        entry_id = input("Choose which entry you want to view in detail, l to list entries or type q to quit: ")
        print("\n")
        match entry_id.lower():
            case "l" | "list":
                # Print all entries: ID in first column, Entryname in second
                for entry in db.list_user_entries(current_encryption.current_user):
                    print(str(entry[0]) + "\t" + current_encryption.decrypt(current_encryption.key, entry[1]))
                print("\n")
                continue
            case "q" | "quit":
                clearterm()
                return True

        # print all fields of the entry with the chosen ID
        entry = db.query_user_entry(current_encryption.current_user, entry_id)
        for index, value in enumerate(entry):
            match index:
                # match index
                # case 0: would display ID of the database entry, therefore gets ignored
                # case 6: skip if secret field is empty, generate totp if not
                # case _: case for all remaining fields: decrypt and display
                case 0:
                    continue
                case 6:
                    if current_encryption.decrypt(current_encryption.key, entry[index]) != "":
                        print(("TOTP:\t" + str(
                            generate_totp(current_encryption.decrypt(current_encryption.key, value)))).expandtabs(16))
                    print("\n")
                case _:
                    print((entries_desc[index].capitalize() + ":\t" + str(
                        current_encryption.decrypt(current_encryption.key, value))).expandtabs(16))


def check_user_entry_exits():
    """
    for show() and delete(). checks if user-entries exits and prints the entries if they exists
    :return False: no entries existing
    :return True: entries are printed
    """
    if db.list_user_entries(current_encryption.current_user) == "":
        print("No entries existing.")
        sleep(1.0)
        clearterm()
        return False
    # Print all entries: ID in first column, Entryname in second
    for entry in db.list_user_entries(current_encryption.current_user):
        print(str(entry[0]) + "\t" + current_encryption.decrypt(current_encryption.key, entry[1]))
    return True


def clearterm():
    """
    deletes prints on terminal
    :return: nothing
    """
    system('cls' if name == 'nt' else 'clear')


def generate_totp(commonsecret):
    """
    calculates totp for 2FA
    :param commonsecret: common secret from website for 2FA authentication
    :return totp: calculated totp
    """
    try:
        totp = TOTP(commonsecret)
        return totp.now()
    except ValueError:
        return False


PROMPT_LOGIN = r"""
  _____                                        _                                                      
 |  __ \                                      | |                                                     
 | |__) |__ _  ___  ___ __      __ ___   _ __ | |_  _ __ ___    __ _  _ __    __ _   __ _   ___  _ __ 
 |  ___// _` |/ __|/ __|\ \ /\ / // _ \ | '__|| __|| '_ ` _ \  / _` || '_ \  / _` | / _` | / _ \| '__|
 | |   | (_| |\__  \__ \ \ V  V /| (_) || |   | |_ | | | | | || (_| || | | || (_| || (_| ||  __/| |   
 |_|    \__,_||___/|___/  \_/\_/  \___/ |_|    \__||_| |_| |_| \__,_||_| |_| \__,_| \__, | \___||_|   
                                                                                     __/ |            
                                                                                    |___/                       
Type 'l' to login or 'r' to register: """

CHANGE_PROMPT = "Please enter the new value for "

INVALID_MSG = "Invalid input!"

PROMPT_MAIN = """
l   list entries\ts   show entry
a   add entry\th   print this list
c   change entry\tq   quit
d   delete entry\tdu  delete user account
"""

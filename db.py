import os
from sqlite3 import connect, OperationalError, IntegrityError
from os import path, remove
from sys import exit as sysexit


class MissingEntry(Exception):
    """
    raise if nothing is in the pulled entry
    """


USERDB = "userdbs/"
INVALID_USERNAME = "Username not a valid Dataformat."
SECRETS = "secrets.db"
USERDB_NOT_FOUND = """
Database file not found. Please register a new user or copy your user database file into the userdbs directory."""
SECRETS_NOT_FOUND = "Database file not found."
TABLE_NOT_FOUND = "User table cannot be found or entry cannot be created."
INVALID_COLUMN = "Invalid column."
USER_NOT_FOUND = "User cannot be found."


def create_user_db(user):
    """
    create_user_db creates a database for a user with all the necessary columns.
    It creates the columns id, entryname, username, email, password and notes.


    :param user: user for whom the database should be created
    :return: True if everything went right
    """
    try:
        connection = connect(USERDB + user + ".db")
        cursor = connection.cursor()

        instruction = """
        CREATE TABLE entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entryname VARCHAR NOT NULL,
        username VARCHAR,
        email VARCHAR,
        password VARCHAR,
        notes VARCHAR,
        common_secret VARCHAR);"""

        cursor.execute(instruction)
        connection.close()
        return True
    except OperationalError:
        print("Database already exists.")
        sysexit()
    except TypeError:
        print(INVALID_USERNAME)
        sysexit()


def create_secrets_db():
    """
    create_secrets_db creates a database the global secrets with all the necessary columns.
    It creates the username, salt and hash.
    :return: True if everything went right.
    """
    try:
        connection = connect(SECRETS)
        cursor = connection.cursor()

        instruction = """
        CREATE TABLE secrets (
        username VARCHAR NOT NULL,
        salt VARCHAR NOT NULL,
        hash VARCHAR NOT NULL);"""

        cursor.execute(instruction)
        connection.close()
        return True
    except OperationalError:
        print("Database already exists.")
        sysexit()


def add_secrets_entry(username, salt, pwhash):
    """
    add_secrets_entry stores a user's salt and hash in the secrets database
    :param username: User whose salt and hash should be stored
    :param salt: Actual value of the user's salt
    :param pwhash: Actual value of the user's hash
    :return: True if everything went right
    """
    if not path.exists(SECRETS):
        print(SECRETS_NOT_FOUND)
        sysexit()
    try:
        connection = connect(SECRETS)
        cursor = connection.cursor()
        cursor.execute('INSERT INTO secrets VALUES (?, ?, ?)', (username, salt, pwhash))
        connection.commit()
        connection.close()
        return True
    except OperationalError:
        print("Secrets table cannot be found or entry cannot be created.")
        sysexit()


def add_user_entry(user, entryname, username, email, password, note, common_secret):
    """
    add_user_entry creates an entry with credentials in a user's database
    :param user: The user whose credentials should be stored
    :param entryname: Name of the service for which credentials should be stored
    :param username: Login name for the service
    :param email: E-Mail address
    :param password: Password for the service
    :param note: Additional information
    :param common_secret: for totp key generation (like google authenticator)
    :return: id of the newly created entry
    """
    try:
        if not path.exists(USERDB + user + ".db"):
            print(USERDB_NOT_FOUND)
            sysexit()

        connection = connect(USERDB + user + ".db")
        cursor = connection.cursor()
        cursor.execute("INSERT INTO entries(entryname, username, email, password, notes, common_secret) "
                       "VALUES (?, ?, ?, ?, ?, ?)", (entryname, username, email, password, note, common_secret))
        connection.commit()
        query = "select id from entries order by id desc limit 1;"
        identifier = ""
        cursor.execute(query)
        for spalte in cursor:
            identifier = spalte[0]
        connection.close()
        return identifier
    except IntegrityError:
        print("Missing required argument.")
        sysexit()
    except OperationalError:
        print(TABLE_NOT_FOUND)
        sysexit()
    except TypeError:
        print(INVALID_USERNAME)
        sysexit()


def change_user_entry(user, identifier, column, value):
    """
    change_user_entry changes a specific value of an entry in a user's database
    :param user: User, in whose database the change should occur
    :param identifier: id of the entry that should be changed
    :param column: Name of the column that should  be changed
    :param value: New value, that should be inserted
    :return: True if everything went right
    """
    try:
        if not path.exists(USERDB + user + ".db"):
            print(USERDB_NOT_FOUND)
            sysexit()

        connection = connect(USERDB + user + ".db")
        cursor = connection.cursor()
        match column:
            case "entryname":
                cursor.execute("UPDATE entries SET entryname = ? WHERE id = ?", (value, identifier))
            case "username":
                cursor.execute("UPDATE entries SET username = ? WHERE id = ?", (value, identifier))
            case "email":
                cursor.execute("UPDATE entries SET email = ? WHERE id = ?", (value, identifier))
            case "password":
                cursor.execute("UPDATE entries SET password = ? WHERE id = ?", (value, identifier))
            case "notes":
                cursor.execute("UPDATE entries SET notes = ? WHERE id = ?", (value, identifier))
            case "common_secret":
                cursor.execute("UPDATE entries SET common_secret = ? WHERE id = ?", (value, identifier))
            case _:
                print(INVALID_COLUMN)
                return False
        connection.commit()
        connection.close()
        return True
    except OperationalError:
        print(TABLE_NOT_FOUND)
        sysexit()
    except TypeError:
        print(INVALID_USERNAME)
        sysexit()


def query_secrets_entry_column(username, column):
    """
    query_secrets_entry_column is used to get the salt or the hash of a user from the secrets database
    :param username: Name of the user whose salt or hash should be queried
    :param column: Column to query ("salt" or "hash")
    :return: Actual salt or hash value
    """
    if not path.exists(SECRETS):
        print(SECRETS_NOT_FOUND)
        sysexit()

    try:
        connection = connect(SECRETS)
        cursor = connection.cursor()
        match column:
            case "salt":
                cursor.execute("SELECT salt FROM secrets WHERE username = ?;", (username,))
            case "hash":
                cursor.execute("SELECT hash FROM secrets WHERE username = ?;", (username,))
            case _:
                print(INVALID_COLUMN)
                return False
        result = ""
        for spalte in cursor:
            result = spalte[0]
        connection.close()
        if result == "":
            raise MissingEntry
        return result
    except OperationalError:
        print(TABLE_NOT_FOUND)
        sysexit()
    except MissingEntry:
        print("Entry Missing from Database.")
        sysexit()


def query_user_entry(user, identifier):
    """
    query_user_entry returns a completely entry from the "user".db.

    :param user: The queried user.
    :param identifier: The id which is queried.
    :return: Return the user entry.
    """
    try:
        if not path.exists(USERDB + user + ".db"):
            print(USERDB_NOT_FOUND)
            sysexit()

        connection = connect(USERDB + user + ".db")
        cursor = connection.cursor()
        cursor.execute("select * from entries where id = ?;", (identifier,))
        result = ""
        for spalte in cursor:
            result = spalte
        connection.close()
        return result
    except OperationalError:
        print(TABLE_NOT_FOUND)
        sysexit()
    except TypeError:
        print(INVALID_USERNAME)
        sysexit()


def query_user_entry_column(user, identifier, column):
    """
    query_user_entry_column returns data from a colum
    (entryname, username, email, password, notes, common_secret) in the "user".db.
    :param user: The affected user.
    :param identifier: The id which queried.
    :param column: The colum which queried.
    :return: return the entry from the queried id.
    """
    try:
        if not path.exists(USERDB + user + ".db"):
            print(USERDB_NOT_FOUND)
            sysexit()

        connection = connect(USERDB + user + ".db")
        cursor = connection.cursor()
        match column:
            case "entryname":
                cursor.execute("select entryname from entries where id = ?;", (identifier,))
                if cursor == "":
                    raise MissingEntry
            case "username":
                cursor.execute("select username from entries where id = ?;", (identifier,))
            case "email":
                cursor.execute("select email from entries where id = ?;", (identifier,))
            case "password":
                cursor.execute("select password from entries where id = ?;", (identifier,))
            case "notes":
                cursor.execute("select notes from entries where id = ?;", (identifier,))
            case "common_secret":
                cursor.execute("select common_secret from entries where id = ?;", (id,))
            case _:
                print(INVALID_COLUMN)
                return False
        result = ""
        if cursor is None:
            raise MissingEntry
        for spalte in cursor:
            result = spalte[0]
        connection.close()
        return result
    except OperationalError:
        print(TABLE_NOT_FOUND)
        sysexit()
    except TypeError:
        print(INVALID_USERNAME)
        sysexit()
    except MissingEntry:
        print("Entry Missing from Database.")
        sysexit()


def list_user_entries(user):
    """
    creates list of the user-entries
    :param user: Username
    :return result: list with the entries
    """
    try:
        if not path.exists(USERDB + user + ".db"):
            print(USERDB_NOT_FOUND)
            sysexit()

        connection = connect(USERDB + user + ".db")
        cursor = connection.cursor()
        cursor.execute("select id,entryname from entries order by id asc")
        result = []
        for spalte in cursor:
            result.append([spalte[0], spalte[1]])
        return result
    except OperationalError:
        print(TABLE_NOT_FOUND)
        sysexit()
    except TypeError:
        print(INVALID_USERNAME)
        sysexit()


def delete_secrets_entry(user):
    """
    delete_secrets_entry deletes a secret entrie from a user in the secrets.db

    :param user: User which secrets deleted.
    :return:
    """
    if not path.exists(SECRETS):
        print(SECRETS_NOT_FOUND)
        sysexit()

    try:
        connection = connect(SECRETS)
        cursor = connection.cursor()
        cursor.execute('delete from secrets where username = ?;', (user,))
        connection.commit()
        connection.close()
        return True
    except OperationalError:
        print(USER_NOT_FOUND)
        sysexit()


def delete_user_entry(user, identifier):
    """
    delete_user_entry deletes a entry from a user in the "user".db

    :param user: User which entry deleted.
    :param identifier: The id from the entry which deleted.
    :return: True if everything went right
    """
    try:
        if not path.exists(USERDB + user + ".db"):
            print(USERDB_NOT_FOUND)
            sysexit()

        connection = connect(USERDB + user + ".db")
        cursor = connection.cursor()
        cursor.execute('delete from entries where id = ?;', (identifier,))
        connection.commit()
        connection.close()
        return True
    except OperationalError:
        print(USER_NOT_FOUND)
        sysexit()
    except TypeError:
        print(INVALID_USERNAME)
        sysexit()


def delete_user_table(user):
    """
    delete_user_table deletes all user entries from a user.

    :param user: The user which tabele deleted.
    :return: True if everything went right
    """
    try:
        if not path.exists(USERDB + user + ".db"):
            print(USERDB_NOT_FOUND)
            sysexit()

        connection = connect(USERDB + user + ".db")
        cursor = connection.cursor()
        cursor.execute('drop table entries;')
        connection.commit()
        connection.close()
        return True
    except OperationalError:
        print(USER_NOT_FOUND)
        sysexit()
    except TypeError:
        print(INVALID_USERNAME)
        sysexit()


def delete_user_file(user):
    """
    deletes User Database from /userdbs
    :param user: user that is currently using the Manager
    :return True: userdb was successfully deleted
    :return False: userdb was already deleted during use of the Manager
    """
    if path.exists(USERDB + user + ".db"):
        remove(USERDB + user + ".db")
        return True
    print("Database file already deleted.")
    return False


def check_username(user):
    """
    checks and returns username from secrets database
    :param user: username
    :return: return True or False
    """
    if not path.exists(SECRETS):
        print(SECRETS_NOT_FOUND)
        sysexit()
    try:
        conn = connect('secrets.db')
        cursor = conn.execute("SELECT username FROM secrets")
        for row in cursor:
            if user == row[0]:
                return False
        return True
    except OperationalError:
        print(USER_NOT_FOUND)
        sysexit()
    except TypeError:
        print(INVALID_USERNAME)
        sysexit()

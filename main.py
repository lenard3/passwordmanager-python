from os import path, access, mkdir, W_OK
from time import sleep
from sys import exit as sysexit
import helper_functions as hf
from helper_functions import current_encryption
from db import create_secrets_db, list_user_entries


CURRENT_MENU = "login"

try:
    while True:
        match CURRENT_MENU:
            case "login":
                if not path.exists("secrets.db"):
                    create_secrets_db()
                if not path.exists("userdbs/"):
                    if access("./", W_OK):
                        mkdir("userdbs")
                    else:
                        print("Cannot write to current directory, please fix permissions! Exiting.")
                        sysexit()
                type_login = input(hf.PROMPT_LOGIN)
                if type_login == "l":
                    if hf.login():
                        CURRENT_MENU = "main"
                elif type_login == "r" and hf.register():
                    CURRENT_MENU = "main"
                hf.clearterm()
            case "main":
                print(hf.PROMPT_MAIN.expandtabs(25))
                while True:
                    action = input("Choose action: ")
                    match action:
                        case "l":
                            for entry in list_user_entries(current_encryption.current_user):
                                print(str(entry[0]) + "\t" + current_encryption.decrypt(current_encryption.key, entry[1]))
                        case "a":
                            hf.add()
                            break
                        case "c":
                            CURRENT_MENU = "change"
                            break
                        case "d":
                            CURRENT_MENU = "delete"
                            break
                        case "s":
                            CURRENT_MENU = "show"
                            break
                        case "h":
                            print(hf.PROMPT_MAIN.expandtabs(25))
                        case "q":
                            CURRENT_MENU = "quit"
                            break
                        case "du":
                            CURRENT_MENU = "delete_user"
                            break
                hf.clearterm()
            case "add":
                hf.add()
            case "change":
                hf.change()
                hf.clearterm()
                CURRENT_MENU = "main"
            case "delete":
                hf.delete()
                CURRENT_MENU = "main"
            case "show":
                hf.show()
                CURRENT_MENU = "main"
            case "delete_user":
                if hf.delete_user():
                    print("\nGoodbye!")
                    sleep(2)
                    sysexit()
                CURRENT_MENU = "main"
            case "quit":
                print("Goodbye!")
                sleep(2.0)
                sysexit()
except KeyboardInterrupt:
    print("\nGoodbye!")
    del current_encryption
    sysexit()

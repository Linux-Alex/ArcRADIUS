import os
import shutil

def createAddressFileIfNotExists():
    address_file_path = os.path.join(os.path.dirname(__file__), "clients", "address.yml")
    if not os.path.exists(address_file_path):
        with open(address_file_path, 'w') as file:
            pass
        print("Address file created.")
    else:
        print("Address file already exists.")

def createDbIfNotExists():
    db_file_path = os.path.join(os.path.dirname(__file__), "instance", "db.sqlite3")
    if not os.path.exists(db_file_path):
        initial_db_path = os.path.join(os.path.dirname(__file__), "samples", "initial.sqlite3")
        shutil.copy(initial_db_path, db_file_path)
        if os.path.exists(db_file_path):
            print("Database file copied successfully.")
            # print("Database file initial_db_path:", initial_db_path)
        else:
            print("Failed to copy the database file.")
    else:
        print("Database file already exists.")
        # print("Database file path:", db_file_path)

def get_unique_username(base_username, current_usernames):
    if base_username not in current_usernames:
        # If the base username doesn't exist in the list, return it as is.
        return base_username
    else:
        # If the base username exists, append a suffix and check again.
        i = 1
        while True:
            new_username = f"{base_username}_{i}"
            if new_username not in current_usernames:
                return new_username
            i += 1
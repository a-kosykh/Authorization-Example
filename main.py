import sqlite3
import hashlib
import getpass


class DatabaseLayer:
    def __init__(self, name):
        self.name = name
        self.conn = None

    def create_connection(self):
        try:
            self.conn = sqlite3.connect(self.name)
        except sqlite3.Error as e:
            print(e)

    def create_table(self):
        try:
            c = self.conn.cursor()
            c.execute("CREATE TABLE users"
                      "(username text NOT NULL,"
                      "h_password text);")
            c.execute("CREATE UNIQUE INDEX idx_users_username ON users (username);")
        except sqlite3.Error as e:
            print(e)

    def show_table(self):
        try:
            c = self.conn.cursor()
            c.execute("SELECT * FROM users")
            rows = c.fetchall()

            for row in rows:
                print(row)

        except sqlite3.Error as e:
            print(e)

    def register_user(self, data):
        try:
            c = self.conn.cursor()
            sql_query = ''' INSERT INTO users(username, h_password) VALUES (?,?) '''
            c.execute(sql_query, data)
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            return False

    def find_user(self, data):
        c = self.conn.cursor()
        sql_query = ''' SELECT * FROM users WHERE username = ? AND h_password = ? '''
        c.execute(sql_query, data)

        rows = c.fetchall()
        if len(rows) > 0:
            return True
        else:
            return False


class User:
    def __init__(self, name):
        self.name = name


class Auth:
    def __init__(self, db_obj, max_attempts):
        self.db = db_obj
        self.logged_user = None
        self.login_attempts = 0
        self.max_attempts = max_attempts

    def register(self, name, password):
        if self.db is not None:
            h_password = hashlib.pbkdf2_hmac('sha256', bytes(password, 'utf-8'), b'salt', 100000).hex()
            if self.db.register_user((name, h_password)):
                print(f"Successful registration of '{name}'!")
            else:
                print(f"ERROR: User with name '{name}' already exists!")

    def login_limit(self):
        if self.login_attempts == self.max_attempts:
            print("Max login limit reached!")
            return True
        else:
            return False

    def login(self, name, password):
        if self.login_limit():
            return False

        h_password = hashlib.pbkdf2_hmac('sha256', bytes(password, 'utf-8'), b'salt', 100000).hex()
        if db.find_user((name, h_password)):
            print(f"Login complete!")
            self.logged_user = User(name)
            return True
        else:
            print(f"Wrong login or password!")
            self.login_attempts += 1
            return False


def init_loop(user):
    print(f"\nYour are logged as {user.name}...")
    while True:
        command = input("Enter command: ")
        if command == 'exit':
            break


if __name__ == '__main__':
    db = DatabaseLayer("mydb.db")
    db.create_connection()
    # db.create_table()

    auth = Auth(db, 3)

    while True:
        code = input("\nAuthorization soft\n1>Register\n2>Login\n3>Exit\nEnter code: ")
        if code == '1':
            print("\n---Registration---")
            name = input("Enter username: ")
            password = input("Enter password: ")
            auth.register(name, password)
            continue

        if code == '2':
            print("\n---Login---")
            name = input("Enter username: ")
            password = input("Enter password: ")
            if auth.login(name, password):
                init_loop(auth.logged_user)
                break
            continue

        if code == '3':
            print("\nExiting....")
            break

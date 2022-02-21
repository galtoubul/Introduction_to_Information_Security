import base64
import contextlib
import hashlib
import sqlite3
import time


def sha1(val):
    s = hashlib.sha1()
    if isinstance(val, str):
        val = val.encode()
    s.update(val)
    return s.hexdigest()


def create_connection(db_path):
    conn = sqlite3.connect(db_path)
    conn.create_function('sha1', 1, sha1)
    return conn


@contextlib.contextmanager
def connect(db_path):
    with create_connection(db_path) as conn:
        yield conn


class DBLogic:
    def __init__(self, db_connection):
        self.db_connection = db_connection
        self.initialize_db()

    def initialize_db(self):
        self.db_connection.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                user_id  INTEGER PRIMARY KEY,
                username  TEXT,
                password  TEXT,
                full_name TEXT
            );
        ''')
        self.db_connection.executescript('''
            CREATE TABLE IF NOT EXISTS channels (
                channel_id  INTEGER PRIMARY KEY,
                channel     TEXT UNIQUE
            );
        ''')
        self.db_connection.executescript('''
            CREATE TABLE IF NOT EXISTS messages (
                message_id INTEGER PRIMARY KEY,
                user_id    INTEGER REFERENCES users (user_id),
                channel_id INTEGER REFERENCES channels (channel_id),
                timestamp  INTEGER,
                text       TEXT
            );
        ''')
        self.db_connection.executescript('''
            INSERT OR IGNORE INTO users VALUES (1, 'boss', sha1('Dancing in the dark'), 'Bruce Summersteen');
            INSERT OR IGNORE INTO users VALUES (2, 'edward', '', 'Edward Hailden');
            INSERT OR IGNORE INTO users VALUES (3, 'alice', sha1('Into the flood again.'), 'Alice InRopes');
            INSERT OR IGNORE INTO users VALUES (4, 'bob', sha1('Is this love'), 'Bob Marmite');
            INSERT OR IGNORE INTO users VALUES (5, 'system', '', 'Grape Galili');
            INSERT OR IGNORE INTO users VALUES (6, 'test', sha1('1234'), 'Testy McTestFace');
        ''')
        self.db_connection.executescript('''
            INSERT OR IGNORE INTO channels VALUES (1, '#nsk-home');
            INSERT OR IGNORE INTO channels VALUES (2, '#announcements');
            INSERT OR IGNORE INTO channels VALUES (3, '#general-spam');
            INSERT OR IGNORE INTO messages VALUES (1, 3, 3, 1496311872, 'Hey, Bob!');
            INSERT OR IGNORE INTO messages VALUES (2, 4, 3, 1496311872, 'Hi Alice!');
        ''')

    def select_scalar(self, *args, **kwargs):
        """Utility to return a scalar value from a query."""
        row = self.db_connection.execute(*args, **kwargs).fetchone()
        return None if row is None else row[0]

    def login(self, username, password):
        match = self.select_scalar(
            "SELECT * FROM users WHERE username = ? AND password = sha1(?)",
            (username, password,)
        )
        if match:
            return True, base64.b64encode(username.encode()).decode()
        else:
            return False, ''

    def validate_login(self, cookie):
        if not cookie:
            return False
        try:
            # b64decode returns bytes, another decode to get a string
            login = base64.b64decode(cookie).decode()
        except:
            return False
        if self.select_scalar(
            "SELECT * FROM users WHERE username = ?",
            (login,)
        ):
            return login
        else:
            return None

    def get_channels(self):
        return [
            channel for channel,
            in self.db_connection.execute(
                "SELECT channel FROM channels"
            ).fetchall()
        ]

    def get_channel_id(self, channel):
        return self.select_scalar(
            "SELECT channel_id FROM channels WHERE channel = ?",
            (channel,)
        )

    def get_user_name(self, username):
        return self.select_scalar(
            "SELECT full_name FROM users WHERE username = ?",
            (username,)
        )

    def get_user_id(self, username):
        return self.select_scalar(
            "SELECT user_id FROM users WHERE username = ?",
            (username,)
        )

    def add_channel(self, channel):
        max_id = self.select_scalar('SELECT MAX(channel_id) FROM channels')
        self.db_connection.execute(
            'INSERT INTO channels (channel_id, channel) VALUES (?, ?)',
            (max_id + 1, channel,)
        )
   
    def rename_user(self, user_id, new_name):
        self.db_connection.executescript(
            "UPDATE users SET full_name = '%s' WHERE user_id = '%s'" %
            (new_name, user_id,)
        )

    def add_message(self, username, channel, text):
        return self.add_message_(
            self.get_user_id(username),
            self.get_channel_id(channel),
            text
        )

    def add_message_(self, user_id, channel_id, text):
        self.db_connection.execute(
            'INSERT INTO messages (user_id, channel_id, timestamp, text) '
            'VALUES (?, ?, ?, ?)',
            (user_id, channel_id, int(time.time()), text,)
        )

    def list_messages(self, last_id, channel_id):
        return [
            (message_id, username, timestamp, message)
            for message_id, username, timestamp, message
            in self.db_connection.execute(
                'SELECT message_id, username, timestamp, text '
                'FROM users NATURAL JOIN messages '
                'WHERE message_id > ? AND channel_id = ?',
                (last_id, channel_id,)
            ).fetchall()
        ]

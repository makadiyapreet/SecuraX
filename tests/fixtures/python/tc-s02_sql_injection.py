import sqlite3

def authenticate(conn, user, pwd):
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM accounts WHERE user = ? AND pass = ?", (user, pwd))
    return cursor.fetchone()

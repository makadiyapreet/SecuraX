import sqlite3

def authenticate(conn, user, pwd):
    cursor = conn.cursor()
    query = f"SELECT id FROM accounts WHERE user = '{user}' AND pass = '{pwd}'"
    cursor.execute(query)
    return cursor.fetchone()

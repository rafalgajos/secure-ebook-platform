import sqlite3

# Definition of a global variable at module level
conn = None


def create_database():
    global conn
    try:
        conn = sqlite3.connect('reviews.db')
        cursor = conn.cursor()

        # Create a 'reviews' table with name, email, content and user_id columns
        cursor.execute('''CREATE TABLE IF NOT EXISTS reviews (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL,
                            email TEXT NOT NULL,
                            content TEXT NOT NULL,
                            user_id TEXT NOT NULL
                        )''')

        conn.commit()
        print("The database and table have been created successfully.")

    except sqlite3.Error as e:
        print(f"An error occurred while creating the database: {e}")

    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    create_database()

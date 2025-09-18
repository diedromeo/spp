import os
import sqlite3
from flask import Flask, render_template_string, request, g, session, redirect, url_for

app = Flask(__name__)
app.secret_key = os.urandom(24)

DATABASE = 'database.db'
VALID_USERNAME = 'admin'
VALID_PASSWORD = 'password123'

# Helper function to get a database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

# Initialize the database with a user
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (VALID_USERNAME, VALID_PASSWORD))
        db.commit()

# Close the database connection at the end of the request
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# The login page
@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return render_template_string("""
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Company Secure Login</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-xl w-full max-w-sm">
                <h2 class="text-2xl font-bold text-center mb-6 text-gray-800">Company Secure Login</h2>
                {% if error %}
                    <p class="text-red-500 text-sm mb-4 text-center">{{ error }}</p>
                {% endif %}
                <form action="/login" method="post" class="space-y-4">
                    <div>
                        <label for="username" class="block text-sm font-medium text-gray-700">Username</label>
                        <input type="text" id="username" name="username" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                    </div>
                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                        <input type="password" id="password" name="password" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                    </div>
                    <div>
                        <button type="submit" class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
                            Log in
                        </button>
                    </div>
                </form>
            </div>
        </body>
        </html>
    """, error=request.args.get('error'))

# The login logic
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    db = get_db()
    cursor = db.cursor()
    
    # VULNERABILITY: User input is directly formatted into the SQL query string.
    # A safe query would use a prepared statement like:
    # cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    # For educational purposes, a print statement to show the query being executed
    print(f"Executing query: {query}")

    try:
        cursor.execute(query)
        user = cursor.fetchone()
    except sqlite3.OperationalError as e:
        print(f"SQL Error: {e}")
        return redirect(url_for('index', error="A database error occurred."))

    if user:
        session['logged_in'] = True
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('index', error="Invalid username or password"))

# The dashboard page for logged-in users
@app.route('/dashboard')
def dashboard():
    if not 'logged_in' in session:
        return redirect(url_for('index', error="You must be logged in to view this page."))
    
    # The flag is in the "dashboard" page.
    flag = "ctf7{n0t_s0_s3cur3_sql_inJ3cti0n}"

    sql_explanation = f"""
    <div class="mt-10 p-6 bg-gray-50 rounded-lg border border-gray-200">
        <h3 class="text-xl font-bold mb-4 text-gray-800">Understanding SQL Injection</h3>
        <p class="text-gray-700 mb-4">
            Congratulations! You've successfully performed a **SQL Injection** attack. This vulnerability occurs when an attacker can interfere with the queries that an application makes to its database. By injecting malicious SQL syntax into an input field, you can trick the database into executing unintended commands.
        </p>

        <h4 class="text-lg font-semibold mt-6 mb-2 text-gray-800">How This Attack Worked</h4>
        <p class="text-gray-700 mb-4">
            In this challenge, the Flask application was using an **f-string** to build the SQL query, which is a common but dangerous practice. The vulnerable line of code looks like this:
            <pre class="bg-gray-200 p-2 rounded-md my-2 text-sm font-mono overflow-auto"><code>query = f"SELECT * FROM users WHERE username = '{{username}}' AND password = '{{password}}'"</code></pre>
            Your input for the username field was not sanitized, allowing you to manipulate the query.
        </p>

        <h4 class="text-lg font-semibold mt-6 mb-2 text-gray-800">The Winning Payload</h4>
        <p class="text-gray-700 mb-4">
            You likely used a payload similar to **' or 1=1--** in the username field. Let's break down how this works:
            <ul class="list-disc list-inside text-gray-700 space-y-2">
                <li><code>'</code>: The single quote closes the `username` string in the original query.</li>
                <li><code>or 1=1</code>: This adds a condition to the query that is always true. The `WHERE` clause now becomes `WHERE 'username' = '' OR 1=1`. Since `1=1` is always true, the entire condition becomes true, and the database will return the first row it finds.</li>
                <li><code>--</code>: The double hyphens are the SQL comment syntax. This comments out the rest of the query, including the password check. The database ignores everything after this, effectively bypassing the password requirement.</li>
            </ul>
        </p>

        <h4 class="text-lg font-semibold mt-6 mb-2 text-gray-800">How to Fix This Vulnerability</h4>
        <p class="text-gray-700">
            To prevent SQL injection, developers should use **prepared statements** (also known as parameterized queries). These separate the SQL logic from the user-provided data, ensuring that the input is treated as a literal value and not as executable code. The safe way to write the query would have been:
            <pre class="bg-gray-200 p-2 rounded-md my-2 text-sm font-mono overflow-auto"><code>cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))</code></pre>
        </p>
    </div>
    """

    return render_template_string("""
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Admin Dashboard</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-xl text-center w-full max-w-2xl">
                <h2 class="text-3xl font-bold text-gray-800 mb-4">Welcome to Your Dashboard!</h2>
                <p class="text-lg text-gray-600 mb-6">You have successfully logged in.</p>
                <div class="p-4 bg-gray-200 rounded-lg font-mono text-xl mb-6">
                    """ + flag + """
                </div>
                <img src="https://media3.giphy.com/media/bqmgTU1CY1QgFt2tCR/giphy.gif" class="mx-auto rounded-lg" alt="Success">
                """ + sql_explanation + """
                <a href="/logout" class="mt-6 inline-block py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700">
                    Log out
                </a>
            </div>
        </body>
        </html>
    """, flag=flag)

# Logout route
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index', error="You have been logged out."))

# The Flask application runs here.
if __name__ == '__main__':
    # Initialize the database with our single user.
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
import mysql.connector
from mysql.connector import Error
import google.generativeai as genai
import os
import secrets
from functools import wraps
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder='static')
app.secret_key = secrets.token_hex(16)

# Configure Gemini API using environment variable
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("Missing GEMINI_API_KEY environment variable")

genai.configure(api_key=GEMINI_API_KEY)


# Update the database connection function to use mysql.connector
def get_db_connection():
    DB_Password = os.environ.get("DB_Password")
    DB_Name = os.environ.get("DB_Name")
    if not DB_Name and DB_Password:
        raise ValueError("Missing DB_Password and DB_Name environment variable")
    else:
        try:
            return mysql.connector.connect(
                host="sql12.freesqldatabase.com",        # Replace with your actual host
                user="sql12800929",               # Your database username
                password=DB_Password,          # Your DB password
                database=DB_Name,
                port= 3306
            )
        except Error as e:
            print(f"Database Connection Error: {e}")
            raise

# Authentication middleware
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

# Helper function to check if a user has access to a project
def user_has_access_to_project(user_id, role, project_id, conn=None):
    # Admins have access to all projects
    if role.lower() == 'admin':
        return True

    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True

    try:
        cursor = conn.cursor()

        # Check if the user is the creator of the project
        cursor.execute("""
            SELECT 1 FROM Projects WHERE project_id = %s AND created_by = %s
        """, (project_id, user_id))
        if cursor.fetchone():
            return True

        # Check if the user is assigned to any task in the project
        cursor.execute("""
            SELECT 1 FROM Tasks WHERE project_id = %s AND assigned_to = %s LIMIT 1
        """, (project_id, user_id))
        if cursor.fetchone():
            return True

        return False

    except Exception as e:
        print(f"Access check error: {e}")
        return False

    finally:
        if close_conn:
            conn.close()


# Helper function to check if a user has access to a task
def user_has_access_to_task(user_id, role, task_id, conn=None):
    # Admins have access to all tasks
    if role.lower() == 'admin':
        return True

    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True

    try:
        cursor = conn.cursor()

        # Check if the task is directly assigned to the user
        cursor.execute("""
            SELECT 1 FROM Tasks
            WHERE task_id = %s AND assigned_to = %s
            LIMIT 1
        """, (task_id, user_id))
        if cursor.fetchone():
            return True

        # Check if the user created the project that the task belongs to
        cursor.execute("""
            SELECT 1
            FROM Projects p
            JOIN Tasks t ON p.project_id = t.project_id
            WHERE t.task_id = %s AND p.created_by = %s
            LIMIT 1
        """, (task_id, user_id))
        if cursor.fetchone():
            return True

        # Check if the user is assigned to any task in the same project
        cursor.execute("""
            SELECT 1
            FROM Tasks t1
            WHERE t1.project_id = (
                SELECT t2.project_id FROM Tasks t2 WHERE t2.task_id = %s
            )
            AND t1.assigned_to = %s
            LIMIT 1
        """, (task_id, user_id))
        if cursor.fetchone():
            return True

        return False

    except Exception as e:
        print(f"Access check error: {e}")
        return False

    finally:
        if close_conn and conn:
            conn.close()


#API to Register
@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        security = data.get('security')
        answer = data.get('answer')

        # Validate required fields
        if not username or not email or not password or not role or not security or not answer:
            return jsonify({"error": "All fields are required"}), 400

        try:
            conn = get_db_connection()
            cursor = conn.cursor(buffered=True)  # Using buffered cursor for MySQL

            # Check if username already exists
            cursor.execute("SELECT COUNT(*) FROM Users WHERE username = %s", (username,))
            if cursor.fetchone()[0] > 0:
                return jsonify({"error": "Username already exists"}), 409

            # Check if email already exists
            cursor.execute("SELECT COUNT(*) FROM Users WHERE email = %s", (email,))
            if cursor.fetchone()[0] > 0:
                return jsonify({"error": "Email already exists"}), 409

            # Hash the password
            password_hash = generate_password_hash(password)

            # Insert new user with hashed password
            cursor.execute("""
                INSERT INTO Users (username, email, role, password_hash, security, answer)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (username, email, role, password_hash, security, answer))

            # Commit to save the insert
            conn.commit()

            # Get the newly created user's ID
            user_id = cursor.lastrowid

            # Auto-login the user by setting session data
            session['user_id'] = user_id
            session['username'] = username
            session['role'] = role
            session['email'] = email
            session['security'] = security

            # Log the registration activity
            try:
                log_activity(user_id, "User_Registration", f"User {username} registered and logged in")
            except Exception as log_error:
                # Just print the error but don't stop the registration process
                print(f"Error logging activity: {log_error}")

            return jsonify({
                "message": "Registration successful",
                "user": {
                    "id": user_id,
                    "username": username,
                    "role": role,
                    "email": email,
                    "security": security
                }
            }), 201

        except Exception as e:
            print(f"Database Error: {e}")
            return jsonify({"error": f"Registration failed: {str(e)}"}), 500
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    except Exception as e:
        print(f"General Registration Error: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500

# User login route
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    user_id = data.get('user_id')
    username = data.get('username')
    password = data.get('password')

    if not user_id or not username or not password:
        return jsonify({"error": "User ID, username, and password are required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(buffered=True)  # Using buffered cursor for MySQL

        # First check if user_id and username match and get email
        cursor.execute("""
            SELECT user_id, username, password_hash, role, email
            FROM Users
            WHERE user_id = %s AND username = %s
        """, (user_id, username))

        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Invalid User ID or username"}), 401

        # Now verify the password
        stored_password = user[2]

        # Check if it's a hashed password or plain text (for backward compatibility)
        if stored_password.startswith('pbkdf2:sha256:') or stored_password.startswith('scrypt:'):
            # It's a hashed password
            is_password_correct = check_password_hash(stored_password, password)
        else:
            # It's a plain text password (not recommended)
            is_password_correct = (stored_password == password)

        if not is_password_correct:
            return jsonify({"error": "Invalid password"}), 401

        # Set session data - now including email
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['role'] = user[3]
        session['email'] = user[4]  # Store email in session

        # Log activity
        try:
            log_activity(user[0], "User_Login", f"User {username} logged in")
        except Exception as log_error:
            print(f"Error logging activity: {log_error}")

        return jsonify({
            "message": "Login successful",
            "user": {
                "id": user[0],
                "username": user[1],
                "role": user[3],
                "email": user[4]
            }
        }), 200

    except Exception as e:
        print(f"Login Error: {e}")
        return jsonify({"error": f"Login failed: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Verify identity endpoint
@app.route('/api/verify-identity', methods=['POST'])
def api_verify_identity():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    security = data.get('security')
    answer = data.get('answer')

    if not username or not email or not security or not answer:
        return jsonify({"error": "All fields are required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(buffered=True)  # Using buffered cursor for MySQL

        # Fetch user data based on username and email (case-insensitive match)
        # MySQL LOWER() function for case-insensitive matching
        cursor.execute("""
            SELECT user_id, security, answer
            FROM Users
            WHERE LOWER(username) = LOWER(%s) AND LOWER(email) = LOWER(%s)
        """, (username, email))

        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Invalid username or email."}), 404

        user_id = user[0]
        stored_question = user[1]
        stored_answer = user[2]

        # Validate security question and answer (case-insensitive)
        if str(stored_question) != str(security):
            return jsonify({"error": "Incorrect security question selected."}), 400

        if stored_answer.lower().strip() != answer.lower().strip():
            return jsonify({"error": "Incorrect security answer."}), 400

        # Return success with user_id for the next step
        return jsonify({
            "message": "Identity verified successfully.",
            "user_id": user_id,
            "username": username
        }), 200
    except Exception as e:
        print(f"Identity Verification Error: {e}")
        return jsonify({"error": f"Failed to verify identity: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

# Password reset endpoint
@app.route('/api/forgot-password', methods=['POST'])
def api_forgot_password():
    data = request.json
    user_id = data.get('user_id')
    new_password = data.get('new_password')

    if not user_id or not new_password:
        return jsonify({"error": "User ID and new password are required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(buffered=True)  # Using buffered cursor for MySQL

        # Get username for activity log
        cursor.execute("SELECT username FROM Users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "User not found."}), 404

        username = user[0]

        # Update password
        new_password_hash = generate_password_hash(new_password)

        cursor.execute("""
            UPDATE Users
            SET password_hash = %s
            WHERE user_id = %s
        """, (new_password_hash, user_id))

        conn.commit()

        # Optional: Log password reset
        try:
            log_activity(user_id, "Password_Reset", f"User {username} reset their password.")
        except Exception as log_error:
            print(f"Failed to log activity: {log_error}")
            # Continue anyway, not critical

        return jsonify({"message": "Password updated successfully."}), 200
    except Exception as e:
        print(f"Forgot Password Error: {e}")
        return jsonify({"error": f"Failed to reset password: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

# CORS handlers for preflight requests
@app.route('/api/verify-identity', methods=['OPTIONS'])
def handle_options_verify_identity():
    response = make_response()
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'POST')
    return response

@app.route('/api/forgot-password', methods=['OPTIONS'])
def handle_options_forgot_password():
    response = make_response()
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'POST')
    return response

# User profile endpoint
@app.route('/api/user-profile', methods=['GET'])
def get_user_profile():
    # Check if user is logged in
    if 'user_id' not in session:
        return jsonify({"error": "User not authenticated", "success": False}), 401

    try:
        conn = get_db_connection()
        cursor = conn.cursor(buffered=True)  # Using buffered cursor for MySQL

        # Get user data from database to ensure it's up-to-date
        cursor.execute("""
            SELECT user_id, username, role, email
            FROM Users
            WHERE user_id = %s
        """, (session['user_id'],))

        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found", "success": False}), 404

        return jsonify({
            "success": True,
            "user": {
                "id": user[0],
                "username": user[1],
                "role": user[2],
                "email": user[3]
            }
        }), 200

    except Exception as e:
        print(f"Profile Error: {e}")
        return jsonify({"error": f"Failed to retrieve profile: {str(e)}", "success": False}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Check authentication status endpoint
@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if 'user_id' in session:
        return jsonify({
            "authenticated": True,
            "user": {
                "id": session.get('user_id'),
                "username": session.get('username'),
                "role": session.get('role')
            }
        }), 200
    else:
        return jsonify({"authenticated": False}), 401

# User logout endpoint
@app.route('/api/logout', methods=['POST'])
def api_logout():
    if 'user_id' in session:
        user_id = session['user_id']
        username = session.get('username', '')
        session.clear()
        try:
            log_activity(user_id, "User_Logout", f"User {username} logged out")
        except Exception as e:
            print(f"Error logging logout: {e}")
        return jsonify({"message": "Logout successful"}), 200
    return jsonify({"message": "Not logged in"}), 200

# Serve the registration page
@app.route('/register')
def register_page():
    if 'user_id' in session:
        return redirect(url_for('app_page'))
    return send_from_directory('static', 'register.html')

# Function to parse natural language queries using Gemini API
def parse_query_with_gemini(query, user_projects=None, context=None):
    try:
        model = genai.GenerativeModel("models/gemini-1.5-flash")
        # Bot name
        bot_name = "Gemmo"
        # If we have user-specific projects, include them in the context
        project_context = ""
        if user_projects:
            project_names = [p['project_name'] for p in user_projects]
            project_context = f"Consider only these projects: {', '.join(project_names)}. "
        # Add context-specific instructions to the prompt
        additional_instructions = ""
        if context == "termination":
            additional_instructions = """
            If the query indicates termination of the session (e.g., 'terminate', 'cancel', 'exit'), respond with:
            ACTION: terminate_session
            """
        elif context == "confirmation":
            additional_instructions = """
            If the query confirms an action (e.g., 'yes', 'ok'), respond with:
            ACTION: confirmation
            INTENT: CONFIRM
            If the query denies an action (e.g., 'no'), respond with:
            ACTION: confirmation
            INTENT: DENY
            If the query is ambiguous, respond with:
            ACTION: confirmation
            INTENT: UNKNOWN
            """
        elif context == "priority":
            additional_instructions = """
            If the query specifies a priority (e.g., 'low', 'medium', 'high'), respond with:
            ACTION: priority
            PRIORITY: [extracted priority]
            """
        # New context for general user interaction
        additional_instructions += f"""
        If the query is a greeting, respond with:
        ACTION: greeting
        RESPONSE: [greeting response from {bot_name} mentioning the bot's name]
        If the query expresses gratitude, respond with:
        ACTION: gratitude
        RESPONSE: [gratitude acknowledgment from {bot_name} with the {bot_name} mentioning the bot's name]
        If the query is about your capabilities or features, respond with:
        ACTION: show_features
        RESPONSE: [short summary of what {bot_name} can do]
        If the query is asking for your name, respond with:
        ACTION: bot_identity
        RESPONSE: [response mentioning the bot's name and purpose]
        """
        # Construct the full prompt
        prompt = f"""{project_context}
        Interpret this project management query: "{query}"
        {additional_instructions}
        If the query is about checking a project's status, respond with:
        ACTION: get_project_status
        PROJECT_NAME: [extracted project name]
        If the query is about checking a task's status, respond with:
        ACTION: get_task_status
        TASK_NAME: [extracted task name]
        If the query is about checking a user's activity or asking about a user, respond with:
        ACTION: get_user_activity
        USER_NAME: [extracted user name]
        If the query is about updating a task status, respond with:
        ACTION: update_task_status
        TASK_NAME: [extracted task name]
        NEW_STATUS: [extracted new status]
        If the query is about updating a project status, respond with:
        ACTION: update_project_status
        NEW_STATUS: [extracted new status]
        PROJECT_NAME: [extracted project name]
        If the query is about adding a new project, respond with:
        ACTION: start_add_project
        If the query is about adding a new task, respond with:
        ACTION: start_add_task
        If the query is about listing or all Users, to get all Users details respond with:
        ACTION: list_all_users
        If the query is about listing pending projects, respond with:
        ACTION: list_pending_projects
        If the query is about listing completed projects, respond with:
        ACTION: list_completed_projects
        If the query is about listing all projects with their status, respond with:
        ACTION: list_all_projects_status
        If the query is about listing pending tasks, respond with:
        ACTION: list_pending_tasks
        If the query is about listing completed tasks, respond with:
        ACTION: list_completed_tasks
        If the query is about listing all tasks with their status, respond with:
        ACTION: list_all_tasks_status
        If the query is about listing low-priority tasks, respond with:
        ACTION: list_low_priority_tasks
        If the query is about listing medium-priority tasks, respond with:
        ACTION: list_medium_priority_tasks
        If the query is about listing high-priority tasks, respond with:
        ACTION: list_high_priority_tasks
        If the query is ambiguous, respond with:
        ACTION: ambiguous
        REASON: [reason for ambiguity]
        If the query doesn't match any known action, respond with:
        ACTION: invalid
        """
        interpreted_query = model.generate_content(prompt)
        interpreted_text = interpreted_query.text.strip()
        print(f"Interpreted Query: {interpreted_text}")

        # Fix line continuation issue in regex
        lines = interpreted_text.splitlines()
        interpreted_text = '\n'.join(lines)

        # Extract action
        action_match = re.search(r"ACTION:\s*(\w+)", interpreted_text)
        if not action_match:
            return {"error": "Could not parse query"}
        action = action_match.group(1).lower()

        if action == "ambiguous":
            reason_match = re.search(r"REASON:\s*(.+)$", interpreted_text, re.MULTILINE | re.DOTALL)
            reason = reason_match.group(1).strip() if reason_match else "Query is ambiguous"
            return {"error": f"Ambiguous query. {reason}"}
        elif action == "invalid":
            return {"error": "Invalid query. Please try a different command."}
        elif action in {"greeting", "gratitude", "show_features", "bot_identity"}:
            response_match = re.search(r"RESPONSE:\s*(.+)$", interpreted_text, re.MULTILINE | re.DOTALL)
            return {"action": action, "response": response_match.group(1).strip() if response_match else ""}
        elif action == "get_project_status":
            project_match = re.search(r"PROJECT_NAME:\s*(.+)$", interpreted_text, re.MULTILINE)
            if not project_match:
                return {"error": "Could not identify project name"}
            return {"action": "get_project_status", "project_name": project_match.group(1).strip()}
        elif action == "get_task_status":
            task_match = re.search(r"TASK_NAME:\s*(.+)$", interpreted_text, re.MULTILINE)
            if not task_match:
                return {"error": "Could not identify task name"}
            return {"action": "get_task_status", "task_name": task_match.group(1).strip()}
        elif action == "get_user_activity":
            user_match = re.search(r"USER_NAME:\s*(.+)$", interpreted_text, re.MULTILINE)
            if not user_match:
                return {"error": "Could not identify user name"}
            return {"action": "get_user_activity", "user_name": user_match.group(1).strip()}
        elif action == "update_project_status":
            status_match = re.search(r"NEW_STATUS:\s*(.+)$", interpreted_text, re.MULTILINE)
            project_match = re.search(r"PROJECT_NAME:\s*(.+)$", interpreted_text, re.MULTILINE)
            if not (status_match and project_match):
                return {"error": "Missing information for updating project status"}
            return {
                "action": "update_project_status",
                "new_status": status_match.group(1).strip(),
                "project_name": project_match.group(1).strip()
            }
        elif action == "update_task_status":
            task_match = re.search(r"TASK_NAME:\s*(.+)$", interpreted_text, re.MULTILINE)
            status_match = re.search(r"NEW_STATUS:\s*(.+)$", interpreted_text, re.MULTILINE)
            if not (task_match and status_match):
                return {"error": "Missing information for updating task status"}
            return {
                "action": "update_task_status",
                "task_name": task_match.group(1).strip(),
                "new_status": status_match.group(1).strip()
            }
        elif action == "start_add_project":
            return {"action": "start_add_project"}
        elif action == "start_add_task":
            return {"action": "start_add_task"}
        elif action == "list_all_users":
            return {"action": "list_all_users"}
        elif action == "list_pending_projects":
            return {"action": "list_pending_projects"}
        elif action == "list_completed_projects":
            return {"action": "list_completed_projects"}
        elif action == "list_all_projects_status":
            return {"action": "list_all_projects_status"}
        elif action == "list_pending_tasks":
            return {"action": "list_pending_tasks"}
        elif action == "list_completed_tasks":
            return {"action": "list_completed_tasks"}
        elif action == "list_all_tasks_status":
            return {"action": "list_all_tasks_status"}
        elif action == "list_low_priority_tasks":
            return {"action": "list_low_priority_tasks"}
        elif action == "list_medium_priority_tasks":
            return {"action": "list_medium_priority_tasks"}
        elif action == "list_high_priority_tasks":
            return {"action": "list_high_priority_tasks"}
        elif action == "confirmation":
            intent_match = re.search(r"INTENT:\s*(\w+)", interpreted_text)
            if not intent_match:
                return {"error": "Could not determine confirmation intent"}
            return {"action": "confirmation", "intent": intent_match.group(1).upper()}
        elif action == "terminate_session":
            return {"action": "terminate_session"}
        elif action == "priority":
            priority_match = re.search(r"PRIORITY:\s*(\w+)", interpreted_text)
            if not priority_match:
                return {"error": "Could not determine priority"}
            return {"action": "priority", "priority": priority_match.group(1).capitalize()}
        else:
            return {"error": "Invalid action"}
    except Exception as e:
        print(f"Error parsing query with Gemini API: {e}")
        return {"error": str(e)}

#function to format the response to the user
def format_response_with_gemini(data, user_role, context_type, additional_context=None):
    try:
        model = genai.GenerativeModel("models/gemini-1.5-flash")  # Better handling of long prompts

        # Helper to build formatted item lists
        def format_item_list(items, type_name="item"):
            return "<br>".join([
                f"<strong>{item.get(f'{type_name}_name', 'Unnamed')}</strong> (<strong>{item.get('status', 'Unknown')}</strong>) (<strong>{item.get('username', 'Unknown')}</strong>) (<strong>{item.get('user_id', 'Unknown')}</strong>) (<strong>{item.get('role', 'Unknown')}</strong>)"
                for item in items
            ])

        # Helper to process Gemini response in batches
        def generate_batched_response(item_list, prompt_template_func, batch_size=5):
            full_response = ""
            total_items = len(item_list)
            for i in range(0, total_items, batch_size):
                batch = item_list[i:i + batch_size]
                prompt = prompt_template_func(batch)
                response = model.generate_content(prompt)
                batch_response = response.text.strip()
                # Clean up any malformed HTML
                batch_response = batch_response.replace("**", "<strong>")
                open_tags = batch_response.count("<strong>") - batch_response.count("</strong>")
                if open_tags > 0:
                    batch_response += "</strong>" * open_tags
                full_response += batch_response + "<br><br>"
            return full_response.strip()

        # Build prompt based on context
        if context_type == "pending_projects":
            if not data:
                return "No pending projects found."
            print(f"[DEBUG] Pending Projects Count: {len(data)}")
            def prompt_func(batch):
                project_list = format_item_list(batch, "project")
                return f"""
                    You are responding to {user_role}.
                    Here are your pending projects:
                    {project_list}
                    Appreciate their involvement and provide a clear overview of each project with its current status.
                    Include motivational language and recognition of effort.
                    Wrap key names like project titles and statuses in HTML <strong> tags so they can be styled on the frontend.
                    Keep your response under 2-3 sentences and conversational.
                """
            return generate_batched_response(data, prompt_func, batch_size=5)

        elif context_type == "completed_projects":
            if not data:
                return "No completed projects found."
            print(f"[DEBUG] Completed Projects Count: {len(data)}")
            def prompt_func(batch):
                project_list = format_item_list(batch, "project")
                return f"""
                    You are responding to {user_role}.
                    Here are your completed projects:
                    {project_list}
                    Celebrate their achievements and provide a clear overview of each project with its current status.
                    Include motivational language and wrap important terms like project names and statuses in HTML <strong> tags.
                    Keep your response under 2-3 sentences and conversational.
                """
            return generate_batched_response(data, prompt_func, batch_size=5)

        elif context_type == "pending_tasks":
            if not data:
                return "No pending tasks found."
            print(f"[DEBUG] Pending Tasks Count: {len(data)}")
            def prompt_func(batch):
                task_list = format_item_list(batch, "task")
                return f"""
                    You are responding to {user_role}.
                    Here are your pending tasks:
                    {task_list}
                    Recognize their efforts and provide a clear overview of each task with its current status.
                    Include motivational language and wrap important terms like task names and statuses in HTML <strong> tags.
                    Keep your response under 2-3 sentences and conversational.
                """
            return generate_batched_response(data, prompt_func, batch_size=5)

        elif context_type == "completed_tasks":
            if not data:
                return "No completed tasks found."
            print(f"[DEBUG] Completed Tasks Count: {len(data)}")
            def prompt_func(batch):
                task_list = format_item_list(batch, "task")
                return f"""
                    You are responding to {user_role}.
                    Here are your completed tasks:
                    {task_list}
                    Celebrate their progress and provide a clear overview of each task with its current status.
                    Include motivational language and wrap important terms like task names and statuses in HTML <strong> tags.
                    Keep your response under 2-3 sentences and conversational.
                """
            return generate_batched_response(data, prompt_func, batch_size=5)

        elif context_type == "all_users":
            if not data:
                return "No Users found."
            print(f"[DEBUG] Users Count: {len(data)}")
            def prompt_func(batch):
                user_list = format_item_list(batch, "user")
                return f"""
                    You are responding to {user_role}.
                    Here are your Users list:
                    {user_list}
                    Provide a clear overview of each user with their role.
                    Wrap important terms like usernames and user_ids and role in HTML <strong> tags.
                    Keep your response under 2-3 sentences and conversational.
                """
            return generate_batched_response(data, prompt_func, batch_size=5)
        
        elif context_type == "users_activity":
            if not data:
                return "No Activity found."
            print(f"[DEBUG] Activities Count: {len(data)}")
            def prompt_func(batch):
                activity_list = format_item_list(batch, "user")
                return f"""
                    You are responding to {user_role}.
                    Here are your Users list:
                    {activity_list}
                    List out all the Activities of the User properly and Provide a clear overview of each User's Activity like Project_Creation, Task_Creation, Project_Status_Update, Task_Status_Update and Password_Reset.
                    Wrap important terms like usernames and  and activity_type and description in HTML <strong> tags.
                    Keep your response under 2-3 sentences and conversational.
                """
            return generate_batched_response(data, prompt_func, batch_size=5)

        elif context_type == "priority_tasks":
            priority_level = additional_context if additional_context else "specified"
            if not data:
                return f"No {priority_level}-priority tasks found."
            print(f"[DEBUG] Priority ({priority_level}) Tasks Count: {len(data)}")
            def prompt_func(batch):
                task_list = format_item_list(batch, "task")
                return f"""
                    You are responding to {user_role}.
                    Here are your {priority_level}-priority tasks:
                    {task_list}
                    Acknowledge their focus and provide a clear overview of each task with its current status.
                    Include motivational language and wrap important terms like task names and statuses in HTML <strong> tags.
                    Keep your response under 2-3 sentences and conversational.
                """
            return generate_batched_response(data, prompt_func, batch_size=5)

        elif context_type == "all_projects_status":
            if not data:
                return "No projects found."
            print(f"[DEBUG] All Projects Status Count: {len(data)}")
            def prompt_func(batch):
                project_list = format_item_list(batch, "project")
                return f"""
                    You are responding to {user_role}.
                    Here is the current status of all your projects:
                    {project_list}
                    Appreciate their involvement and provide a clear overview of each project with its current status.
                    Include motivational language and wrap important terms in HTML <strong> tags.
                    Keep your response under 2-3 sentences and conversational.
                """
            return generate_batched_response(data, prompt_func, batch_size=5)

        elif context_type == "all_tasks_status":
            if not data:
                return "No tasks found."
            print(f"[DEBUG] All Tasks Status Count: {len(data)}")
            def prompt_func(batch):
                task_list = format_item_list(batch, "task")
                return f"""
                    You are responding to {user_role}.
                    Here is the current status of all your tasks:
                    {task_list}
                    Recognize their contributions and motivate them.
                    Include motivational language and wrap important terms in HTML <strong> tags.
                    Keep your response under 2-3 sentences and conversational.
                """
            return generate_batched_response(data, prompt_func, batch_size=5)

        elif context_type == "project_status":
            project_name = additional_context.get("project_name", "the project")
            status = additional_context.get("status", "Unknown")
            prompt = f"You are responding to {user_role}. Generate a brief message about the status of project '<strong>{project_name}</strong>', which is currently '<strong>{status}</strong>'."
            response = model.generate_content(prompt)
            formatted_response = response.text.strip()
            return formatted_response.replace("**", "<strong>").replace("\n", "<br>")

        elif context_type == "task_status":
            task_name = additional_context.get("task_name", "the task")
            status = additional_context.get("status", "Unknown")
            prompt = f"You are responding to {user_role}. Generate a brief message about the status of task '<strong>{task_name}</strong>', which is currently '<strong>{status}</strong>'."
            response = model.generate_content(prompt)
            formatted_response = response.text.strip()
            return formatted_response.replace("**", "<strong>").replace("\n", "<br>")

        elif context_type == "update_success":
            item_type = additional_context.get("type", "item")
            item_name = additional_context.get("name", "the item")
            new_status = additional_context.get("new_status", "updated")
            prompt = f"You are responding to {user_role}. Generate a brief confirmation message that the {item_type} '<strong>{item_name}</strong>' has been successfully updated to status '<strong>{new_status}</strong>'."
            response = model.generate_content(prompt)
            formatted_response = response.text.strip()
            return formatted_response.replace("**", "<strong>").replace("\n", "<br>")

        else:
            prompt = f"Generate a brief response about the {context_type} data for {user_role}. Use HTML <strong> tags to highlight important information."
            prompt += " Keep your response under 2-3 sentences and conversational. Make sure to use HTML <strong> tags for formatting instead of Markdown or other formats."
            response = model.generate_content(prompt)
            formatted_response = response.text.strip()
            return formatted_response.replace("**", "<strong>").replace("\n", "<br>")

    except Exception as e:
        print(f"Gemini API Error: {e}")
        if not data:
            return f"No <strong>{context_type.replace('_', ' ')}</strong> found."
        elif isinstance(data, list):
            return f"Found <strong>{len(data)}</strong> {context_type.replace('_', ' ')}."
        else:
            return f"Information about <strong>{context_type.replace('_', ' ')}</strong> is available."

# Serve the login page as default route
@app.route('/')
def login():
    if 'user_id' in session:
        return redirect(url_for('app_page'))
    return send_from_directory('static', 'login.html')

# Serve the main application page with authentication requirement
@app.route('/app')
def app_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return send_from_directory('static', 'index.html')

# Serve static files
@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

# Modified route to fetch project status data for the pie chart (with role-based filtering)
@app.route('/get_project_status', methods=['GET'])
@login_required
def get_project_status():
    user_id = session.get('user_id')
    role = session.get('role', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # For admin, show all projects
        if role.lower() == 'admin':
            cursor.execute("""
    SELECT status, COUNT(*) AS count
    FROM Projects
    GROUP BY status
""")
            rows = cursor.fetchall()
            if not rows:
                return jsonify({"labels": [], "data": []}), 200

            data = {
                "labels": [row[0] for row in rows],
                "data": [row[1] for row in rows]
            }
            return jsonify(data), 200
        else:
            # For regular users, we need to query projects they created and are assigned to separately and merge results
            projects_set = set()
            status_count = {}

            # First, get projects created by the user
            cursor.execute("""
    SELECT status
    FROM Projects
    WHERE created_by = %s
""", (user_id,))
            for row in cursor.fetchall():
                status = row[0]
                if status not in status_count:
                    status_count[status] = 0
                status_count[status] += 1

            # Second, get projects the user is assigned to via tasks (need to avoid double counting)
            cursor.execute("""
    SELECT p.project_id, p.status
    FROM Projects p
    INNER JOIN Tasks t ON p.project_id = t.project_id
    WHERE t.assigned_to = %s
""", (user_id,))
            for row in cursor.fetchall():
                project_id, status = row[0], row[1]
                # Only count if we haven't seen this project_id before
                if project_id not in projects_set:
                    projects_set.add(project_id)
                    if status not in status_count:
                        status_count[status] = 0
                    status_count[status] += 1

            # Convert the dictionary to lists for the response
            labels = list(status_count.keys())
            data = [status_count[label] for label in labels]

            return jsonify({"labels": labels, "data": data}), 200
    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# Helper function to get accessible projects for a user
def get_user_accessible_projects(user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # For admin, return all projects
        if role.lower() == 'admin':
            cursor.execute("SELECT project_id, project_name FROM Projects")
            rows = cursor.fetchall()
            return [{"project_id": row[0], "project_name": row[1]} for row in rows]
        else:
            # For regular users, we need to query projects they created and are assigned to separately
            projects = {}

            # Get projects created by user
            cursor.execute("""
    SELECT project_id, project_name FROM Projects WHERE created_by = %s
""", (user_id,))
            for row in cursor.fetchall():
                project_id, project_name = row[0], row[1]
                projects[project_id] = {"project_id": project_id, "project_name": project_name}

            # Get projects user is assigned to via tasks
            cursor.execute("""
    SELECT DISTINCT p.project_id, p.project_name
    FROM Projects p
    INNER JOIN Tasks t ON p.project_id = t.project_id
    WHERE t.assigned_to = %s
""", (user_id,))
            for row in cursor.fetchall():
                project_id, project_name = row[0], row[1]
                projects[project_id] = {"project_id": project_id, "project_name": project_name}

            return list(projects.values())
    except Exception as e:
        print(f"Error fetching user projects: {e}")
        return []
    finally:
        conn.close()

# Modified route to handle natural language queries (with role-based filtering)
@app.route('/query', methods=['POST'])
@login_required
def handle_query():
    data = request.json
    query = data.get('query')
    user_id = session.get('user_id')
    role = session.get('role', '')

    if not query:
        return jsonify({"error": "'query' must be provided."}), 400

    # Check if the user is in a session (e.g., adding a new project)
    if session.get("in_session") == "add_project":
        response = handle_add_project_session(user_id, query)
        return response  # Return the response directly to the frontend

    if session.get("in_session") == "add_task":
        response = handle_add_task_session(user_id, query, role)
        return response  # Return the response directly to the frontend

    # Get the projects accessible to this user for context
    user_projects = get_user_accessible_projects(user_id, role)

    # Parse the query using Gemini API (with user's project context)
    parsed_data = parse_query_with_gemini(query, user_projects)

    if "error" in parsed_data:
        return jsonify({"error": parsed_data["error"]}), 400

    action = parsed_data.get("action")

    # ✅ Explicitly handle greetings, gratitude, identity, features
    if action == "greeting":
        return jsonify({"message": parsed_data["response"]}), 200
    elif action == "gratitude":
        return jsonify({"message": parsed_data["response"]}), 200
    elif action == "bot_identity":
        return jsonify({"message": parsed_data["response"]}), 200
    elif action == "show_features":
        return jsonify({"message": parsed_data["response"]}), 200

    # Continue with original action handling
    if action == "start_add_project":
        session["in_session"] = "add_project"
        session["project_details"] = {}
        return jsonify({"message": "Sure! Let's add a new project. Please provide the title of the project."}), 200

    elif action == "start_add_task":
        if role.lower() != 'admin':
            return jsonify({"error": "Only admins can assign tasks. You can view tasks assigned to you."}), 403
        else:
            session["in_session"] = "add_task"
            session["task_details"] = {}
            return jsonify({"message": "Sure! Let's add a new task. Please provide the name of the task."}), 200

    elif action == "list_all_users":
        if role.lower() != 'admin':
            return jsonify({"error": "Only admins can see all Users."}), 403
        else:
            return get_all_users(role)

    elif action == "list_pending_projects":
        return get_pending_projects(user_id, role)

    elif action == "list_completed_projects":
        return get_completed_projects(user_id, role)

    elif action == "list_all_projects_status":
        return list_all_projects_status(user_id, role)

    elif action == "get_project_status":
        project_name = parsed_data.get("project_name")
        if not project_name:
            return jsonify({"error": "Project name not provided"}), 400
        return get_project_status_by_name(project_name, user_id, role)

    elif action == "list_pending_tasks":
        return get_pending_tasks(user_id, role)

    elif action == "list_completed_tasks":
        return get_completed_tasks(user_id, role)

    elif action == "list_all_tasks_status":
        return list_all_tasks_status(user_id, role)

    elif action == "list_low_priority_tasks":
        return get_low_priority_tasks(user_id, role)

    elif action == "list_medium_priority_tasks":
        return get_medium_priority_tasks(user_id, role)

    elif action == "list_high_priority_tasks":
        return get_high_priority_tasks(user_id, role)

    elif action == "get_task_status":
        task_name = parsed_data.get("task_name")
        if not task_name:
            return jsonify({"error": "Task name not provided"}), 400
        return get_task_status_by_name(task_name, user_id, role)

    elif action == "get_user_activity":
        if role.lower() != 'admin':
            return jsonify({"error": "Only admins can access a specific user's Activity."}), 403
        else:
            user_name = parsed_data.get("user_name")
            if not user_name:
                return jsonify({"error": "User name not provided"}), 400
            return get_user_activity(user_name, role)

    elif action == "update_task_status":
        return update_task_status(parsed_data, user_id, role)

    elif action == "update_project_status":
        return update_project_status(parsed_data, user_id, role)

    else:
        return jsonify({"error": "Invalid query"}), 400

# Function to handle the "Add a new project" session
def handle_add_project_session(user_id, query):
    project_details = session.get("project_details", {})
    if "project_name" not in project_details:
        project_details["project_name"] = query.strip()
        session["project_details"] = project_details
        return jsonify({"message": "Got it! Now please provide the description of the project."}), 200
    elif "description" not in project_details:
        project_details["description"] = query.strip()
        session["project_details"] = project_details
        return jsonify({"message": "Great! Now please provide the start date of the project (format: YYYY-MM-DD)."}), 200
    elif "start_date" not in project_details:
        project_details["start_date"] = query.strip()
        session["project_details"] = project_details
        return jsonify({"message": "Great! Now please provide the end date of the project (format: YYYY-MM-DD)."}), 200
    elif "end_date" not in project_details:
        project_details["end_date"] = query.strip()
        session.pop("in_session")
        session.pop("project_details")
        return insert_project(user_id, project_details)

# Function to insert a new project
def insert_project(user_id, data):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
    INSERT INTO Projects (project_name, description, start_date, end_date, status, created_by)
    VALUES (%s, %s, %s, %s, %s, %s)""", (data['project_name'], data['description'], data['start_date'], data['end_date'], 'Pending', user_id))
        conn.commit()
        log_activity(user_id, "Project_Creation", f"Created project: {data['project_name']}")
        # Format success message using Gemini
        success_message = format_response_with_gemini(
            None,  # No data required for this context
            "user",  # Assuming standard user response
            "update_success",
            {"type": "project", "name": data['project_name'], "new_status": "created"}
        )

        return jsonify({"message": success_message}), 200
    finally:
        conn.close()


# Function to handle the "Add a new task" session
def handle_add_task_session(user_id, query, role):
    task_details = session.get("task_details", {})

    # Step 1: Collect task name
    if "task_name" not in task_details:
        if not query.strip():
            return jsonify({"error": "Task name cannot be empty."}), 400
        task_details["task_name"] = query.strip()
        session["task_details"] = task_details
        return jsonify({"message": "Got it! Now please provide the description of the task."}), 200

    # Step 2: Collect task description
    elif "description" not in task_details:
        if not query.strip():
            return jsonify({"error": "Task description cannot be empty."}), 400
        task_details["description"] = query.strip()
        session["task_details"] = task_details
        return jsonify({"message": "Great! Now please specify the user ID of the person this task is assigned to."}), 200

    # Step 3: Collect assigned_to (user ID)
    elif "assigned_to" not in task_details:
        try:
            assigned_to = int(query.strip())

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM Users WHERE user_id = %s", (assigned_to,))
            result = cursor.fetchone()
            cursor.close()
            conn.close()

            if not result:
                return jsonify({"error": f"No user found with user_id {assigned_to}. Please provide a valid user ID."}), 400

            username = result[0]
            task_details["assigned_to"] = assigned_to
            task_details["assigned_username"] = username
            session["task_details"] = task_details

            return jsonify({
                "message": f"You are assigning the task '{task_details['task_name']}' to '{username}'. Is this okay? Please reply with 'yes' or 'no'."
            }), 200

        except ValueError:
            return jsonify({"error": "Invalid user ID. Please provide a valid numeric user ID."}), 400

    # Step 4: Handle confirmation
    elif "confirmation_received" not in task_details:
        normalized_query = query.strip().lower()
        if normalized_query == "yes":
            task_details["confirmation_received"] = True
            session["task_details"] = task_details
            return jsonify({"message": "Great! Now please provide the project ID this task belongs to."}), 200
        elif normalized_query == "no":
            task_details.pop("assigned_to", None)
            task_details.pop("assigned_username", None)
            session["task_details"] = task_details
            return jsonify({"message": "Please provide the user ID of the person this task is assigned to."}), 200
        else:
            return jsonify({"error": "Invalid response. Please reply with 'yes' or 'no'."}), 400

    # ✅ Step 5: Collect and validate project ID
    elif "project_id" not in task_details:
        try:
            project_id = int(query.strip())
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM Projects WHERE project_id = %s", (project_id,))
            result = cursor.fetchone()
            cursor.close()
            conn.close()

            if not result:
                return jsonify({"error": f"No project found with project_id {project_id}."}), 400

            task_details["project_id"] = project_id
            task_details["project_name"] = result[0]
            session["task_details"] = task_details

            return jsonify({
                "message": f"The task will be added to the project '{result[0]}'. Is that okay? Reply 'yes' or 'no'."
            }), 200

        except ValueError:
            return jsonify({"error": "Invalid project ID. Please enter a numeric value."}), 400

    # Step 6: Confirm Project
    elif "project_confirmed" not in task_details:
        response = query.strip().lower()
        if response == "yes":
            task_details["project_confirmed"] = True
            session["task_details"] = task_details
            return jsonify({"message": "Almost done! Please provide the due date (YYYY-MM-DD)."}) ,200
        elif response == "no":
            task_details.pop("project_id")
            task_details.pop("project_name")
            session["task_details"] = task_details
            return jsonify({"message": "Please provide the correct project ID for this task."}), 200
        else:
            return jsonify({"error": "Please reply with 'yes' or 'no'."}), 400

    # Step 6: Collect due date
    elif "due_date" not in task_details:
        try:
            due_date = query.strip()
            if not re.match(r"\d{4}-\d{2}-\d{2}", due_date):
                raise ValueError("Invalid date format")
            task_details["due_date"] = due_date
            session["task_details"] = task_details
            return jsonify({"message": "Great! Now please provide the priority of the task (Low, Medium, High)."}), 200
        except ValueError:
            return jsonify({"error": "Invalid date format. Please use YYYY-MM-DD."}), 400

    # Step 7: Collect priority and insert task
    elif "priority" not in task_details:
        normalized_priority = query.strip().lower()
        priority_map = {
            "low": "Low",
            "medium": "Medium",
            "high": "High"
        }
        if normalized_priority in priority_map:
            task_details["priority"] = priority_map[normalized_priority]

            # Final step: insert into DB
            session.pop("in_session", None)
            session.pop("task_details", None)
            return insert_task(user_id, task_details)
        else:
            return jsonify({"error": "Invalid priority. Please choose from Low, Medium, or High."}), 400

    return jsonify({"error": "An unexpected error occurred during task creation."}), 500

# Function to insert a new task
def insert_task(user_id, data):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
    INSERT INTO Tasks (
        task_name, description, assigned_to, project_id, due_date, status, priority
    ) VALUES (%s, %s, %s, %s, %s, 'Pending', %s)
""", (data['task_name'], data['description'], data['assigned_to'], data['project_id'], data['due_date'], data['priority']))

        conn.commit()
        log_activity(user_id, "Task_Creation", f"Created task: {data['task_name']}")
        # Optional: Use Gemini to generate success message
        success_message = f"✅ The task '{data['task_name']}' has been successfully created with {data['priority']} priority."

        return jsonify({"message": success_message}), 200
    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Failed to create task: {str(e)}"}), 500
    finally:
        conn.close()

# Fixed function to retrieve pending projects (with role-based filtering)
def get_pending_projects(user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    projects = []

    try:
        # For admin, show all pending projects
        if role.lower() == 'admin':
            cursor.execute("SELECT project_id, project_name, start_date, end_date, status FROM Projects WHERE status = 'Pending'")
            rows = cursor.fetchall()
            projects = [{"project_id": row[0], "project_name": row[1], "start_date": row[2], "end_date": row[3], "status": row[4]} for row in rows]
        else:
            # Get projects the user created with 'Pending' status
            cursor.execute("""
    SELECT project_id, project_name, start_date, end_date, status
    FROM Projects
    WHERE status = 'Pending' AND created_by = %s
""", (user_id,))
            rows = cursor.fetchall()
            projects_dict = {}
            for row in rows:
                project_id = row[0]
                if project_id not in projects_dict:
                    projects_dict[project_id] = {"project_id": project_id, "project_name": row[1], "start_date": row[2], "end_date": row[3], "status": row[4]}

            # Get 'Pending' projects the user is assigned to via tasks
            cursor.execute("""
    SELECT DISTINCT p.project_id, p.project_name, p.start_date, p.end_date, p.status
    FROM Projects p
    INNER JOIN Tasks t ON p.project_id = t.project_id
    WHERE p.status = 'Pending' AND t.assigned_to = %s
""", (user_id,))
            rows = cursor.fetchall()
            for row in rows:
                project_id = row[0]
                if project_id not in projects_dict:
                    projects_dict[project_id] = {"project_id": project_id, "project_name": row[1], "start_date": row[2], "end_date": row[3], "status": row[4]}

            projects = list(projects_dict.values())

        # Process the data using Gemini API
        response_message = format_response_with_gemini(projects, role, "pending_projects")

        # Return the formatted response along with the raw data
        return jsonify({
            "message": response_message,
            "projects": projects
        }), 200

    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# Fixed function to retrieve completed projects (with role-based filtering)
def get_completed_projects(user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    projects = []

    try:
        # For admin, show all completed projects
        if role.lower() == 'admin':
            cursor.execute("SELECT project_id, project_name, start_date, end_date, status FROM Projects WHERE status = 'Completed'")
            rows = cursor.fetchall()
            projects = [{"project_id": row[0], "project_name": row[1], "start_date": row[2], "end_date": row[3], "status": row[4]} for row in rows]
        else:
            # Get projects the user created with 'Completed' status
            cursor.execute("""
    SELECT project_id, project_name, start_date, end_date, status
    FROM Projects
    WHERE status = 'Completed' AND created_by = %s
""", (user_id,))
            rows = cursor.fetchall()
            projects_dict = {}
            for row in rows:
                project_id = row[0]
                if project_id not in projects_dict:
                    projects_dict[project_id] = {"project_id": project_id, "project_name": row[1], "start_date": row[2], "end_date": row[3], "status": row[4]}

            # Get 'Completed' projects the user is assigned to via tasks
            cursor.execute("""
    SELECT DISTINCT p.project_id, p.project_name, p.start_date, p.end_date, p.status
    FROM Projects p
    INNER JOIN Tasks t ON p.project_id = t.project_id
    WHERE p.status = 'Completed' AND t.assigned_to = %s
""", (user_id,))
            rows = cursor.fetchall()
            for row in rows:
                project_id = row[0]
                if project_id not in projects_dict:
                    projects_dict[project_id] = {"project_id": project_id, "project_name": row[1], "start_date": row[2], "end_date": row[3], "status": row[4]}

            projects = list(projects_dict.values())

        # Process the data using Gemini API
        response_message = format_response_with_gemini(projects, role, "completed_projects")

        # Return the formatted response along with the raw data
        return jsonify({
            "message": response_message,
            "projects": projects
        }), 200

    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# Fixed function to retrieve the status of all projects (with role-based filtering)
def list_all_projects_status(user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    projects = []

    try:
        # For admin, show status of all projects
        if role.lower() == 'admin':
            cursor.execute("SELECT project_name, status FROM Projects")
            rows = cursor.fetchall()
            projects = [{"project_name": row[0], "status": row[1]} for row in rows]
        else:
            # Get projects the user created
            cursor.execute("""
    SELECT project_name, status
    FROM Projects
    WHERE created_by = %s
""", (user_id,))
            rows = cursor.fetchall()
            projects_dict = {}
            for row in rows:
                project_name = row[0]
                if project_name not in projects_dict:
                    projects_dict[project_name] = {"project_name": project_name, "status": row[1]}

            # Get projects the user is assigned to via tasks
            cursor.execute("""
    SELECT DISTINCT p.project_name, p.status
    FROM Projects p
    INNER JOIN Tasks t ON p.project_id = t.project_id
    WHERE t.assigned_to = %s
""", (user_id,))
            rows = cursor.fetchall()
            for row in rows:
                project_name = row[0]
                if project_name not in projects_dict:
                    projects_dict[project_name] = {"project_name": project_name, "status": row[1]}

            projects = list(projects_dict.values())

        # Process the data using Gemini API
        response_message = format_response_with_gemini(projects, role, "all_projects_status")

        # Return the formatted response along with the raw data
        return jsonify({
            "message": response_message,
            "projects": projects
        }), 200

    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# Fixed function to retrieve the status of a specific project (with access check)
def get_project_status_by_name(project_name, user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # First get the project ID to check access - add better error handling and logging
        print(f"Querying project: '{project_name}'")

        # Fix parameter binding by using a tuple
        cursor.execute("SELECT project_id, status FROM Projects WHERE project_name = %s", (project_name,))
        result = cursor.fetchone()

        if not result:
            print(f"Project not found: '{project_name}'")
            return {"error": "Project not found"}, 404

        project_id, status = result
        print(f"Found project_id: {project_id}, status: {status}")

        # Check if user has access to this project
        has_access = user_has_access_to_project(user_id, role, project_id, conn)
        print(f"User {user_id} with role {role} has access to project {project_id}: {has_access}")

        if not has_access:
            return {"error": "You do not have access to this project"}, 403

        # Process the data using Gemini API
        project_data = {"project_name": project_name, "status": status}
        response_message = format_response_with_gemini(
            None,  # No list data
            role,
            "project_status",
            project_data
        )

        # Return the formatted response along with the raw data
        return jsonify({
            "message": response_message,
            "project": project_data
        }), 200

    except Exception as e:
        print(f"Database Error in get_project_status_by_name: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    finally:
        conn.close()

# Function to retrieve pending tasks (with role-based filtering)
def get_pending_tasks(user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    tasks = []

    try:
        # For admin, show all pending tasks
        if role.lower() == 'admin':
            cursor.execute("SELECT task_id, task_name, description, due_date, priority FROM Tasks WHERE status = 'Pending'")
            rows = cursor.fetchall()
            tasks = [{"task_id": row[0], "task_name": row[1], "description": row[2], "due_date": row[3], "priority": row[4]} for row in rows]
        else:
            # Get tasks assigned to the user with 'Pending' status
            cursor.execute("""
    SELECT task_id, task_name, description, due_date, priority
    FROM Tasks
    WHERE status = 'Pending' AND assigned_to = %s
""", (user_id,))
            rows = cursor.fetchall()
            tasks = [{"task_id": row[0], "task_name": row[1], "description": row[2], "due_date": row[3], "priority": row[4]} for row in rows]

        # Return the tasks directly - will be sent to frontend
        # Process the data using Gemini API
        response_message = format_response_with_gemini(tasks, role, "pending_tasks")

        # Return the formatted response along with the raw data
        return jsonify({
            "message": response_message,
            "tasks": tasks
        }), 200

    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# Function to retrieve completed tasks (with role-based filtering)
def get_completed_tasks(user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    tasks = []

    try:
        # For admin, show all completed tasks
        if role.lower() == 'admin':
            cursor.execute("SELECT task_id, task_name, description, due_date, priority FROM Tasks WHERE status = 'Completed'")
            rows = cursor.fetchall()
            tasks = [{"task_id": row[0], "task_name": row[1], "description": row[2], "due_date": row[3], "priority": row[4]} for row in rows]
        else:
            # Get tasks assigned to the user with 'Completed' status
            cursor.execute("""
    SELECT task_id, task_name, description, due_date, priority
    FROM Tasks
    WHERE status = 'Completed' AND assigned_to = %s
""", (user_id,))

            rows = cursor.fetchall()
            tasks = [{"task_id": row[0], "task_name": row[1], "description": row[2], "due_date": row[3], "priority": row[4]} for row in rows]

        # Process the data using Gemini API
        response_message = format_response_with_gemini(tasks, role, "completed_tasks")

        # Return the formatted response along with the raw data
        return jsonify({
            "message": response_message,
            "tasks": tasks
        }), 200

    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# Function to retrieve all tasks with their status (with role-based filtering)
def list_all_tasks_status(user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    tasks = []

    try:
        # For admin, show status of all tasks
        if role.lower() == 'admin':
            cursor.execute("SELECT  task_name,  status FROM  Tasks")
            rows = cursor.fetchall()
            tasks = [{"task_name": row[0], "status": row[1]} for row in rows]
        else:
            # Get tasks assigned to the user
            cursor.execute("""
                SELECT task_name, status,
                FROM Tasks
                WHERE assigned_to = %s
            """, (user_id,))
            rows = cursor.fetchall()
            tasks = [{"task_name": row[0], "status": row[1]} for row in rows]

        # Process the data using Gemini API
        response_message = format_response_with_gemini(tasks, role, "all_tasks_status")

        # Return the formatted response along with the raw data
        return jsonify({
            "message": response_message,
            "tasks": tasks
        }), 200

    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# Function to retrieve low-priority tasks (with role-based filtering)
def get_low_priority_tasks(user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    tasks = []

    try:
        # For admin, show all low-priority tasks
        if role.lower() == 'admin':
            cursor.execute("SELECT task_id, task_name, description, due_date, priority FROM Tasks WHERE priority = 'Low'")
            rows = cursor.fetchall()
            tasks = [{"task_id": row[0], "task_name": row[1], "description": row[2], "due_date": row[3], "priority": row[4]} for row in rows]
        else:
            # Get low-priority tasks assigned to the user
            cursor.execute("""
    SELECT task_id, task_name, description, due_date, priority
    FROM Tasks
    WHERE priority = 'Low' AND assigned_to = %s
""", (user_id,))
            rows = cursor.fetchall()
            tasks = [{"task_id": row[0], "task_name": row[1], "description": row[2], "due_date": row[3], "priority": row[4]} for row in rows]

        # Process the data using Gemini API
        response_message = format_response_with_gemini(tasks, role, "priority_tasks", "Low")

        # Return the formatted response along with the raw data
        return jsonify({
            "message": response_message,
            "tasks": tasks
        }), 200

    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# Function to retrieve medium-priority tasks (with role-based filtering)
def get_medium_priority_tasks(user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    tasks = []

    try:
        # For admin, show all medium-priority tasks
        if role.lower() == 'admin':
            cursor.execute("SELECT task_id, task_name, description, due_date, priority FROM Tasks WHERE priority = 'Medium'")
            rows = cursor.fetchall()
            tasks = [{"task_id": row[0], "task_name": row[1], "description": row[2], "due_date": row[3], "priority": row[4]} for row in rows]
        else:
            # Get medium-priority tasks assigned to the user
            cursor.execute("""
    SELECT task_id, task_name, description, due_date, priority
    FROM Tasks
    WHERE priority = 'Medium' AND assigned_to = %s
""", (user_id,))
            rows = cursor.fetchall()
            tasks = [{"task_id": row[0], "task_name": row[1], "description": row[2], "due_date": row[3], "priority": row[4]} for row in rows]

        # Process the data using Gemini API
        response_message = format_response_with_gemini(tasks, role, "priority_tasks", "Medium")

        # Return the formatted response along with the raw data
        return jsonify({
            "message": response_message,
            "tasks": tasks
        }), 200

    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# Function to retrieve high-priority tasks (with role-based filtering)
def get_high_priority_tasks(user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    tasks = []

    try:
        # For admin, show all high-priority tasks
        if role.lower() == 'admin':
            cursor.execute("SELECT task_id, task_name, description, due_date, priority FROM Tasks WHERE priority = 'High'")
            rows = cursor.fetchall()
            tasks = [{"task_id": row[0], "task_name": row[1], "description": row[2], "due_date": row[3], "priority": row[4]} for row in rows]
        else:
            # Get high-priority tasks assigned to the user
            cursor.execute("""
    SELECT task_id, task_name, description, due_date, priority
    FROM Tasks
    WHERE priority = 'High' AND assigned_to = %s
""", (user_id,))

            rows = cursor.fetchall()
            tasks = [{"task_id": row[0], "task_name": row[1], "description": row[2], "due_date": row[3], "priority": row[4]} for row in rows]

        # Process the data using Gemini API
        response_message = format_response_with_gemini(tasks, role, "priority_tasks", "High")

        # Return the formatted response along with the raw data
        return jsonify({
            "message": response_message,
            "tasks": tasks
        }), 200

    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# Fixed function to retrieve the status of a specific task (with access check)
def get_task_status_by_name(task_name, user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # First get the project ID to check access - add better error handling and logging
        print(f"Querying task: '{task_name}'")

        # Fix parameter binding by using a tuple
        cursor.execute("SELECT task_id, status FROM Tasks WHERE task_name = %s", (task_name,))
        result = cursor.fetchone()

        if not result:
            print(f"Task not found: '{task_name}'")
            return {"error": "Task not found"}, 404

        task_id, status = result
        print(f"Found task_id: {task_id}, status: {status}")

        # Check if user has access to this task
        has_access = user_has_access_to_project(user_id, role, task_id, conn)
        print(f"User {user_id} with role {role} has access to task {task_id}: {has_access}")

        if not has_access:
            return {"error": "You do not have access to this task"}, 403

        # Process the data using Gemini API
        task_data = {"task_name": task_name, "status": status}
        response_message = format_response_with_gemini(
            None,  # No list data
            role,
            "task_status",
            task_data
        )

        # Return the formatted response along with the raw data
        return jsonify({
            "message": response_message,
            "task": task_data
        }), 200

    except Exception as e:
        print(f"Database Error in get_task_status_by_name: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# Function to update the status of a task (with access check)
def update_task_status(data, user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        task_name = data.get('task_name')
        new_status = data.get('new_status')

        if not task_name or not new_status:
            return jsonify({"error": "Both 'task_name' and 'new_status' must be provided"}), 400

        # Get project_id using task_name
        cursor.execute("SELECT task_id, project_id FROM Tasks WHERE task_name = %s", (task_name,))
        task_result = cursor.fetchone()

        if not task_result:
            return jsonify({"error": "Task not found"}), 404

        task_id, project_id = task_result

        # Check if user has access to the project
        if not user_has_access_to_project(user_id, role, project_id, conn):
            return jsonify({"error": "You do not have access to this task"}), 403

        # Update task status
        cursor.execute("UPDATE Tasks SET status = %s WHERE task_id = %s", (new_status, task_id))
        conn.commit()

        log_activity(user_id, "Task_Update", f"Updated task '{task_name}' status to '{new_status}'")
        # Process the data using Gemini API
        response_message = format_response_with_gemini(
            None,  # No list data needed
            role,
            "update_success",
            {"type": "task", "name": task_name, "new_status": new_status}
        )

        return jsonify({"message": response_message}), 200

    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    finally:
        conn.close()


# Function to update the status of a project (with access check)
def update_project_status(data, user_id, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        project_name = data.get('project_name')
        new_status = data.get('new_status')

        if not project_name or not new_status:
            return jsonify({"error": "Both 'project_name' and 'new_status' must be provided"}), 400

        # Get project_id
        cursor.execute("SELECT project_id FROM Projects WHERE project_name = %s", (project_name,))
        result = cursor.fetchone()

        if not result:
            return jsonify({"error": "Project not found"}), 404

        project_id = result[0]

        # Check access
        if not user_has_access_to_project(user_id, role, project_id, conn):
            return jsonify({"error": "You do not have access to this project"}), 403

        # Update status
        cursor.execute("UPDATE Projects SET status = %s WHERE project_id = %s", (new_status, project_id))
        conn.commit()

        log_activity(user_id, "Project_Status_Update", f"Updated project '{project_name}' status to '{new_status}'")

        # Process the data using Gemini API
        response_message = format_response_with_gemini(
            None,  # No list data needed
            role,
            "update_success",
            {"type": "project", "name": project_name, "new_status": new_status}
        )

        return jsonify({"message": response_message}), 200

    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    finally:
        conn.close()

# Fixed function to retrieve all users
def get_all_users(role):
    conn = get_db_connection()
    cursor = conn.cursor()
    users = []

    try:
        # For admin, show all completed projects
        if role.lower() == 'admin':
            cursor.execute("SELECT user_id, username, email, role FROM Users")
            rows = cursor.fetchall()
            users = [{"user_id": row[0], "username": row[1], "email": row[2], "role": row[3]} for row in rows]

        # Process the data using Gemini API
        response_message = format_response_with_gemini(users, role, "all_users")

        # Return the formatted response along with the raw data
        return jsonify({
            "message": response_message,
            "users": users
        }), 200

    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# Fixed function to retrieve the activities of a specific user
def get_user_activity(user_name, role):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        print(f"Querying user: '{user_name}'")

        cursor.execute("""
            SELECT activity_type, description
            FROM Activity_Log
            WHERE user_id = (
                SELECT user_id FROM Users WHERE username = %s
            )
            AND activity_type NOT IN ('User_Login', 'User_Logout', 'User_Registration')
        """, (user_name,))
        result = cursor.fetchall()

        if not result:
            print(f"No activity found for user: '{user_name}'")
            return {"error": "No activity found for this user"}, 404

        # If you want to return ALL activities
        activity_list = [
            {"activity_type": activity_type, "description": description}
            for activity_type, description in result
        ]

        # Format with Gemini – assuming your formatter accepts lists
        activity_data = {"username": user_name, "activities": activity_list}
        response_message = format_response_with_gemini(
            role,
            "user_activity",
            activity_data
        )

        return jsonify({
            "message": response_message,
            "activity": activity_data
        }), 200

    except Exception as e:
        print(f"Database Error in get_user_activity: {e}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    finally:
        conn.close()


# Function to log user activity
def log_activity(user_id, activity_type, description):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Activity_Log (user_id, activity_type, description)
            VALUES (%s, %s, %s)
        """, (user_id, activity_type, description))
        conn.commit()
    except Exception as e:
        print(f"Error logging activity: {e}")
    finally:
        if conn:
            conn.close()


# New API to get projects for the current user
@app.route('/api/my-projects', methods=['GET'])
@login_required
def get_my_projects():
    user_id = session.get('user_id')
    role = session.get('role', '')

    # Use the helper function to get accessible projects
    projects = get_user_accessible_projects(user_id, role)
    return jsonify({"projects": projects}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

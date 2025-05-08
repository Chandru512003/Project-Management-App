
# 📌 AI-Powered Project Management Assistant

An intelligent chatbot assistant for managing software development projects using natural language. Built with **Flask**, **Google Gemini AI**, and **MySQL**, this project helps users query project status, manage tasks, and track activities—all through a chat interface.

---

## 🚀 Features

- 🔐 User Authentication (Register/Login/Password Reset)
- 💬 Chatbot powered by Google Gemini AI
- 📊 Activity logging and tracking
- 📁 MySQL backend with structured schema
- 📂 Modular design with easily customizable components
- 🌐 Simple HTML frontend for interactions

---

## 🛠 Tech Stack

- **Backend**: Flask, Gemini AI (Google Generative AI), Python
- **Frontend**: HTML, CSS
- **Database**: MySQL
- **File Structure**:
  ```
  /main.py                 # Flask application
  /index.html              # Landing/chat interface
  /login.html              # Login page
  /register.html           # Register page
  /password.html           # Reset password page
  /Database Schema.sql     # MySQL DB schema
  ```

---

## 📦 Installation & Setup

### ✅ Requirements

- Python 3.8+
- MySQL Server
- Google Gemini API key
- `pip install -r requirements.txt`

### ⚙️ Steps

```bash
git clone https://github.com/Chandru512003/Project-Management-App.git
cd Project-Management-App

# Setup virtual environment (optional)
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create MySQL database using the provided SQL script
mysql -u root -p < "Database Schema.sql"

# Run the app
python main.py
```

---

## 🔐 Environment Variables

Set the following variables in a `.env` file or directly in your environment:

```bash
GEMINI_API_KEY=your_api_key_here
SECRET_KEY=your_flask_secret_key
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=your_mysql_password
MYSQL_DATABASE=project_assistant_db
```

---

## 💡 How to Use

1. Register or log in via the frontend.
2. Ask project-related queries (e.g., “What tasks are pending?”).
3. View intelligent responses powered by Gemini AI.
4. All user actions are logged in the MySQL database.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request for enhancements or bug fixes.

---

## 🧾 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgements

- Google Gemini (Vertex AI) for NLP processing
- Flask for the lightweight web framework
- MySQL for data management

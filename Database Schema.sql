create database Project_Management
use Project_Management

-- USERS table
CREATE TABLE Users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    role VARCHAR(30) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    password_hash VARCHAR(255) NOT NULL,
    security INT,
    answer VARCHAR(255)
);
ALTER TABLE Users AUTO_INCREMENT = 800;

-- PROJECTS table
CREATE TABLE Projects (
    project_id INT AUTO_INCREMENT PRIMARY KEY,
    project_name VARCHAR(100) NOT NULL,
    description TEXT,
    start_date DATE,
    end_date DATE,
    status VARCHAR(30) DEFAULT 'Pending',
    created_by INT,
    FOREIGN KEY (created_by) REFERENCES Users(user_id)
);

-- TASKS table
CREATE TABLE Tasks (
    task_id INT AUTO_INCREMENT PRIMARY KEY,
    task_name VARCHAR(100) NOT NULL,
    description TEXT,
    assigned_to INT,
    project_id INT,
    due_date DATE,
    status VARCHAR(30) DEFAULT 'Pending',
    priority VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assigned_to) REFERENCES Users(user_id),
    FOREIGN KEY (project_id) REFERENCES Projects(project_id)
);

-- ACTIVITY LOG table
CREATE TABLE Activity_Log (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    activity_type VARCHAR(50),
    description TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES Users(user_id)
);

INSERT INTO Users (username, email, role, password_hash,security,answer)
VALUES
('Chandru', 'chandru@gmail.com', 'Admin', 'Admin@1234',1,'Vishal')

CREATE TRIGGER trg_UpdateProjectStatus
ON Tasks
AFTER UPDATE
AS
BEGIN
    IF UPDATE(status)
    BEGIN
        -- Update project status to 'Completed' if all tasks are completed
        UPDATE Projects
        SET status = 'Completed'
        WHERE project_id IN (
            SELECT DISTINCT project_id
            FROM inserted
        )
        AND NOT EXISTS (
            SELECT 1
            FROM Tasks
            WHERE Tasks.project_id = Projects.project_id
            AND Tasks.status != 'Completed'
        );
    END;
END;

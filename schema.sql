-- Database schema for AI Powered Real-Time Academic Database Integrity System

CREATE TABLE departments (
    department_id   INT PRIMARY KEY AUTO_INCREMENT,
    department_name VARCHAR(100) NOT NULL UNIQUE,
    description     VARCHAR(255)
);

CREATE TABLE admins (
    admin_id       INT PRIMARY KEY AUTO_INCREMENT,
    username       VARCHAR(50) NOT NULL UNIQUE,
    password       VARCHAR(255) NOT NULL,
    name           VARCHAR(100) NOT NULL,
    department_id  INT,
    role           VARCHAR(30) DEFAULT 'ADMIN',
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (department_id) REFERENCES departments(department_id)
);

CREATE TABLE students (
    student_id      INT PRIMARY KEY AUTO_INCREMENT,
    reg_no          VARCHAR(20) NOT NULL UNIQUE,
    name            VARCHAR(100) NOT NULL,
    department      VARCHAR(50),
    department_id   INT,
    year_level      INT CHECK (year_level BETWEEN 1 AND 4),
    section         VARCHAR(5),
    status          VARCHAR(20) DEFAULT 'ACTIVE',
    FOREIGN KEY (department_id) REFERENCES departments(department_id)
);

CREATE TABLE faculty (
    faculty_id      INT PRIMARY KEY AUTO_INCREMENT,
    emp_no          VARCHAR(20) NOT NULL UNIQUE,
    name            VARCHAR(100) NOT NULL,
    department      VARCHAR(50),
    department_id   INT,
    FOREIGN KEY (department_id) REFERENCES departments(department_id)
);

CREATE TABLE subjects (
    subject_id      INT PRIMARY KEY AUTO_INCREMENT,
    subject_code    VARCHAR(20) NOT NULL UNIQUE,
    subject_name    VARCHAR(100) NOT NULL,
    credits         INT CHECK (credits BETWEEN 1 AND 5)
);

CREATE TABLE timetable (
    timetable_id    INT PRIMARY KEY AUTO_INCREMENT,
    faculty_id      INT NOT NULL,
    subject_id      INT NOT NULL,
    section         VARCHAR(20) NOT NULL,
    day             VARCHAR(15) NOT NULL,
    start_time      TIME NOT NULL,
    end_time        TIME NOT NULL,
    room            VARCHAR(30),
    last_updated_by VARCHAR(50),
    last_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (faculty_id) REFERENCES faculty(faculty_id),
    FOREIGN KEY (subject_id) REFERENCES subjects(subject_id)
);

CREATE TABLE enrollments (
    enroll_id       INT PRIMARY KEY AUTO_INCREMENT,
    student_id      INT NOT NULL,
    subject_id      INT NOT NULL,
    faculty_id      INT NOT NULL,
    semester        INT CHECK (semester BETWEEN 1 AND 8),
    UNIQUE(student_id, subject_id, semester),
    FOREIGN KEY (student_id) REFERENCES students(student_id),
    FOREIGN KEY (subject_id) REFERENCES subjects(subject_id),
    FOREIGN KEY (faculty_id) REFERENCES faculty(faculty_id)
);

CREATE TABLE marks (
    mark_id          INT PRIMARY KEY AUTO_INCREMENT,
    enroll_id        INT NOT NULL,
    student_id       INT NOT NULL,
    cycle_test_1     DECIMAL(5,2) CHECK (cycle_test_1 BETWEEN 0 AND 15),
    cycle_test_2     DECIMAL(5,2) CHECK (cycle_test_2 BETWEEN 0 AND 15),
    project_marks    DECIMAL(5,2) CHECK (project_marks BETWEEN 0 AND 20),
    assignment_marks DECIMAL(5,2) CHECK (assignment_marks BETWEEN 0 AND 10),
    internal_total   DECIMAL(5,2),
    last_updated_by  VARCHAR(50),
    last_updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (enroll_id) REFERENCES enrollments(enroll_id),
    FOREIGN KEY (student_id) REFERENCES students(student_id)
);

CREATE TABLE attendance (
    attendance_id    INT PRIMARY KEY AUTO_INCREMENT,
    enroll_id        INT NOT NULL,
    student_id       INT NOT NULL,
    total_classes    INT CHECK (total_classes >= 0),
    attended_classes INT CHECK (attended_classes >= 0),
    attendance_pct   DECIMAL(5,2),
    eligibility      VARCHAR(10),
    last_updated_by  VARCHAR(50),
    last_updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (enroll_id) REFERENCES enrollments(enroll_id),
    FOREIGN KEY (student_id) REFERENCES students(student_id)
);

CREATE TABLE anomalies (
    anomaly_id   INT PRIMARY KEY AUTO_INCREMENT,
    enroll_id    INT,
    category     VARCHAR(30),
    description  VARCHAR(255),
    score        DECIMAL(6,3),
    detected_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status       VARCHAR(20) DEFAULT 'OPEN',
    FOREIGN KEY (enroll_id) REFERENCES enrollments(enroll_id)
);

CREATE TABLE audit_log (
    audit_id    INT PRIMARY KEY AUTO_INCREMENT,
    table_name  VARCHAR(50),
    operation   VARCHAR(10),
    record_id   INT,
    changed_by  VARCHAR(50),
    changed_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    old_values  TEXT,
    new_values  TEXT
);

CREATE TABLE login_activity (
    login_activity_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    role VARCHAR(20) NOT NULL,
    student_id INT NULL,
    faculty_id INT NULL,
    department VARCHAR(50) NULL,
    section VARCHAR(20) NULL,
    year_level INT NULL,
    login_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    logout_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (student_id) REFERENCES students(student_id),
    FOREIGN KEY (faculty_id) REFERENCES faculty(faculty_id)
);

CREATE TABLE student_risk_scores (
    enroll_id           INT PRIMARY KEY,
    risk_score          DECIMAL(5,2),
    marks_contribution  DECIMAL(5,2),
    attendance_contribution DECIMAL(5,2),
    predicted_outcome   VARCHAR(20),
    last_updated        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (enroll_id) REFERENCES enrollments(enroll_id)
);

CREATE TABLE feedback (
    feedback_id         INT PRIMARY KEY AUTO_INCREMENT,
    enroll_id           INT NOT NULL,
    student_id          INT NOT NULL,
    faculty_id          INT NOT NULL,
    subject_id          INT NOT NULL,
    teaching_quality    ENUM('excellent', 'good', 'average', 'poor'),
    subject_knowledge   ENUM('excellent', 'good', 'average', 'poor'),
    communication       ENUM('excellent', 'good', 'average', 'poor'),
    preparation         ENUM('excellent', 'good', 'average', 'poor'),
    responsiveness      ENUM('excellent', 'good', 'average', 'poor'),
    punctuality         ENUM('excellent', 'good', 'average', 'poor'),
    overall_rating      ENUM('excellent', 'good', 'average', 'poor'),
    comments            TEXT,
    submitted_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (enroll_id) REFERENCES enrollments(enroll_id),
    FOREIGN KEY (student_id) REFERENCES students(student_id),
    FOREIGN KEY (faculty_id) REFERENCES faculty(faculty_id),
    FOREIGN KEY (subject_id) REFERENCES subjects(subject_id),
    UNIQUE(enroll_id)  -- one feedback per enrollment
);

-- Tables for question-wise and component-wise marks
CREATE TABLE cycle_test_questions (
    question_id         INT PRIMARY KEY AUTO_INCREMENT,
    mark_id             INT NOT NULL,
    test_number         INT CHECK (test_number IN (1, 2)),
    question_number     INT CHECK (question_number BETWEEN 1 AND 50),
    marks_obtained      DECIMAL(5,2) CHECK (marks_obtained >= 0),
    max_marks           DECIMAL(5,2) DEFAULT 10,
    FOREIGN KEY (mark_id) REFERENCES marks(mark_id),
    UNIQUE(mark_id, test_number, question_number)
);

CREATE TABLE project_components (
    component_id        INT PRIMARY KEY AUTO_INCREMENT,
    mark_id             INT NOT NULL,
    component_name      VARCHAR(100),
    marks_obtained      DECIMAL(5,2) CHECK (marks_obtained >= 0),
    max_marks           DECIMAL(5,2),
    FOREIGN KEY (mark_id) REFERENCES marks(mark_id)
);

DELIMITER $$

CREATE TRIGGER trg_marks_before_ins
BEFORE INSERT ON marks
FOR EACH ROW
BEGIN
    SET NEW.internal_total =
        IFNULL(NEW.cycle_test_1,0) +
        IFNULL(NEW.cycle_test_2,0) +
        IFNULL(NEW.project_marks,0) +
        IFNULL(NEW.assignment_marks,0);

    IF NEW.internal_total > 60 THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Internal total cannot exceed 60';
    END IF;
END$$

CREATE TRIGGER trg_marks_before_upd
BEFORE UPDATE ON marks
FOR EACH ROW
BEGIN
    SET NEW.internal_total =
        IFNULL(NEW.cycle_test_1,0) +
        IFNULL(NEW.cycle_test_2,0) +
        IFNULL(NEW.project_marks,0) +
        IFNULL(NEW.assignment_marks,0);

    IF NEW.internal_total > 60 THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Internal total cannot exceed 60';
    END IF;
END$$

CREATE TRIGGER trg_attendance_before_ins
BEFORE INSERT ON attendance
FOR EACH ROW
BEGIN
    IF NEW.total_classes > 0 THEN
        SET NEW.attendance_pct =
            (NEW.attended_classes * 100.0) / NEW.total_classes;
    ELSE
        SET NEW.attendance_pct = 0;
    END IF;

    IF NEW.attendance_pct >= 75 THEN
        SET NEW.eligibility = 'ELIGIBLE';
    ELSE
        SET NEW.eligibility = 'DEBARRED';
    END IF;
END$$

CREATE TRIGGER trg_attendance_before_upd
BEFORE UPDATE ON attendance
FOR EACH ROW
BEGIN
    IF NEW.total_classes > 0 THEN
        SET NEW.attendance_pct =
            (NEW.attended_classes * 100.0) / NEW.total_classes;
    ELSE
        SET NEW.attendance_pct = 0;
    END IF;

    IF NEW.attendance_pct >= 75 THEN
        SET NEW.eligibility = 'ELIGIBLE';
    ELSE
        SET NEW.eligibility = 'DEBARRED';
    END IF;
END$$

CREATE TRIGGER trg_marks_audit
AFTER UPDATE ON marks
FOR EACH ROW
BEGIN
    INSERT INTO audit_log(table_name, operation, record_id, changed_by, old_values, new_values)
    VALUES(
        'marks',
        'UPDATE',
        OLD.mark_id,
        NEW.last_updated_by,
        CONCAT('internal_total=', OLD.internal_total),
        CONCAT('internal_total=', NEW.internal_total)
    );
END$$

CREATE TRIGGER trg_attendance_audit
AFTER UPDATE ON attendance
FOR EACH ROW
BEGIN
    INSERT INTO audit_log(table_name, operation, record_id, changed_by, old_values, new_values)
    VALUES(
        'attendance',
        'UPDATE',
        NEW.last_updated_by,
        CONCAT('attendance_pct=', OLD.attendance_pct),
        CONCAT('attendance_pct=', NEW.attendance_pct)
    );
END$$

DELIMITER ;

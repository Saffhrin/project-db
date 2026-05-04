from collections import defaultdict
from datetime import date
import csv
import io

from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
import os

from ai_anomaly_detector import run_detection


DB_URL = os.getenv(
    "ACADEMIC_DB_URL",
    "mysql+mysqlconnector://root:Amit948@localhost/academic_integrity",
)

# Official % = (sum of present sessions) / full-term session count (e.g. 65). Daily rows store
# total_classes=1 each, so DB triggers on a single row are misleading—compute in app instead.
ATTENDANCE_TERM_CLASS_COUNT = int(os.getenv("ATTENDANCE_TERM_CLASS_COUNT", "65"))
ATTENDANCE_ELIGIBILITY_PCT = float(os.getenv("ATTENDANCE_ELIGIBILITY_PCT", "75"))


def term_attendance_pct_and_eligibility(attended_sum: float, term_total: int) -> tuple[float, str]:
    if term_total <= 0:
        return 0.0, "DEBARRED"
    pct = min(100.0, round((float(attended_sum) * 100.0) / float(term_total), 2))
    elig = "ELIGIBLE" if pct >= ATTENDANCE_ELIGIBILITY_PCT else "DEBARRED"
    return pct, elig


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-me")

    engine: Engine = create_engine(DB_URL, echo=False, future=True)
    app.config["DB_ENGINE"] = engine

    def ensure_login_activity_table():
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS login_activity (
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
                    )
                    """
                )
            )

    ensure_login_activity_table()

    @app.context_processor
    def inject_globals():
        return {
            "app_title": "Edu Integrity - Academic Records Portal",
            "current_user": session.get("user"),
        }

    def get_current_user():
        return session.get("user")

    def require_role(*roles):
        user = get_current_user()
        return user is not None and user.get("role") in roles

    def make_csv_response(filename, fieldnames, rows):
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

        response = make_response(output.getvalue())
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response

    @app.route("/")
    def index():
        profile = None
        user = get_current_user()
        if user:
            engine = app.config["DB_ENGINE"]
            with engine.begin() as conn:
                if user.get("role") == "STUDENT" and user.get("student_id"):
                    user_data = conn.execute(
                        text(
                            """
                            SELECT s.student_id, s.reg_no, s.name AS student_name, s.department, s.section
                            FROM students s
                            WHERE s.student_id = :student_id
                            """
                        ),
                        {"student_id": user.get("student_id")},
                    ).mappings().first()
                    if user_data:
                        # Generate email: initial + first letter of name + last 3 of reg_no
                        name_parts = user_data["student_name"].split(".")
                        initial = name_parts[0][0].lower() if name_parts[0] else ""
                        first_letter = name_parts[1][0].lower() if len(name_parts) > 1 and name_parts[1] else ""
                        last3 = user_data["reg_no"][-3:] if len(user_data["reg_no"]) >= 3 else user_data["reg_no"]
                        email = f"{initial}{first_letter}{last3}@srmist.edu.in"
                        profile = {
                            "role": "STUDENT",
                            "name": user_data["student_name"],
                            "id": user_data["student_id"],
                            "reg_no": user_data["reg_no"],
                            "email": email,
                            "institution": "College of engineering and technology,Tiruchirappalli",
                            "department": user_data.get("department", ""),
                            "section": user_data.get("section", ""),
                        }
                elif user.get("role") == "FACULTY" and user.get("faculty_id"):
                    user_data = conn.execute(
                        text(
                            """
                            SELECT f.faculty_id, f.emp_no, f.name AS faculty_name, f.department
                            FROM faculty f
                            WHERE f.faculty_id = :faculty_id
                            """
                        ),
                        {"faculty_id": user.get("faculty_id")},
                    ).mappings().first()
                    if user_data:
                        profile = {
                            "role": "FACULTY",
                            "name": user_data["faculty_name"],
                            "id": user_data["faculty_id"],
                            "faculty_no": user_data["emp_no"],
                            "email": f"{user_data['emp_no']}@srmist.edu.in",
                            "institution": "College of engineering and technology,Tiruchirappalli",
                            "department": user_data.get("department", ""),
                        }
                else:
                    profile = {
                        "role": "ADMIN",
                        "name": user.get("username"),
                        "id": user.get("user_id"),
                        "email": f"{user.get('username')}@srmist.edu.in",
                        "institution": "College of engineering and technology,Tiruchirappalli",
                    }

        return render_template("index.html", profile=profile)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        engine = app.config["DB_ENGINE"]
        selected_role = request.args.get("role", "").upper()

        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            required_role = request.form.get("role", "").upper()

            login_department = None
            login_section = None
            login_year = None

            with engine.begin() as conn:
                row = conn.execute(
                    text(
                        """
                        SELECT user_id, username, password, role,
                               student_id, faculty_id
                        FROM users
                        WHERE username = :username
                        """
                    ),
                    {"username": username},
                ).mappings().first()

                if not row or row["password"] != password:
                    flash("Invalid username or password.", "danger")
                    return render_template("login.html", selected_role=required_role)

                if required_role and row["role"] != required_role:
                    flash(f"Account role mismatch: expected {required_role}.", "danger")
                    return render_template("login.html", selected_role=required_role)

                if row["role"] == "STUDENT" and row["student_id"]:
                    student_info = conn.execute(
                        text(
                            "SELECT department, section, year_level FROM students WHERE student_id = :sid"
                        ),
                        {"sid": row["student_id"]},
                    ).mappings().first()
                    if student_info:
                        login_department = student_info.get("department")
                        login_section = student_info.get("section")
                        login_year = student_info.get("year_level")

                if row["role"] == "FACULTY" and row["faculty_id"]:
                    faculty_info = conn.execute(
                        text(
                            "SELECT department FROM faculty WHERE faculty_id = :fid"
                        ),
                        {"fid": row["faculty_id"]},
                    ).mappings().first()
                    if faculty_info:
                        login_department = faculty_info.get("department")

                conn.execute(
                    text(
                        "INSERT INTO login_activity (user_id, role, student_id, faculty_id, department, section, year_level, login_at) VALUES (:uid, :role, :sid, :fid, :dept, :sect, :year, NOW())"
                    ),
                    {
                        "uid": row["user_id"],
                        "role": row["role"],
                        "sid": row["student_id"],
                        "fid": row["faculty_id"],
                        "dept": login_department,
                        "sect": login_section,
                        "year": login_year,
                    },
                )

            session["user"] = {
                "user_id": row["user_id"],
                "username": row["username"],
                "role": row["role"],
                "student_id": row["student_id"],
                "faculty_id": row["faculty_id"],
            }

            flash(f"Welcome, {row['username']} ({row['role']}).", "success")
            return redirect(url_for("index"))

        return render_template("login.html", selected_role=selected_role)


    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        engine = app.config["DB_ENGINE"]

        if request.method == "POST":
            username = request.form.get("username")
            role = request.form.get("role")
            identifier = request.form.get("identifier")
            new_password = request.form.get("new_password")
            confirm_password = request.form.get("confirm_password")

            if not username or role not in ("STUDENT", "FACULTY") or not identifier:
                flash("Please enter valid username, role, and linked ID.", "danger")
                return render_template("forgot_password.html")

            if not new_password or new_password != confirm_password:
                flash("Passwords do not match.", "danger")
                return render_template("forgot_password.html")

            with engine.begin() as conn:
                user_row = None

                if role == "STUDENT":
                    user_row = conn.execute(
                        text(
                            """
                            SELECT u.user_id
                            FROM users u
                            JOIN students s ON s.student_id = u.student_id
                            WHERE u.username = :username
                              AND u.role = 'STUDENT'
                              AND s.reg_no = :identifier
                            """
                        ),
                        {"username": username, "identifier": identifier},
                    ).mappings().first()
                else:
                    user_row = conn.execute(
                        text(
                            """
                            SELECT u.user_id
                            FROM users u
                            JOIN faculty f ON f.faculty_id = u.faculty_id
                            WHERE u.username = :username
                              AND u.role = 'FACULTY'
                              AND f.emp_no = :identifier
                            """
                        ),
                        {"username": username, "identifier": identifier},
                    ).mappings().first()

                if not user_row:
                    flash("No matching account found for that username and linked ID.", "danger")
                    return render_template("forgot_password.html")

                conn.execute(
                    text("UPDATE users SET password = :pwd WHERE user_id = :uid"),
                    {"pwd": new_password, "uid": user_row["user_id"]},
                )

            flash("Password reset successful. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("forgot_password.html")

    @app.route("/logout")
    def logout():
        user = get_current_user()
        if user and user.get("user_id"):
            engine = app.config["DB_ENGINE"]
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE login_activity SET logout_at = NOW() WHERE user_id = :uid AND logout_at IS NULL ORDER BY login_at DESC LIMIT 1"
                    ),
                    {"uid": user.get("user_id")},
                )

        session.pop("user", None)
        flash("Logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        engine = app.config["DB_ENGINE"]
        with engine.begin() as conn:
            students = conn.execute(
                text("SELECT student_id, reg_no, name FROM students ORDER BY reg_no")
            ).mappings().all()
            faculty = conn.execute(
                text("SELECT faculty_id, emp_no, name FROM faculty ORDER BY emp_no")
            ).mappings().all()

        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            role = request.form.get("role")
            student_id = request.form.get("student_id") or None
            faculty_id = request.form.get("faculty_id") or None

            if role not in ("ADMIN", "FACULTY", "STUDENT"):
                flash("Invalid role selected.", "danger")
                return render_template(
                    "signup.html", students=students, faculty=faculty
                )

            if role == "STUDENT" and not student_id:
                flash("Select the student record for this account.", "danger")
                return render_template(
                    "signup.html", students=students, faculty=faculty
                )
            if role == "FACULTY" and not faculty_id:
                flash("Select the faculty record for this account.", "danger")
                return render_template(
                    "signup.html", students=students, faculty=faculty
                )

            try:
                with engine.begin() as conn:
                    conn.execute(
                        text(
                            """
                            INSERT INTO users (username, password, role, student_id, faculty_id)
                            VALUES (:username, :password, :role, :student_id, :faculty_id)
                            """
                        ),
                        {
                            "username": username,
                            "password": password,
                            "role": role,
                            "student_id": int(student_id) if student_id else None,
                            "faculty_id": int(faculty_id) if faculty_id else None,
                        },
                    )
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))
            except SQLAlchemyError as exc:
                flash(f"Error creating account: {exc}", "danger")

        return render_template("signup.html", students=students, faculty=faculty)

    @app.route("/students/new", methods=["GET", "POST"])
    def student_registration():
        if not require_role("ADMIN"):
            flash("Only admin can register students.", "danger")
            return redirect(url_for("login"))
        engine = app.config["DB_ENGINE"]
        if request.method == "POST":
            reg_no = request.form.get("reg_no")
            name = request.form.get("name")
            department = request.form.get("department")
            year_level = request.form.get("year_level")
            section = request.form.get("section")
            try:
                with engine.begin() as conn:
                    conn.execute(
                        text(
                            """
                            INSERT INTO students (reg_no, name, department, year_level, section)
                            VALUES (:reg_no, :name, :department, :year_level, :section)
                            """
                        ),
                        {
                            "reg_no": reg_no,
                            "name": name,
                            "department": department,
                            "year_level": int(year_level),
                            "section": section,
                        },
                    )
                flash("Student registered successfully.", "success")
                return redirect(url_for("student_registration"))
            except SQLAlchemyError as exc:
                flash(f"Error registering student: {exc}", "danger")
        return render_template("student_registration.html")

    @app.route("/faculty/new", methods=["GET", "POST"])
    def faculty_registration():
        if not require_role("ADMIN"):
            flash("Only admin can register faculty.", "danger")
            return redirect(url_for("login"))
        engine = app.config["DB_ENGINE"]
        if request.method == "POST":
            emp_no = request.form.get("emp_no")
            name = request.form.get("name")
            department = request.form.get("department")
            try:
                with engine.begin() as conn:
                    conn.execute(
                        text(
                            """
                            INSERT INTO faculty (emp_no, name, department)
                            VALUES (:emp_no, :name, :department)
                            """
                        ),
                        {
                            "emp_no": emp_no,
                            "name": name,
                            "department": department,
                        },
                    )
                flash("Faculty registered successfully.", "success")
                return redirect(url_for("faculty_registration"))
            except SQLAlchemyError as exc:
                flash(f"Error registering faculty: {exc}", "danger")

        return render_template("faculty_registration.html")

    @app.route("/subjects/new", methods=["GET", "POST"])
    def subject_registration():
        if not require_role("ADMIN"):
            flash("Only admin can register subjects.", "danger")
            return redirect(url_for("login"))
        engine = app.config["DB_ENGINE"]
        if request.method == "POST":
            subject_code = request.form.get("subject_code")
            subject_name = request.form.get("subject_name")
            credits = request.form.get("credits") or 4
            try:
                with engine.begin() as conn:
                    conn.execute(
                        text(
                            """
                            INSERT INTO subjects (subject_code, subject_name, credits)
                            VALUES (:subject_code, :subject_name, :credits)
                            """
                        ),
                        {
                            "subject_code": subject_code,
                            "subject_name": subject_name,
                            "credits": int(credits),
                        },
                    )
                flash("Subject created successfully.", "success")
                return redirect(url_for("subject_registration"))
            except SQLAlchemyError as exc:
                flash(f"Error creating subject: {exc}", "danger")

        return render_template("subject_registration.html")

    @app.route("/enrollments/new", methods=["GET", "POST"])
    def enrollment_registration():
        if not require_role("ADMIN"):
            flash("Only admin can create enrollments.", "danger")
            return redirect(url_for("login"))

        selected_department = request.args.get("department", "")
        selected_section = request.args.get("section", "")

        engine = app.config["DB_ENGINE"]
        with engine.begin() as conn:
            departments = conn.execute(
                text("SELECT DISTINCT department FROM students ORDER BY department")
            ).scalars().all()

            sections = []
            if selected_department:
                sections = conn.execute(
                    text(
                        "SELECT DISTINCT section FROM students WHERE department = :department ORDER BY section"
                    ),
                    {"department": selected_department},
                ).scalars().all()

            where_clauses = []
            params = {}
            if selected_department:
                where_clauses.append("department = :department")
                params["department"] = selected_department
            if selected_section:
                where_clauses.append("COALESCE(section, '') = :section")
                params["section"] = selected_section

            where_sql = "" if not where_clauses else "WHERE " + " AND ".join(where_clauses)

            students = conn.execute(
                text(
                    f"""
                    SELECT student_id, reg_no, name
                    FROM students
                    {where_sql}
                    ORDER BY reg_no
                    """
                ),
                params,
            ).mappings().all()

            subjects = conn.execute(
                text(
                    "SELECT subject_id, subject_code, subject_name FROM subjects ORDER BY subject_code"
                )
            ).mappings().all()
            faculty = conn.execute(
                text(
                    "SELECT faculty_id, emp_no, name FROM faculty ORDER BY emp_no"
                )
            ).mappings().all()


        if request.method == "POST":
            try:
                data = {
                    "student_id": int(request.form.get("student_id")),
                    "subject_id": int(request.form.get("subject_id")),
                    "faculty_id": int(request.form.get("faculty_id")),
                    "semester": int(request.form.get("semester") or 1),
                }
            except (TypeError, ValueError):
                flash("Please select student, subject, faculty and semester.", "danger")
                return render_template(
                    "enrollment_registration.html",
                    students=students,
                    subjects=subjects,
                    faculty=faculty,
                )

            try:
                with engine.begin() as conn:
                    conn.execute(
                        text(
                            """
                            INSERT INTO enrollments (student_id, subject_id, faculty_id, semester)
                            VALUES (:student_id, :subject_id, :faculty_id, :semester)
                            """
                        ),
                        data,
                    )
                flash("Enrollment created successfully.", "success")
            except SQLAlchemyError as exc:
                flash(f"Error creating enrollment: {exc}", "danger")

        return render_template(
            "enrollment_registration.html",
            students=students,
            subjects=subjects,
            faculty=faculty,
            departments=departments,
            sections=sections,
            selected_department=selected_department,
            selected_section=selected_section,
        )

    @app.route("/enrollments/manage", methods=["GET", "POST"])
    def manage_enrollments():
        if not require_role("ADMIN"):
            flash("Only admin can manage enrollments.", "danger")
            return redirect(url_for("login"))
        engine = app.config["DB_ENGINE"]
        
        if request.method == "POST":
            enroll_id = request.form.get("enroll_id")
            try:
                with engine.begin() as conn:
                    # Get enrollment details before deletion for audit
                    enrollment = conn.execute(
                        text(
                            """
                            SELECT e.enroll_id, s.reg_no, s.name AS student_name,
                                   sub.subject_code, sub.subject_name, f.emp_no, f.name AS faculty_name
                            FROM enrollments e
                            JOIN students s ON e.student_id = s.student_id
                            JOIN subjects sub ON e.subject_id = sub.subject_id
                            JOIN faculty f ON e.faculty_id = f.faculty_id
                            WHERE e.enroll_id = :enroll_id
                            """
                        ),
                        {"enroll_id": enroll_id},
                    ).mappings().first()
                    
                    if enrollment:
                        # Delete related marks and attendance first
                        conn.execute(
                            text("DELETE FROM marks WHERE enroll_id = :enroll_id"),
                            {"enroll_id": enroll_id},
                        )
                        conn.execute(
                            text("DELETE FROM attendance WHERE enroll_id = :enroll_id"),
                            {"enroll_id": enroll_id},
                        )
                        conn.execute(
                            text("DELETE FROM anomalies WHERE enroll_id = :enroll_id"),
                            {"enroll_id": enroll_id},
                        )
                        # Finally delete the enrollment
                        conn.execute(
                            text("DELETE FROM enrollments WHERE enroll_id = :enroll_id"),
                            {"enroll_id": enroll_id},
                        )
                        # Log to audit
                        conn.execute(
                            text(
                                """
                                INSERT INTO audit_log (table_name, operation, record_id, changed_by, old_values)
                                VALUES (:table_name, :operation, :record_id, :changed_by, :old_values)
                                """
                            ),
                            {
                                "table_name": "enrollments",
                                "operation": "DELETE",
                                "record_id": enroll_id,
                                "changed_by": session.get("user", {}).get("username", "admin"),
                                "old_values": f"Student: {enrollment['student_name']} ({enrollment['reg_no']}), Subject: {enrollment['subject_name']}, Faculty: {enrollment['faculty_name']}",
                            },
                        )
                        flash(f"Enrollment removed successfully for {enrollment['student_name']} from {enrollment['subject_name']}.", "success")
                    else:
                        flash("Enrollment not found.", "danger")
            except SQLAlchemyError as exc:
                flash(f"Error removing enrollment: {exc}", "danger")
        
        # Get all enrollments
        with engine.begin() as conn:
            enrollments = conn.execute(
                text(
                    """
                    SELECT e.enroll_id, s.reg_no, s.name AS student_name,
                           s.department AS student_department, s.section AS student_section,
                           sub.subject_code, sub.subject_name, f.emp_no, f.name AS faculty_name,
                           e.semester
                    FROM enrollments e
                    JOIN students s ON e.student_id = s.student_id
                    JOIN subjects sub ON e.subject_id = sub.subject_id
                    JOIN faculty f ON e.faculty_id = f.faculty_id
                    ORDER BY s.reg_no, sub.subject_code
                    """
                )
            ).mappings().all()

        return render_template("manage_enrollments.html", enrollments=enrollments)

    @app.route("/marks/new", methods=["GET", "POST"])
    def marks_entry():
        if not require_role("ADMIN", "FACULTY"):
            flash("Only admin or faculty can enter marks.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        engine = app.config["DB_ENGINE"]
        subjects_for_faculty = []
        sections_for_subject = []
        departments_for_subject = []
        years_for_subject = []
        selected_subject_id = None
        selected_year = None
        selected_section = ""
        selected_department = ""

        is_faculty = user["role"] == "FACULTY" and user.get("faculty_id")
        fid = user["faculty_id"] if is_faculty else None

        # When faculty filters (GET) and then submits marks (POST), we keep the same constraints
        # so faculty can only see/enter marks for that (subject_id, section, year) scope.
        form_subject_id = request.form.get("subject_id")
        arg_subject_id = request.args.get("subject_id")
        raw_subject_id = arg_subject_id if request.method == "GET" else form_subject_id
        try:
            raw_subject_id_int = int(raw_subject_id) if raw_subject_id not in (None, "") else None
        except ValueError:
            raw_subject_id_int = None

        raw_section = request.args.get("section") if request.method == "GET" else request.form.get("section")
        if raw_section is None:
            raw_section = ""
        raw_section_str = raw_section

        raw_department = request.args.get("department") if request.method == "GET" else request.form.get("department")
        if raw_department is None:
            raw_department = ""
        raw_department_str = raw_department

        raw_year = request.args.get("year") if request.method == "GET" else request.form.get("year")
        if raw_year is None or raw_year == "":
            raw_year_int = None
        else:
            try:
                raw_year_int = int(raw_year)
            except ValueError:
                raw_year_int = None

        with engine.begin() as conn:
            if is_faculty:
                subjects_for_faculty = conn.execute(
                    text(
                        """
                        SELECT DISTINCT sub.subject_id, sub.subject_code, sub.subject_name
                        FROM enrollments e
                        JOIN subjects sub ON sub.subject_id = e.subject_id
                        WHERE e.faculty_id = :fid
                        ORDER BY sub.subject_code
                        """
                    ),
                    {"fid": fid},
                ).mappings().all()

                allowed_subject_ids = {s["subject_id"] for s in subjects_for_faculty}
                if raw_subject_id_int in allowed_subject_ids:
                    selected_subject_id = raw_subject_id_int
                elif subjects_for_faculty:
                    selected_subject_id = subjects_for_faculty[0]["subject_id"]

                if selected_subject_id is not None:
                    # Choose year available for this subject+faculty
                    years_for_subject = conn.execute(
                        text(
                            """
                            SELECT DISTINCT s.year_level AS year
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                            ORDER BY s.year_level
                            """
                        ),
                        {"fid": fid, "sid": selected_subject_id},
                    ).mappings().all()
                    allowed_years = {r["year"] for r in years_for_subject}
                    if raw_year_int in allowed_years:
                        selected_year = raw_year_int
                    elif years_for_subject:
                        selected_year = years_for_subject[0]["year"]

                    # First choose department available for this subject+faculty+year
                    departments_for_subject = conn.execute(
                        text(
                            """
                            SELECT DISTINCT s.department AS department
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                              AND s.year_level = :year
                            ORDER BY s.department
                            """
                        ),
                        {"fid": fid, "sid": selected_subject_id, "year": selected_year},
                    ).mappings().all()
                    allowed_departments = {r["department"] for r in departments_for_subject}

                    if raw_department_str in allowed_departments:
                        selected_department = raw_department_str
                    elif departments_for_subject:
                        selected_department = departments_for_subject[0]["department"]

                    # Then choose section available for selected department + year
                    sections_for_subject = conn.execute(
                        text(
                            """
                            SELECT DISTINCT COALESCE(s.section,'') AS section
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                              AND s.department = :department
                              AND s.year_level = :year
                            ORDER BY section
                            """
                        ),
                        {
                            "fid": fid,
                            "sid": selected_subject_id,
                            "department": selected_department,
                            "year": selected_year,
                        },
                    ).mappings().all()
                    allowed_sections = {r["section"] for r in sections_for_subject}

                    if raw_section_str in allowed_sections:
                        selected_section = raw_section_str
                    elif sections_for_subject:
                        selected_section = sections_for_subject[0]["section"]

                # Enrollment list is constrained to faculty + selected subject + selected section + selected department + selected year.
                if selected_subject_id is None or selected_year is None or selected_section == "" or selected_department == "":
                    enrollments = []
                else:
                    enrollments = conn.execute(
                        text(
                            """
                            SELECT e.enroll_id,
                                   s.reg_no,
                                   s.name AS student_name,
                                   s.department AS student_department,
                                   sub.subject_code,
                                   sub.subject_name
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            JOIN subjects sub ON sub.subject_id = e.subject_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                              AND COALESCE(s.section,'') = :section
                              AND s.department = :department
                              AND s.year_level = :year
                            ORDER BY s.reg_no
                            """
                        ),
                        {
                            "fid": fid,
                            "sid": selected_subject_id,
                            "section": selected_section,
                            "department": selected_department,
                            "year": selected_year,
                        },
                    ).mappings().all()
            else:
                departments_for_subject = conn.execute(
                    text("SELECT DISTINCT department FROM students ORDER BY department")
                ).mappings().all()
                allowed_departments = {d["department"] for d in departments_for_subject}

                if raw_department_str in allowed_departments:
                    selected_department = raw_department_str
                elif departments_for_subject:
                    selected_department = departments_for_subject[0]["department"]

                years_for_subject = conn.execute(
                    text(
                        """
                        SELECT DISTINCT year_level AS year
                        FROM students
                        WHERE department = :department
                        ORDER BY year_level
                        """
                    ),
                    {"department": selected_department},
                ).mappings().all()
                allowed_years = {r["year"] for r in years_for_subject}
                if raw_year_int in allowed_years:
                    selected_year = raw_year_int
                elif years_for_subject:
                    selected_year = years_for_subject[0]["year"]

                sections_for_subject = conn.execute(
                    text(
                        """
                        SELECT DISTINCT COALESCE(section,'') AS section
                        FROM students
                        WHERE department = :department
                          AND year_level = :year
                        ORDER BY section
                        """
                    ),
                    {"department": selected_department, "year": selected_year},
                ).mappings().all()
                allowed_sections = {s["section"] for s in sections_for_subject}

                if raw_section_str in allowed_sections:
                    selected_section = raw_section_str
                elif sections_for_subject:
                    selected_section = sections_for_subject[0]["section"]

                if selected_department == "" or selected_section == "" or selected_year is None:
                    enrollments = []
                else:
                    enrollments = conn.execute(
                        text(
                            """
                            SELECT e.enroll_id,
                                   s.reg_no,
                                   s.name AS student_name,
                                   s.department AS student_department,
                                   sub.subject_code,
                                   sub.subject_name
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            JOIN subjects sub ON sub.subject_id = e.subject_id
                            WHERE s.department = :department
                              AND COALESCE(s.section, '') = :section
                              AND s.year_level = :year
                            ORDER BY sub.subject_code, s.reg_no
                            """
                        ),
                        {
                            "department": selected_department,
                            "section": selected_section,
                            "year": selected_year,
                        },
                    ).mappings().all()

        if request.method == "POST":
            enroll_id = request.form.get("enroll_id")
            user_username = request.form.get("updated_by") or "faculty"
            
            try:
                # Parse question-wise marks for Cycle Tests
                ct1_questions = []
                for q in range(1, 6):
                    marks = float(request.form.get(f"ct1_q{q}") or 0)
                    if marks > 10:
                        raise ValueError(f"Question {q} in CT1 cannot exceed 10 marks")
                    ct1_questions.append(marks)
                
                ct2_questions = []
                for q in range(1, 6):
                    marks = float(request.form.get(f"ct2_q{q}") or 0)
                    if marks > 10:
                        raise ValueError(f"Question {q} in CT2 cannot exceed 10 marks")
                    ct2_questions.append(marks)
                
                # Calculate scaled values
                ct1_total = sum(ct1_questions)
                ct2_total = sum(ct2_questions)
                ct1_scaled = (ct1_total / 50) * 15 if ct1_total <= 50 else 15
                ct2_scaled = (ct2_total / 50) * 15 if ct2_total <= 50 else 15
                
                # Parse project components
                project_impl = float(request.form.get("project_impl") or 0)
                project_research = float(request.form.get("project_research") or 0)
                project_review = float(request.form.get("project_review") or 0)
                project_total = project_impl + project_research + project_review
                
                if project_impl > 8:
                    raise ValueError("Implementation cannot exceed 8 marks")
                if project_research > 8:
                    raise ValueError("Research Paper cannot exceed 8 marks")
                if project_review > 4:
                    raise ValueError("Final Review cannot exceed 4 marks")
                if project_total > 20:
                    raise ValueError("Project total cannot exceed 20 marks")
                
                # Assignment marks
                assignment_marks = float(request.form.get("assignment_marks") or 0)
                if assignment_marks > 10:
                    raise ValueError("Assignment cannot exceed 10 marks")
                
                # Calculate internal total
                internal_total = ct1_scaled + ct2_scaled + project_total + assignment_marks
                if internal_total > 60:
                    raise ValueError(f"Internal total ({internal_total}) cannot exceed 60 marks")
                
                data = {
                    "enroll_id": int(enroll_id),
                    "cycle_test_1": ct1_scaled,
                    "cycle_test_2": ct2_scaled,
                    "project_marks": project_total,
                    "assignment_marks": assignment_marks,
                    "updated_by": user_username,
                }
            except (ValueError, TypeError) as e:
                flash(f"Marks validation error: {str(e)}", "danger")
                return render_template(
                    "marks_entry.html",
                    enrollments=enrollments,
                    subjects_for_faculty=subjects_for_faculty,
                    sections_for_subject=sections_for_subject,
                    departments_for_subject=departments_for_subject,
                    selected_subject_id=selected_subject_id,
                    selected_section=selected_section,
                    selected_department=selected_department,
                    years_for_subject=years_for_subject,
                    selected_year=selected_year,
                )

            if is_faculty:
                # Prevent a faculty from submitting an enrollment outside the selected scope.
                submitted_subject_id = request.form.get("subject_id")
                submitted_section = request.form.get("section") or ""
                submitted_department = request.form.get("department") or ""
                try:
                    submitted_subject_id_int = int(submitted_subject_id) if submitted_subject_id not in (None, "") else None
                except ValueError:
                    submitted_subject_id_int = None

                with engine.begin() as conn:
                    allowed = conn.execute(
                        text(
                            """
                            SELECT 1
                            FROM enrollments e
                            WHERE e.enroll_id = :enroll_id
                              AND e.faculty_id = :fid
                            LIMIT 1
                            """
                        ),
                        {
                            "enroll_id": int(enroll_id),
                            "fid": fid,
                        },
                    ).scalar_one_or_none()

                if not allowed:
                    flash("Unauthorized enrollment for this faculty.", "danger")
                    return render_template(
                        "marks_entry.html",
                        enrollments=enrollments,
                        subjects_for_faculty=subjects_for_faculty,
                        sections_for_subject=sections_for_subject,
                        departments_for_subject=departments_for_subject,
                        selected_subject_id=selected_subject_id,
                        selected_section=selected_section,
                        selected_department=selected_department,
                    )

            try:
                with engine.begin() as conn:
                    # Get student_id from enroll_id if needed for marks table
                    enroll_data = conn.execute(
                        text("SELECT student_id FROM enrollments WHERE enroll_id = :eid"),
                        {"eid": int(enroll_id)}
                    ).mappings().first()

                    if not enroll_data:
                        raise ValueError("Invalid enrollment")

                    student_id = enroll_data["student_id"]
                    include_student_id = conn.execute(
                        text("SHOW COLUMNS FROM marks LIKE 'student_id'")
                    ).first() is not None
                    if include_student_id:
                        data["student_id"] = student_id

                    # Check if marks exist and if faculty can edit
                    if is_faculty:
                        expired = conn.execute(
                            text(
                                """
                                SELECT 1
                                FROM marks
                                WHERE enroll_id = :enroll_id
                                GROUP BY enroll_id
                                HAVING MAX(last_updated_at) < (CURRENT_TIMESTAMP - INTERVAL 24 HOUR)
                                LIMIT 1
                                """
                            ),
                            {"enroll_id": int(enroll_id)},
                        ).mappings().first()

                        if expired:
                            flash(
                                "You can only edit marks within 24 hours after uploading.",
                                "danger",
                            )
                            return render_template(
                                "marks_entry.html",
                                enrollments=enrollments,
                                subjects_for_faculty=subjects_for_faculty,
                                sections_for_subject=sections_for_subject,
                                departments_for_subject=departments_for_subject,
                                selected_subject_id=selected_subject_id,
                                selected_section=selected_section,
                                selected_department=selected_department,
                            )
                    
                    # Update or insert marks
                    updated = conn.execute(
                        text(
                            """
                            UPDATE marks
                            SET cycle_test_1 = :cycle_test_1,
                                cycle_test_2 = :cycle_test_2,
                                project_marks = :project_marks,
                                assignment_marks = :assignment_marks,
                                last_updated_by = :updated_by,
                                last_updated_at = CURRENT_TIMESTAMP
                            WHERE enroll_id = :enroll_id
                            """
                        ),
                        data,
                    ).rowcount

                    mark_id = None
                    if updated == 0:
                        # Insert new row (student_id is optional per schema)
                        if include_student_id:
                            insert_query = text(
                                """
                                INSERT INTO marks (
                                    enroll_id, student_id, cycle_test_1, cycle_test_2,
                                    project_marks, assignment_marks, last_updated_by,
                                    last_updated_at
                                ) VALUES (
                                    :enroll_id, :student_id, :cycle_test_1, :cycle_test_2,
                                    :project_marks, :assignment_marks, :updated_by,
                                    CURRENT_TIMESTAMP
                                )
                                """
                            )
                        else:
                            insert_query = text(
                                """
                                INSERT INTO marks (
                                    enroll_id, cycle_test_1, cycle_test_2,
                                    project_marks, assignment_marks, last_updated_by,
                                    last_updated_at
                                ) VALUES (
                                    :enroll_id, :cycle_test_1, :cycle_test_2,
                                    :project_marks, :assignment_marks, :updated_by,
                                    CURRENT_TIMESTAMP
                                )
                                """
                            )
                        result = conn.execute(insert_query, data)
                        # Get the inserted mark_id
                        mark_id = conn.execute(text("SELECT LAST_INSERT_ID() as id")).scalar()
                    else:
                        # Get existing mark_id
                        mark_data = conn.execute(
                            text("SELECT mark_id FROM marks WHERE enroll_id = :eid"),
                            {"eid": int(enroll_id)}
                        ).mappings().first()
                        mark_id = mark_data["mark_id"] if mark_data else None
                    
                    # Delete existing question/component records and insert fresh ones
                    if mark_id:
                        conn.execute(text("CREATE TABLE IF NOT EXISTS cycle_test_questions (question_id INT PRIMARY KEY AUTO_INCREMENT, mark_id INT NOT NULL, test_number INT CHECK (test_number IN (1, 2)), question_number INT CHECK (question_number BETWEEN 1 AND 50), marks_obtained DECIMAL(5,2) CHECK (marks_obtained >= 0), max_marks DECIMAL(5,2) DEFAULT 10, FOREIGN KEY (mark_id) REFERENCES marks(mark_id), UNIQUE(mark_id, test_number, question_number))"))
                        conn.execute(text("CREATE TABLE IF NOT EXISTS project_components (component_id INT PRIMARY KEY AUTO_INCREMENT, mark_id INT NOT NULL, component_name VARCHAR(100), marks_obtained DECIMAL(5,2) CHECK (marks_obtained >= 0), max_marks DECIMAL(5,2), FOREIGN KEY (mark_id) REFERENCES marks(mark_id))"))
                        conn.execute(text("DELETE FROM cycle_test_questions WHERE mark_id = :mid"), {"mid": mark_id})
                        conn.execute(text("DELETE FROM project_components WHERE mark_id = :mid"), {"mid": mark_id})
                        
                        # Insert cycle test 1 questions
                        for q_num, marks in enumerate(ct1_questions, 1):
                            conn.execute(
                                text(
                                    """
                                    INSERT INTO cycle_test_questions 
                                    (mark_id, test_number, question_number, marks_obtained, max_marks)
                                    VALUES (:mid, 1, :qnum, :marks, 10)
                                    """
                                ),
                                {"mid": mark_id, "qnum": q_num, "marks": marks}
                            )
                        
                        # Insert cycle test 2 questions
                        for q_num, marks in enumerate(ct2_questions, 1):
                            conn.execute(
                                text(
                                    """
                                    INSERT INTO cycle_test_questions 
                                    (mark_id, test_number, question_number, marks_obtained, max_marks)
                                    VALUES (:mid, 2, :qnum, :marks, 10)
                                    """
                                ),
                                {"mid": mark_id, "qnum": q_num, "marks": marks}
                            )
                        
                        # Insert project components
                        components = [
                            ("Implementation", project_impl, 8),
                            ("Research Paper", project_research, 8),
                            ("Final Review", project_review, 4),
                        ]
                        for comp_name, marks, max_m in components:
                            conn.execute(
                                text(
                                    """
                                    INSERT INTO project_components 
                                    (mark_id, component_name, marks_obtained, max_marks)
                                    VALUES (:mid, :cname, :marks, :max)
                                    """
                                ),
                                {"mid": mark_id, "cname": comp_name, "marks": marks, "max": max_m}
                            )
                
                flash("Marks saved successfully with detailed breakdown!", "success")
            except SQLAlchemyError as exc:
                flash(f"Error saving marks: {exc}", "danger")

        return render_template(
            "marks_entry.html",
            enrollments=enrollments,
            subjects_for_faculty=subjects_for_faculty,
            sections_for_subject=sections_for_subject,
            departments_for_subject=departments_for_subject,
            years_for_subject=years_for_subject,
            selected_subject_id=selected_subject_id,
            selected_year=selected_year,
            selected_section=selected_section,
            selected_department=selected_department,
        )

    @app.route("/attendance/new", methods=["GET", "POST"])
    def attendance_entry():
        """Daily attendance entry - faculty marks attendance for each day"""
        if not require_role("ADMIN", "FACULTY"):
            flash("Only admin or faculty can manage attendance.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        engine = app.config["DB_ENGINE"]
        subjects_for_faculty = []
        sections_for_subject = []
        departments_for_subject = []
        years_for_subject = []
        selected_subject_id = None
        selected_year = None
        selected_section = ""
        selected_department = ""
        attendance_records = []
        enrollments = []

        is_faculty = user["role"] == "FACULTY" and user.get("faculty_id")
        fid = user["faculty_id"] if is_faculty else None

        form_subject_id = request.form.get("subject_id")
        arg_subject_id = request.args.get("subject_id")
        raw_subject_id = arg_subject_id if request.method == "GET" else form_subject_id
        try:
            raw_subject_id_int = int(raw_subject_id) if raw_subject_id not in (None, "") else None
        except ValueError:
            raw_subject_id_int = None

        raw_section = request.args.get("section") if request.method == "GET" else request.form.get("section")
        if raw_section is None:
            raw_section = ""
        raw_section_str = raw_section

        raw_department = request.args.get("department") if request.method == "GET" else request.form.get("department")
        if raw_department is None:
            raw_department = ""
        raw_department_str = raw_department

        raw_year = request.args.get("year") if request.method == "GET" else request.form.get("year")
        if raw_year is None or raw_year == "":
            raw_year_int = None
        else:
            try:
                raw_year_int = int(raw_year)
            except ValueError:
                raw_year_int = None

        with engine.begin() as conn:
            # Ensure attendance table has date column for daily tracking
            try:
                conn.execute(
                    text(
                        """
                        ALTER TABLE attendance ADD COLUMN attendance_date DATE
                        """
                    )
                )
            except:
                pass  # Column already exists

            # Ensure student_id column exists
            try:
                conn.execute(
                    text(
                        """
                        ALTER TABLE attendance ADD COLUMN student_id INT
                        """
                    )
                )
            except:
                pass  # Column already exists

            # Add unique constraint for daily tracking (enroll_id + date)
            try:
                conn.execute(
                    text(
                        """
                        ALTER TABLE attendance ADD UNIQUE KEY unique_daily_attendance (enroll_id, attendance_date)
                        """
                    )
                )
            except:
                pass  # Unique key already exists

            # Get all subjects for filtering (admin sees all, faculty sees only their subjects)
            all_subjects = conn.execute(
                text(
                    """
                    SELECT DISTINCT sub.subject_id, sub.subject_code, sub.subject_name
                    FROM subjects sub
                    WHERE sub.subject_id IN (SELECT DISTINCT subject_id FROM enrollments)
                    ORDER BY sub.subject_code
                    """
                )
            ).mappings().all()

            if is_faculty:
                # Faculty path - filter subjects to only those they teach
                subjects_for_faculty = conn.execute(
                    text(
                        """
                        SELECT DISTINCT sub.subject_id, sub.subject_code, sub.subject_name
                        FROM enrollments e
                        JOIN subjects sub ON sub.subject_id = e.subject_id
                        WHERE e.faculty_id = :fid
                        ORDER BY sub.subject_code
                        """
                    ),
                    {"fid": fid},
                ).mappings().all()

                allowed_subject_ids = {s["subject_id"] for s in subjects_for_faculty}
                if raw_subject_id_int in allowed_subject_ids:
                    selected_subject_id = raw_subject_id_int
                elif subjects_for_faculty:
                    selected_subject_id = subjects_for_faculty[0]["subject_id"]

                if selected_subject_id is not None:
                    years_for_subject = conn.execute(
                        text(
                            """
                            SELECT DISTINCT s.year_level AS year
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                            ORDER BY s.year_level
                            """
                        ),
                        {"fid": fid, "sid": selected_subject_id},
                    ).mappings().all()
                    allowed_years = {r["year"] for r in years_for_subject}
                    if raw_year_int in allowed_years:
                        selected_year = raw_year_int
                    elif years_for_subject:
                        selected_year = years_for_subject[0]["year"]

                    departments_for_subject = conn.execute(
                        text(
                            """
                            SELECT DISTINCT s.department AS department
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                              AND s.year_level = :year
                            ORDER BY s.department
                            """
                        ),
                        {"fid": fid, "sid": selected_subject_id, "year": selected_year},
                    ).mappings().all()
                    allowed_departments = {r["department"] for r in departments_for_subject}

                    if raw_department_str in allowed_departments:
                        selected_department = raw_department_str
                    elif departments_for_subject:
                        selected_department = departments_for_subject[0]["department"]

                    sections_for_subject = conn.execute(
                        text(
                            """
                            SELECT DISTINCT COALESCE(s.section,'') AS section
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                              AND s.department = :department
                              AND s.year_level = :year
                            ORDER BY section
                            """
                        ),
                        {
                            "fid": fid,
                            "sid": selected_subject_id,
                            "department": selected_department,
                            "year": selected_year,
                        },
                    ).mappings().all()
                    allowed_sections = {r["section"] for r in sections_for_subject}

                    if raw_section_str in allowed_sections:
                        selected_section = raw_section_str
                    elif sections_for_subject:
                        selected_section = sections_for_subject[0]["section"]

                if selected_subject_id is None or selected_year is None or selected_department == "" or selected_section == "":
                    enrollments = []
                else:
                    # Fetch students for this class
                    enrollments = conn.execute(
                        text(
                            """
                            SELECT e.enroll_id,
                                   e.student_id,
                                   s.reg_no,
                                   s.name AS student_name,
                                   s.department AS student_department,
                                   sub.subject_code,
                                   sub.subject_name
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            JOIN subjects sub ON sub.subject_id = e.subject_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                              AND COALESCE(s.section,'') = :section
                              AND s.department = :department
                              AND s.year_level = :year
                            ORDER BY s.reg_no
                            """
                        ),
                        {
                            "fid": fid,
                            "sid": selected_subject_id,
                            "section": selected_section,
                            "department": selected_department,
                            "year": selected_year,
                        },
                    ).mappings().all()
            else:
                # Admin path - can see and mark attendance for all subjects/classes
                subjects_for_faculty = all_subjects

                allowed_subject_ids = {s["subject_id"] for s in subjects_for_faculty}
                if raw_subject_id_int in allowed_subject_ids:
                    selected_subject_id = raw_subject_id_int
                elif subjects_for_faculty:
                    selected_subject_id = subjects_for_faculty[0]["subject_id"]

                if selected_subject_id is not None:
                    years_for_subject = conn.execute(
                        text(
                            """
                            SELECT DISTINCT s.year_level AS year
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.subject_id = :sid
                            ORDER BY s.year_level
                            """
                        ),
                        {"sid": selected_subject_id},
                    ).mappings().all()
                    allowed_years = {r["year"] for r in years_for_subject}
                    if raw_year_int in allowed_years:
                        selected_year = raw_year_int
                    elif years_for_subject:
                        selected_year = years_for_subject[0]["year"]

                    departments_for_subject = conn.execute(
                        text(
                            """
                            SELECT DISTINCT s.department AS department
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.subject_id = :sid
                              AND s.year_level = :year
                            ORDER BY s.department
                            """
                        ),
                        {"sid": selected_subject_id, "year": selected_year},
                    ).mappings().all()
                    allowed_departments = {r["department"] for r in departments_for_subject}

                    if raw_department_str in allowed_departments:
                        selected_department = raw_department_str
                    elif departments_for_subject:
                        selected_department = departments_for_subject[0]["department"]

                    sections_for_subject = conn.execute(
                        text(
                            """
                            SELECT DISTINCT COALESCE(s.section,'') AS section
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.subject_id = :sid
                              AND s.department = :department
                              AND s.year_level = :year
                            ORDER BY section
                            """
                        ),
                        {
                            "sid": selected_subject_id,
                            "department": selected_department,
                            "year": selected_year,
                        },
                    ).mappings().all()
                    allowed_sections = {r["section"] for r in sections_for_subject}

                    if raw_section_str in allowed_sections:
                        selected_section = raw_section_str
                    elif sections_for_subject:
                        selected_section = sections_for_subject[0]["section"]

                if selected_subject_id is None or selected_year is None or selected_department == "" or selected_section == "":
                    enrollments = []
                else:
                    # Fetch students for this class (no faculty filter for admin)
                    enrollments = conn.execute(
                        text(
                            """
                            SELECT e.enroll_id,
                                   e.student_id,
                                   s.reg_no,
                                   s.name AS student_name,
                                   s.department AS student_department,
                                   sub.subject_code,
                                   sub.subject_name
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            JOIN subjects sub ON sub.subject_id = e.subject_id
                            WHERE e.subject_id = :sid
                              AND COALESCE(s.section,'') = :section
                              AND s.department = :department
                              AND s.year_level = :year
                            ORDER BY s.reg_no
                            """
                        ),
                        {
                            "sid": selected_subject_id,
                            "section": selected_section,
                            "department": selected_department,
                            "year": selected_year,
                        },
                    ).mappings().all()

        if request.method == "POST":
            attendance_date = request.form.get("attendance_date")
            subject_id = request.form.get("subject_id")
            
            if not attendance_date:
                flash("Please select an attendance date.", "danger")
                return render_template(
                    "attendance_entry.html",
                    enrollments=enrollments,
                    subjects_for_faculty=subjects_for_faculty,
                    sections_for_subject=sections_for_subject,
                    departments_for_subject=departments_for_subject,
                    years_for_subject=years_for_subject,
                    selected_subject_id=selected_subject_id,
                    selected_year=selected_year,
                    selected_section=selected_section,
                    selected_department=selected_department,
                )

            if is_faculty:
                try:
                    with engine.begin() as conn:
                        # Process attendance for each student
                        for enroll_id_str in request.form.keys():
                            if not enroll_id_str.startswith("enroll_"):
                                continue
                            
                            enroll_id = int(enroll_id_str.replace("enroll_", ""))
                            present = request.form.get(f"present_{enroll_id}") == "on"
                            
                            # Verify faculty has authority over this enrollment
                            auth_check = conn.execute(
                                text(
                                    """
                                    SELECT 1 FROM enrollments
                                    WHERE enroll_id = :eid AND faculty_id = :fid
                                    """
                                ),
                                {"eid": enroll_id, "fid": fid},
                            ).scalar_one_or_none()
                            
                            if not auth_check:
                                continue
                            
                            # Insert daily attendance record
                            conn.execute(
                                text(
                                    """
                                    INSERT INTO attendance (
                                        enroll_id, student_id, total_classes, attended_classes, 
                                        attendance_date, last_updated_by
                                    ) VALUES (
                                        :eid, :sid, 1, :attended, :att_date, :updated_by
                                    )
                                    ON DUPLICATE KEY UPDATE
                                        attended_classes = :attended,
                                        last_updated_by = :updated_by,
                                        last_updated_at = CURRENT_TIMESTAMP
                                    """
                                ),
                                {
                                    "eid": enroll_id,
                                    "sid": enrollments and next((e["student_id"] for e in enrollments if e["enroll_id"] == enroll_id), None),
                                    "attended": 1 if present else 0,
                                    "att_date": attendance_date,
                                    "updated_by": user.get("username", "faculty"),
                                },
                            )
                    
                    flash("Daily attendance recorded successfully.", "success")
                except SQLAlchemyError as exc:
                    flash(f"Error saving attendance: {exc}", "danger")
            else:
                # Admin path - can mark attendance for any enrollment
                try:
                    with engine.begin() as conn:
                        # Process attendance for each student
                        for enroll_id_str in request.form.keys():
                            if not enroll_id_str.startswith("enroll_"):
                                continue
                            
                            enroll_id = int(enroll_id_str.replace("enroll_", ""))
                            present = request.form.get(f"present_{enroll_id}") == "on"
                            
                            # Get student_id for this enrollment
                            enroll_info = conn.execute(
                                text(
                                    """
                                    SELECT student_id FROM enrollments WHERE enroll_id = :eid
                                    """
                                ),
                                {"eid": enroll_id},
                            ).mappings().first()
                            
                            if not enroll_info:
                                continue
                            
                            student_id = enroll_info["student_id"]
                            
                            # Insert daily attendance record
                            conn.execute(
                                text(
                                    """
                                    INSERT INTO attendance (
                                        enroll_id, student_id, total_classes, attended_classes, 
                                        attendance_date, last_updated_by
                                    ) VALUES (
                                        :eid, :sid, 1, :attended, :att_date, :updated_by
                                    )
                                    ON DUPLICATE KEY UPDATE
                                        attended_classes = :attended,
                                        last_updated_by = :updated_by,
                                        last_updated_at = CURRENT_TIMESTAMP
                                    """
                                ),
                                {
                                    "eid": enroll_id,
                                    "sid": student_id,
                                    "attended": 1 if present else 0,
                                    "att_date": attendance_date,
                                    "updated_by": user.get("username", "admin"),
                                },
                            )
                    
                    flash("Daily attendance recorded successfully.", "success")
                except SQLAlchemyError as exc:
                    flash(f"Error saving attendance: {exc}", "danger")
            
            return redirect(url_for("attendance_entry"))

        return render_template(
            "attendance_entry.html",
            enrollments=enrollments,
            subjects_for_faculty=subjects_for_faculty,
            sections_for_subject=sections_for_subject,
            departments_for_subject=departments_for_subject,
            years_for_subject=years_for_subject,
            selected_subject_id=selected_subject_id,
            selected_year=selected_year,
            selected_section=selected_section,
            selected_department=selected_department,
        )

    @app.route("/timetable", methods=["GET", "POST"])
    def faculty_timetable():
        if not require_role("FACULTY"):
            flash("Only faculty can view and manage timetable.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        engine = app.config["DB_ENGINE"]
        fid = user.get("faculty_id")

        with engine.begin() as conn:
            # Ensure timetable table exists, and add year_level filter support
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS timetable (
                        timetable_id INT PRIMARY KEY AUTO_INCREMENT,
                        faculty_id INT NOT NULL,
                        subject_id INT NOT NULL,
                        year_level INT NOT NULL,
                        section VARCHAR(20) NOT NULL,
                        department VARCHAR(50),
                        day VARCHAR(10) NOT NULL,
                        period INT NOT NULL,
                        start_time TIME NOT NULL,
                        end_time TIME NOT NULL,
                        room VARCHAR(30),
                        last_updated_by VARCHAR(50),
                        last_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        FOREIGN KEY (faculty_id) REFERENCES faculty(faculty_id),
                        FOREIGN KEY (subject_id) REFERENCES subjects(subject_id)
                    )
                    """
                )
            )

            # Add period column if it doesn't exist (for table migration)
            try:
                conn.execute(
                    text(
                        """
                        ALTER TABLE timetable ADD COLUMN period INT NOT NULL DEFAULT 1
                        """
                    )
                )
            except:
                pass  # Column already exists

            # Add department column if it doesn't exist
            try:
                conn.execute(
                    text(
                        """
                        ALTER TABLE timetable ADD COLUMN department VARCHAR(50)
                        """
                    )
                )
            except:
                pass  # Column already exists

            year_options = conn.execute(
                text(
                    """
                    SELECT DISTINCT s.year_level AS year
                    FROM enrollments e
                    JOIN students s ON s.student_id = e.student_id
                    WHERE e.faculty_id = :fid
                    ORDER BY s.year_level
                    """
                ),
                {"fid": fid},
            ).mappings().all()

            department_options = conn.execute(
                text(
                    """
                    SELECT DISTINCT department
                    FROM faculty
                    WHERE department IS NOT NULL AND department <> ''
                    ORDER BY department
                    """
                )
            ).scalars().all()

            selected_year = request.args.get("year", type=int)
            if selected_year is None and year_options:
                selected_year = year_options[0]["year"]

            subject_list = conn.execute(
                text(
                    """
                    SELECT DISTINCT sub.subject_id, sub.subject_code, sub.subject_name
                    FROM enrollments e
                    JOIN subjects sub ON sub.subject_id = e.subject_id
                    WHERE e.faculty_id = :fid
                    ORDER BY sub.subject_code
                    """
                ),
                {"fid": fid},
            ).mappings().all()

            timetable_entries = conn.execute(
                text(
                    """
                    SELECT t.timetable_id, t.subject_id, t.year_level, t.section, t.department, t.day, t.period, t.start_time, t.end_time, t.room,
                           sub.subject_code, sub.subject_name
                    FROM timetable t
                    JOIN subjects sub ON sub.subject_id = t.subject_id
                    WHERE t.faculty_id = :fid
                      AND t.day IN ('Monday','Tuesday','Wednesday','Thursday','Friday')
                      AND (:year_level IS NULL OR t.year_level = :year_level)
                    ORDER BY FIELD(t.day, 'Monday','Tuesday','Wednesday','Thursday','Friday'), t.period
                    """
                ),
                {"fid": fid, "year_level": selected_year},
            ).mappings().all()

        if request.method == "POST":
            entry_id = request.form.get("entry_id")
            subject_id = request.form.get("subject_id")
            year_level = request.form.get("year_level")
            period = request.form.get("period")
            section = request.form.get("section", "").strip()
            day = request.form.get("day", "").strip()
            room = request.form.get("room", "").strip()

            department = request.form.get("department", "").strip()
            if not subject_id or not year_level or not period or not section or not day or not department:
                flash("All fields except room are required.", "danger")
                return render_template(
                    "timetable.html",
                    entries=timetable_entries,
                    subjects=subject_list,
                    year_options=year_options,
                    selected_year=selected_year,
                    department_options=department_options,
                    selected_department=department,
                )

            try:
                sid = int(subject_id)
            except ValueError:
                flash("Invalid subject selection.", "danger")
                return render_template("timetable.html", entries=timetable_entries, subjects=subject_list)

            period_map = {
                '1': ('09:00', '10:00'),
                '2': ('10:00', '11:00'),
                '3': ('11:00', '12:00'),
                '4': ('13:00', '14:00'),
                '5': ('14:00', '15:00'),
                '6': ('15:00', '16:00'),
            }
            if period not in period_map:
                flash('Invalid period selected.', 'danger')
                return render_template('timetable.html', entries=timetable_entries, subjects=subject_list, year_options=year_options, selected_year=selected_year)

            start_time, end_time = period_map[period]

            try:
                with engine.begin() as conn:
                    if entry_id:
                        conn.execute(
                            text(
                                """
                                UPDATE timetable
                                SET subject_id = :subject_id,
                                    year_level = :year_level,
                                    section = :section,
                                    department = :department,
                                    period = :period,
                                    day = :day,
                                    start_time = :start_time,
                                    end_time = :end_time,
                                    room = :room,
                                    last_updated_by = :updated_by
                                WHERE timetable_id = :entry_id
                                  AND faculty_id = :fid
                                """
                            ),
                            {
                                "subject_id": sid,
                                "year_level": int(year_level),
                                "section": section,
                                "department": request.form.get("department", ""),
                                "period": int(period),
                                "day": day,
                                "start_time": start_time,
                                "end_time": end_time,
                                "room": room,
                                "updated_by": user.get("username"),
                                "entry_id": int(entry_id),
                                "fid": fid,
                            },
                        )
                        flash("Timetable entry updated.", "success")
                    else:
                        conn.execute(
                            text(
                                """
                                INSERT INTO timetable (
                                    faculty_id, subject_id, year_level, section, department, period, day, start_time, end_time, room, last_updated_by
                                ) VALUES (
                                    :fid, :subject_id, :year_level, :section, :department, :period, :day, :start_time, :end_time, :room, :updated_by
                                )
                                """
                            ),
                            {
                                "fid": fid,
                                "subject_id": sid,
                                "year_level": int(year_level),
                                "section": section,
                                "department": request.form.get("department", ""),
                                "period": int(period),
                                "day": day,
                                "start_time": start_time,
                                "end_time": end_time,
                                "room": room,
                                "updated_by": user.get("username"),
                            },
                        )
                        flash("Timetable entry added.", "success")
            except SQLAlchemyError as exc:
                flash(f"Error saving timetable: {exc}", "danger")

            return redirect(url_for("faculty_timetable"))

        return render_template(
            "timetable.html",
            entries=timetable_entries,
            subjects=subject_list,
            year_options=year_options,
            selected_year=selected_year,
            department_options=department_options,
        )

    @app.route("/faculty/feedbacks")
    def faculty_feedbacks():
        if not require_role("FACULTY"):
            flash("Only faculty can view feedback reports.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        engine = app.config["DB_ENGINE"]
        fid = user.get("faculty_id")

        selected_class_key = request.args.get("class_key", "")
        class_options = []
        selected_class = None

        with engine.begin() as conn:
            class_rows = conn.execute(
                text(
                    """
                    SELECT DISTINCT st.year_level, st.section, st.department
                    FROM enrollments e
                    JOIN students st ON st.student_id = e.student_id
                    WHERE e.faculty_id = :fid
                    ORDER BY st.year_level, st.section, st.department
                    """
                ),
                {"fid": fid},
            ).mappings().all()

            for row in class_rows:
                year_level = row["year_level"]
                section = row["section"] or ""
                department = row["department"] or ""
                key = f"{year_level}|{section}|{department}"
                class_options.append(
                    {
                        "key": key,
                        "year_level": year_level,
                        "section": section,
                        "department": department,
                        "label": f"Year {year_level} / Section {section} / {department or 'N/A'}",
                    }
                )

            if class_options:
                if selected_class_key:
                    selected_class = next((c for c in class_options if c["key"] == selected_class_key), None)
                if not selected_class:
                    selected_class = class_options[0]
                selected_class_key = selected_class["key"]

            if selected_class:
                selected_year = selected_class["year_level"]
                selected_section = selected_class["section"]
                selected_department = selected_class["department"]
            else:
                selected_year = None
                selected_section = ""
                selected_department = ""

            rows = conn.execute(
                text(
                    """
                    SELECT e.enroll_id,
                           s.subject_id,
                           s.subject_code,
                           s.subject_name,
                           st.student_id,
                           st.reg_no,
                           st.name AS student_name,
                           st.year_level,
                           st.section,
                           st.department,
                           fb.feedback_id,
                           fb.teaching_quality,
                           fb.subject_knowledge,
                           fb.communication,
                           fb.preparation,
                           fb.responsiveness,
                           fb.punctuality,
                           fb.overall_rating,
                           fb.comments,
                           fb.submitted_at
                    FROM enrollments e
                    JOIN students st ON st.student_id = e.student_id
                    JOIN subjects s ON s.subject_id = e.subject_id
                    LEFT JOIN feedback fb ON fb.enroll_id = e.enroll_id
                    WHERE e.faculty_id = :fid
                      AND (:selected_year IS NULL OR st.year_level = :selected_year)
                      AND (:selected_section = '' OR st.section = :selected_section)
                      AND (:selected_department = '' OR COALESCE(st.department, '') = :selected_department)
                    ORDER BY s.subject_code, st.reg_no
                    """
                ),
                {
                    "fid": fid,
                    "selected_year": selected_year,
                    "selected_section": selected_section or "",
                    "selected_department": selected_department or "",
                },
            ).mappings().all()

        subject_map = {}
        for row in rows:
            subject_key = (row["subject_id"], row["subject_code"], row["subject_name"])
            subject = subject_map.get(subject_key)
            if not subject:
                subject = {
                    "subject_id": row["subject_id"],
                    "subject_code": row["subject_code"],
                    "subject_name": row["subject_name"],
                    "classes": {},
                    "feedback_count": 0,
                }
                subject_map[subject_key] = subject

            class_key = (row["year_level"], row["section"], row["department"])
            class_group = subject["classes"].get(class_key)
            if not class_group:
                class_group = {
                    "year_level": row["year_level"],
                    "section": row["section"],
                    "department": row["department"],
                    "feedback_count": 0,
                    "feedbacks": [],
                }
                subject["classes"][class_key] = class_group

            if row["feedback_id"] is not None:
                class_group["feedback_count"] += 1
                subject["feedback_count"] += 1
                class_group["feedbacks"].append(
                    {
                        "student_name": row["student_name"],
                        "reg_no": row["reg_no"],
                        "year_level": row["year_level"],
                        "section": row["section"],
                        "department": row["department"],
                        "teaching_quality": row["teaching_quality"],
                        "subject_knowledge": row["subject_knowledge"],
                        "communication": row["communication"],
                        "preparation": row["preparation"],
                        "responsiveness": row["responsiveness"],
                        "punctuality": row["punctuality"],
                        "overall_rating": row["overall_rating"],
                        "comments": row["comments"],
                        "submitted_at": row["submitted_at"],
                    }
                )

        subjects = []
        for subject in subject_map.values():
            classes = sorted(
                subject["classes"].values(),
                key=lambda c: (c["year_level"] or 0, c["section"], c["department"] or "")
            )
            subject["classes"] = classes
            subjects.append(subject)

        subjects.sort(key=lambda s: (s["subject_code"], s["subject_name"]))

        totals = {
            "total_subjects": len(subjects),
            "total_classes": 1 if selected_class else 0,
            "total_feedbacks": sum(s["feedback_count"] for s in subjects),
        }

        return render_template(
            "faculty_feedbacks.html",
            subjects=subjects,
            totals=totals,
            class_options=class_options,
            selected_class=selected_class,
        )

    @app.route("/timetable/delete/<int:tid>", methods=["POST"])
    def delete_timetable_entry(tid):
        if not require_role("FACULTY"):
            flash("Only faculty can delete timetable entries.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        fid = user.get("faculty_id")
        engine = app.config["DB_ENGINE"]

        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        """
                        DELETE FROM timetable
                        WHERE timetable_id = :tid AND faculty_id = :fid
                        """
                    ),
                    {"tid": tid, "fid": fid},
                )
            flash("Timetable entry deleted.", "success")
        except SQLAlchemyError as exc:
            flash(f"Could not delete timetable entry: {exc}", "danger")

        return redirect(url_for("faculty_timetable"))

    @app.route("/marks/detailed", methods=["GET", "POST"])
    def marks_entry_detailed():
        """Question-wise and component-wise marks entry"""
        if not require_role("ADMIN", "FACULTY"):
            flash("Only admin or faculty can enter marks.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        engine = app.config["DB_ENGINE"]
        subjects_for_faculty = []
        sections_for_subject = []
        departments_for_subject = []
        years_for_subject = []
        selected_subject_id = None
        selected_year = None
        selected_section = ""
        selected_department = ""

        is_faculty = user["role"] == "FACULTY" and user.get("faculty_id")
        fid = user["faculty_id"] if is_faculty else None

        form_subject_id = request.form.get("subject_id")
        arg_subject_id = request.args.get("subject_id")
        raw_subject_id = arg_subject_id if request.method == "GET" else form_subject_id
        try:
            raw_subject_id_int = int(raw_subject_id) if raw_subject_id not in (None, "") else None
        except ValueError:
            raw_subject_id_int = None

        raw_section = request.args.get("section") if request.method == "GET" else request.form.get("section")
        if raw_section is None:
            raw_section = ""
        raw_section_str = raw_section

        raw_department = request.args.get("department") if request.method == "GET" else request.form.get("department")
        if raw_department is None:
            raw_department = ""
        raw_department_str = raw_department

        raw_year = request.args.get("year") if request.method == "GET" else request.form.get("year")
        if raw_year is None or raw_year == "":
            raw_year_int = None
        else:
            try:
                raw_year_int = int(raw_year)
            except ValueError:
                raw_year_int = None

        with engine.begin() as conn:
            if is_faculty:
                subjects_for_faculty = conn.execute(
                    text(
                        """
                        SELECT DISTINCT sub.subject_id, sub.subject_code, sub.subject_name
                        FROM enrollments e
                        JOIN subjects sub ON sub.subject_id = e.subject_id
                        WHERE e.faculty_id = :fid
                        ORDER BY sub.subject_code
                        """
                    ),
                    {"fid": fid},
                ).mappings().all()

                allowed_subject_ids = {s["subject_id"] for s in subjects_for_faculty}
                if raw_subject_id_int in allowed_subject_ids:
                    selected_subject_id = raw_subject_id_int
                elif subjects_for_faculty:
                    selected_subject_id = subjects_for_faculty[0]["subject_id"]

                if selected_subject_id is not None:
                    years_for_subject = conn.execute(
                        text(
                            """
                            SELECT DISTINCT s.year_level AS year
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                            ORDER BY s.year_level
                            """
                        ),
                        {"fid": fid, "sid": selected_subject_id},
                    ).mappings().all()
                    allowed_years = {r["year"] for r in years_for_subject}
                    if raw_year_int in allowed_years:
                        selected_year = raw_year_int
                    elif years_for_subject:
                        selected_year = years_for_subject[0]["year"]

                    departments_for_subject = conn.execute(
                        text(
                            """
                            SELECT DISTINCT s.department AS department
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                              AND s.year_level = :year
                            ORDER BY s.department
                            """
                        ),
                        {"fid": fid, "sid": selected_subject_id, "year": selected_year},
                    ).mappings().all()
                    allowed_departments = {r["department"] for r in departments_for_subject}

                    if raw_department_str in allowed_departments:
                        selected_department = raw_department_str
                    elif departments_for_subject:
                        selected_department = departments_for_subject[0]["department"]

                    sections_for_subject = conn.execute(
                        text(
                            """
                            SELECT DISTINCT COALESCE(s.section,'') AS section
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                              AND s.department = :department
                              AND s.year_level = :year
                            ORDER BY section
                            """
                        ),
                        {
                            "fid": fid,
                            "sid": selected_subject_id,
                            "department": selected_department,
                            "year": selected_year,
                        },
                    ).mappings().all()
                    allowed_sections = {r["section"] for r in sections_for_subject}

                    if raw_section_str in allowed_sections:
                        selected_section = raw_section_str
                    elif sections_for_subject:
                        selected_section = sections_for_subject[0]["section"]

                if selected_subject_id is None or selected_year is None or selected_section == "" or selected_department == "":
                    enrollments = []
                else:
                    enrollments = conn.execute(
                        text(
                            """
                            SELECT e.enroll_id,
                                   s.reg_no,
                                   s.name AS student_name,
                                   s.department AS student_department,
                                   sub.subject_code,
                                   sub.subject_name
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            JOIN subjects sub ON sub.subject_id = e.subject_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                              AND COALESCE(s.section,'') = :section
                              AND s.department = :department
                              AND s.year_level = :year
                            ORDER BY s.reg_no
                            """
                        ),
                        {
                            "fid": fid,
                            "sid": selected_subject_id,
                            "section": selected_section,
                            "department": selected_department,
                            "year": selected_year,
                        },
                    ).mappings().all()
            else:
                departments_for_subject = conn.execute(
                    text("SELECT DISTINCT department FROM students ORDER BY department")
                ).mappings().all()
                allowed_departments = {d["department"] for d in departments_for_subject}

                if raw_department_str in allowed_departments:
                    selected_department = raw_department_str
                elif departments_for_subject:
                    selected_department = departments_for_subject[0]["department"]

                years_for_subject = conn.execute(
                    text(
                        """
                        SELECT DISTINCT year_level AS year
                        FROM students
                        WHERE department = :department
                        ORDER BY year_level
                        """
                    ),
                    {"department": selected_department},
                ).mappings().all()
                allowed_years = {r["year"] for r in years_for_subject}
                if raw_year_int in allowed_years:
                    selected_year = raw_year_int
                elif years_for_subject:
                    selected_year = years_for_subject[0]["year"]

                sections_for_subject = conn.execute(
                    text(
                        """
                        SELECT DISTINCT COALESCE(section,'') AS section
                        FROM students
                        WHERE department = :department
                          AND year_level = :year
                        ORDER BY section
                        """
                    ),
                    {"department": selected_department, "year": selected_year},
                ).mappings().all()
                allowed_sections = {s["section"] for s in sections_for_subject}

                if raw_section_str in allowed_sections:
                    selected_section = raw_section_str
                elif sections_for_subject:
                    selected_section = sections_for_subject[0]["section"]

                if selected_department == "" or selected_section == "" or selected_year is None:
                    enrollments = []
                else:
                    enrollments = conn.execute(
                        text(
                            """
                            SELECT e.enroll_id,
                                   s.reg_no,
                                   s.name AS student_name,
                                   s.department AS student_department,
                                   sub.subject_code,
                                   sub.subject_name
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            JOIN subjects sub ON sub.subject_id = e.subject_id
                            WHERE s.department = :department
                              AND COALESCE(s.section, '') = :section
                              AND s.year_level = :year
                            ORDER BY sub.subject_code, s.reg_no
                            """
                        ),
                        {
                            "department": selected_department,
                            "section": selected_section,
                            "year": selected_year,
                        },
                    ).mappings().all()

        if request.method == "POST":
            enroll_id = request.form.get("enroll_id")
            user_username = request.form.get("updated_by") or "faculty"
            
            try:
                # Parse question-wise marks for Cycle Tests
                ct1_questions = []
                for q in range(1, 6):
                    marks = float(request.form.get(f"ct1_q{q}") or 0)
                    if marks > 10:
                        raise ValueError(f"Question {q} in CT1 cannot exceed 10 marks")
                    ct1_questions.append(marks)
                
                ct2_questions = []
                for q in range(1, 6):
                    marks = float(request.form.get(f"ct2_q{q}") or 0)
                    if marks > 10:
                        raise ValueError(f"Question {q} in CT2 cannot exceed 10 marks")
                    ct2_questions.append(marks)
                
                # Calculate scaled values
                ct1_total = sum(ct1_questions)
                ct2_total = sum(ct2_questions)
                ct1_scaled = (ct1_total / 50) * 15 if ct1_total <= 50 else float('inf')
                ct2_scaled = (ct2_total / 50) * 15 if ct2_total <= 50 else float('inf')
                
                # Parse project components
                project_impl = float(request.form.get("project_impl") or 0)
                project_research = float(request.form.get("project_research") or 0)
                project_review = float(request.form.get("project_review") or 0)
                project_total = project_impl + project_research + project_review
                
                if project_impl > 8:
                    raise ValueError("Implementation cannot exceed 8 marks")
                if project_research > 8:
                    raise ValueError("Research Paper cannot exceed 8 marks")
                if project_review > 4:
                    raise ValueError("Final Review cannot exceed 4 marks")
                if project_total > 20:
                    raise ValueError("Project total cannot exceed 20 marks")
                
                # Assignment marks
                assignment_marks = float(request.form.get("assignment_marks") or 0)
                if assignment_marks > 10:
                    raise ValueError("Assignment cannot exceed 10 marks")
                
                # Calculate internal total
                internal_total = ct1_scaled + ct2_scaled + project_total + assignment_marks
                if internal_total > 60:
                    raise ValueError(f"Internal total ({internal_total}) cannot exceed 60 marks")
                
                data = {
                    "enroll_id": int(enroll_id),
                    "cycle_test_1": ct1_scaled,
                    "cycle_test_2": ct2_scaled,
                    "project_marks": project_total,
                    "assignment_marks": assignment_marks,
                    "updated_by": user_username,
                }
            except (ValueError, TypeError) as e:
                flash(f"Marks validation error: {str(e)}", "danger")
                return render_template(
                    "marks_entry_detailed.html",
                    enrollments=enrollments,
                    subjects_for_faculty=subjects_for_faculty,
                    sections_for_subject=sections_for_subject,
                    departments_for_subject=departments_for_subject,
                    selected_subject_id=selected_subject_id,
                    selected_section=selected_section,
                    selected_department=selected_department,
                    years_for_subject=years_for_subject,
                    selected_year=selected_year,
                )

            if is_faculty:
                with engine.begin() as conn:
                    allowed = conn.execute(
                        text(
                            """
                            SELECT 1
                            FROM enrollments e
                            WHERE e.enroll_id = :enroll_id
                              AND e.faculty_id = :fid
                            LIMIT 1
                            """
                        ),
                        {
                            "enroll_id": int(enroll_id),
                            "fid": fid,
                        },
                    ).scalar_one_or_none()

                if not allowed:
                    flash("Unauthorized enrollment for this faculty.", "danger")
                    return render_template(
                        "marks_entry_detailed.html",
                        enrollments=enrollments,
                        subjects_for_faculty=subjects_for_faculty,
                        sections_for_subject=sections_for_subject,
                        departments_for_subject=departments_for_subject,
                        selected_subject_id=selected_subject_id,
                        selected_section=selected_section,
                        selected_department=selected_department,
                        years_for_subject=years_for_subject,
                        selected_year=selected_year,
                    )

            try:
                with engine.begin() as conn:
                    # Get student_id from enroll_id
                    enroll_data = conn.execute(
                        text("SELECT student_id FROM enrollments WHERE enroll_id = :eid"),
                        {"eid": int(enroll_id)}
                    ).mappings().first()
                    
                    if not enroll_data:
                        raise ValueError("Invalid enrollment")
                    
                    student_id = enroll_data["student_id"]

                    # Detect optional student_id column in marks table (for schema compatibility)
                    include_student_id = conn.execute(
                        text("SHOW COLUMNS FROM marks LIKE 'student_id'")
                    ).first() is not None
                    if include_student_id:
                        data["student_id"] = student_id

                    # Update or insert marks
                    updated = conn.execute(
                        text(
                            """
                            UPDATE marks
                            SET cycle_test_1 = :cycle_test_1,
                                cycle_test_2 = :cycle_test_2,
                                project_marks = :project_marks,
                                assignment_marks = :assignment_marks,
                                last_updated_by = :updated_by,
                                last_updated_at = CURRENT_TIMESTAMP
                            WHERE enroll_id = :enroll_id
                            """
                        ),
                        data,
                    ).rowcount

                    mark_id = None
                    if updated == 0:
                        # Insert new row
                        if include_student_id:
                            insert_query = text(
                                """
                                INSERT INTO marks (
                                    enroll_id, student_id, cycle_test_1, cycle_test_2,
                                    project_marks, assignment_marks, last_updated_by,
                                    last_updated_at
                                ) VALUES (
                                    :enroll_id, :student_id, :cycle_test_1, :cycle_test_2,
                                    :project_marks, :assignment_marks, :updated_by,
                                    CURRENT_TIMESTAMP
                                )
                                """
                            )
                        else:
                            insert_query = text(
                                """
                                INSERT INTO marks (
                                    enroll_id, cycle_test_1, cycle_test_2,
                                    project_marks, assignment_marks, last_updated_by,
                                    last_updated_at
                                ) VALUES (
                                    :enroll_id, :cycle_test_1, :cycle_test_2,
                                    :project_marks, :assignment_marks, :updated_by,
                                    CURRENT_TIMESTAMP
                                )
                                """
                            )
                        result = conn.execute(insert_query, data)
                        # Get the inserted mark_id
                        mark_id = conn.execute(text("SELECT LAST_INSERT_ID() as id")).scalar()
                    else:
                        # Get existing mark_id
                        mark_data = conn.execute(
                            text("SELECT mark_id FROM marks WHERE enroll_id = :eid"),
                            {"eid": int(enroll_id)}
                        ).mappings().first()
                        mark_id = mark_data["mark_id"] if mark_data else None
                    
                    # Delete existing question/component records and insert fresh ones
                    if mark_id:
                        conn.execute(text("CREATE TABLE IF NOT EXISTS cycle_test_questions (question_id INT PRIMARY KEY AUTO_INCREMENT, mark_id INT NOT NULL, test_number INT CHECK (test_number IN (1, 2)), question_number INT CHECK (question_number BETWEEN 1 AND 50), marks_obtained DECIMAL(5,2) CHECK (marks_obtained >= 0), max_marks DECIMAL(5,2) DEFAULT 10, FOREIGN KEY (mark_id) REFERENCES marks(mark_id), UNIQUE(mark_id, test_number, question_number))"))
                        conn.execute(text("CREATE TABLE IF NOT EXISTS project_components (component_id INT PRIMARY KEY AUTO_INCREMENT, mark_id INT NOT NULL, component_name VARCHAR(100), marks_obtained DECIMAL(5,2) CHECK (marks_obtained >= 0), max_marks DECIMAL(5,2), FOREIGN KEY (mark_id) REFERENCES marks(mark_id))"))
                        conn.execute(text("DELETE FROM cycle_test_questions WHERE mark_id = :mid"), {"mid": mark_id})
                        conn.execute(text("DELETE FROM project_components WHERE mark_id = :mid"), {"mid": mark_id})
                        
                        # Insert cycle test 1 questions
                        for q_num, marks in enumerate(ct1_questions, 1):
                            conn.execute(
                                text(
                                    """
                                    INSERT INTO cycle_test_questions 
                                    (mark_id, test_number, question_number, marks_obtained, max_marks)
                                    VALUES (:mid, 1, :qnum, :marks, 10)
                                    """
                                ),
                                {"mid": mark_id, "qnum": q_num, "marks": marks}
                            )
                        
                        # Insert cycle test 2 questions
                        for q_num, marks in enumerate(ct2_questions, 1):
                            conn.execute(
                                text(
                                    """
                                    INSERT INTO cycle_test_questions 
                                    (mark_id, test_number, question_number, marks_obtained, max_marks)
                                    VALUES (:mid, 2, :qnum, :marks, 10)
                                    """
                                ),
                                {"mid": mark_id, "qnum": q_num, "marks": marks}
                            )
                        
                        # Insert project components
                        components = [
                            ("Implementation", project_impl, 8),
                            ("Research Paper", project_research, 8),
                            ("Final Review", project_review, 4),
                        ]
                        for comp_name, marks, max_m in components:
                            conn.execute(
                                text(
                                    """
                                    INSERT INTO project_components 
                                    (mark_id, component_name, marks_obtained, max_marks)
                                    VALUES (:mid, :cname, :marks, :max)
                                    """
                                ),
                                {"mid": mark_id, "cname": comp_name, "marks": marks, "max": max_m}
                            )
                
                flash("Marks saved successfully with detailed breakdown!", "success")
            except SQLAlchemyError as exc:
                flash(f"Error saving marks: {exc}", "danger")

        return render_template(
            "marks_entry_detailed.html",
            enrollments=enrollments,
            subjects_for_faculty=subjects_for_faculty,
            sections_for_subject=sections_for_subject,
            departments_for_subject=departments_for_subject,
            selected_subject_id=selected_subject_id,
            selected_section=selected_section,
            selected_department=selected_department,
            years_for_subject=years_for_subject,
            selected_year=selected_year,
        )

    @app.route("/marks/all")
    def marks_all_view():
        if not require_role("ADMIN", "FACULTY"):
            flash("Only admin or faculty can view marks.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        is_faculty = user and user.get("role") == "FACULTY" and user.get("faculty_id")
        faculty_id = user.get("faculty_id") if is_faculty else None

        selected_department = request.args.get("department", "")
        selected_section = request.args.get("section", "")

        engine = app.config["DB_ENGINE"]
        with engine.begin() as conn:
            if is_faculty:
                departments = conn.execute(
                    text(
                        """
                        SELECT DISTINCT s.department
                        FROM students s
                        JOIN enrollments e ON e.student_id = s.student_id
                        WHERE e.faculty_id = :fid
                        ORDER BY s.department
                        """
                    ),
                    {"fid": faculty_id},
                ).scalars().all()
            else:
                departments = conn.execute(
                    text("SELECT DISTINCT department FROM students ORDER BY department")
                ).scalars().all()

            sections = []
            if selected_department:
                if is_faculty:
                    sections = conn.execute(
                        text(
                            """
                            SELECT DISTINCT s.section
                            FROM students s
                            JOIN enrollments e ON e.student_id = s.student_id
                            WHERE e.faculty_id = :fid
                              AND s.department = :department
                            ORDER BY s.section
                            """
                        ),
                        {"fid": faculty_id, "department": selected_department},
                    ).scalars().all()
                else:
                    sections = conn.execute(
                        text(
                            "SELECT DISTINCT section FROM students WHERE department = :department ORDER BY section"
                        ),
                        {"department": selected_department},
                    ).scalars().all()

            where_clauses = []
            params = {}
            if is_faculty:
                where_clauses.append("e.faculty_id = :fid")
                params["fid"] = faculty_id
            if selected_department:
                where_clauses.append("s.department = :department")
                params["department"] = selected_department
            if selected_section:
                where_clauses.append("COALESCE(s.section, '') = :section")
                params["section"] = selected_section

            where_sql = "" if not where_clauses else "WHERE " + " AND ".join(where_clauses)

            records = conn.execute(
                text(
                    f"""
                    SELECT m.*, e.enroll_id,
                           s.reg_no, s.name AS student_name, s.department AS student_department, s.section AS student_section,
                           sub.subject_code, sub.subject_name,
                           f.emp_no AS faculty_emp_no, f.name AS faculty_name
                    FROM marks m
                    JOIN enrollments e ON e.enroll_id = m.enroll_id
                    JOIN students s ON s.student_id = e.student_id
                    JOIN subjects sub ON sub.subject_id = e.subject_id
                    JOIN faculty f ON f.faculty_id = e.faculty_id
                    {where_sql}
                    ORDER BY s.department, s.section, s.reg_no, sub.subject_code
                    """
                ),
                params,
            ).mappings().all()

            # Attach question/component-level split data for each mark.
            records = [dict(r) for r in records]
            mark_ids = [r['mark_id'] for r in records]
            ct_questions_by_mark = defaultdict(list)
            project_components_by_mark = defaultdict(list)

            if mark_ids:
                id_list = ",".join(str(int(mid)) for mid in mark_ids)

                ct_rows = conn.execute(
                    text(
                        f"""
                        SELECT mark_id, test_number, question_number, marks_obtained, max_marks
                        FROM cycle_test_questions
                        WHERE mark_id IN ({id_list})
                        ORDER BY mark_id, test_number, question_number
                        """
                    )
                ).mappings().all()

                for q in ct_rows:
                    ct_questions_by_mark[q['mark_id']].append(q)

                project_rows = conn.execute(
                    text(
                        f"""
                        SELECT mark_id, component_name, marks_obtained, max_marks
                        FROM project_components
                        WHERE mark_id IN ({id_list})
                        ORDER BY mark_id, component_id
                        """
                    )
                ).mappings().all()

                for c in project_rows:
                    project_components_by_mark[c['mark_id']].append(c)

            for rec in records:
                rec['ct1_questions'] = [q for q in ct_questions_by_mark.get(rec['mark_id'], []) if q['test_number'] == 1]
                rec['ct2_questions'] = [q for q in ct_questions_by_mark.get(rec['mark_id'], []) if q['test_number'] == 2]
                rec['project_components'] = project_components_by_mark.get(rec['mark_id'], [])

        return render_template(
            "marks_all.html",
            marks=records,
            departments=departments,
            sections=sections,
            selected_department=selected_department,
            selected_section=selected_section,
        )

    @app.route("/marks/all/download")
    def marks_all_download():
        if not require_role("ADMIN", "FACULTY"):
            flash("Only admin or faculty can download marks.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        is_faculty = user and user.get("role") == "FACULTY" and user.get("faculty_id")
        faculty_id = user.get("faculty_id") if is_faculty else None
        selected_department = request.args.get("department", "")
        selected_section = request.args.get("section", "")

        engine = app.config["DB_ENGINE"]
        with engine.begin() as conn:
            where_clauses = []
            params = {}
            if is_faculty:
                where_clauses.append("e.faculty_id = :fid")
                params["fid"] = faculty_id
            if selected_department:
                where_clauses.append("s.department = :department")
                params["department"] = selected_department
            if selected_section:
                where_clauses.append("COALESCE(s.section, '') = :section")
                params["section"] = selected_section

            where_sql = "" if not where_clauses else "WHERE " + " AND ".join(where_clauses)

            records = conn.execute(
                text(
                    f"""
                    SELECT m.*, e.enroll_id,
                           s.reg_no, s.name AS student_name, s.department AS student_department, s.section AS student_section,
                           sub.subject_code, sub.subject_name,
                           f.emp_no AS faculty_emp_no, f.name AS faculty_name
                    FROM marks m
                    JOIN enrollments e ON e.enroll_id = m.enroll_id
                    JOIN students s ON s.student_id = e.student_id
                    JOIN subjects sub ON sub.subject_id = e.subject_id
                    JOIN faculty f ON f.faculty_id = e.faculty_id
                    {where_sql}
                    ORDER BY s.department, s.section, s.reg_no, sub.subject_code
                    """
                ),
                params,
            ).mappings().all()

        mark_ids = [int(r["mark_id"]) for r in records if r["mark_id"] is not None]
        ct1_questions_by_mark = defaultdict(lambda: {q: None for q in range(1, 6)})
        ct2_questions_by_mark = defaultdict(lambda: {q: None for q in range(1, 6)})
        project_components_by_mark = defaultdict(lambda: {"Implementation": None, "Research Paper": None, "Final Review": None})

        if mark_ids:
            id_list = ",".join(str(mid) for mid in mark_ids)
            ct_rows = conn.execute(
                text(
                    f"""
                    SELECT mark_id, test_number, question_number, marks_obtained
                    FROM cycle_test_questions
                    WHERE mark_id IN ({id_list})
                    ORDER BY mark_id, test_number, question_number
                    """
                )
            ).mappings().all()
            for q in ct_rows:
                if q["test_number"] == 1:
                    ct1_questions_by_mark[q["mark_id"]][q["question_number"]] = q["marks_obtained"]
                else:
                    ct2_questions_by_mark[q["mark_id"]][q["question_number"]] = q["marks_obtained"]

            project_rows = conn.execute(
                text(
                    f"""
                    SELECT mark_id, component_name, marks_obtained
                    FROM project_components
                    WHERE mark_id IN ({id_list})
                    ORDER BY mark_id, component_id
                    """
                )
            ).mappings().all()
            for c in project_rows:
                project_components_by_mark[c["mark_id"]][c["component_name"]] = c["marks_obtained"]

        rows = []
        for r in records:
            mark_id = r["mark_id"]
            ct1 = ct1_questions_by_mark.get(mark_id, {}) if mark_id is not None else {}
            ct2 = ct2_questions_by_mark.get(mark_id, {}) if mark_id is not None else {}
            pc = project_components_by_mark.get(mark_id, {}) if mark_id is not None else {}
            rows.append(
                {
                    "Mark ID": r["mark_id"],
                    "Reg No": r["reg_no"],
                    "Student Name": r["student_name"],
                    "Department": r["student_department"],
                    "Section": r["student_section"],
                    "Subject Code": r["subject_code"],
                    "Subject Name": r["subject_name"],
                    "Faculty": f"{r['faculty_name']} ({r['faculty_emp_no']})",
                    "CT1-Q1": ct1.get(1),
                    "CT1-Q2": ct1.get(2),
                    "CT1-Q3": ct1.get(3),
                    "CT1-Q4": ct1.get(4),
                    "CT1-Q5": ct1.get(5),
                    "CT1 Total": r["cycle_test_1"],
                    "CT2-Q1": ct2.get(1),
                    "CT2-Q2": ct2.get(2),
                    "CT2-Q3": ct2.get(3),
                    "CT2-Q4": ct2.get(4),
                    "CT2-Q5": ct2.get(5),
                    "CT2 Total": r["cycle_test_2"],
                    "Project Implementation": pc.get("Implementation"),
                    "Project Research Paper": pc.get("Research Paper"),
                    "Project Final Review": pc.get("Final Review"),
                    "Project Marks": r["project_marks"],
                    "Assignment Marks": r["assignment_marks"],
                    "Last Updated At": r["last_updated_at"],
                    "Updated By": r["last_updated_by"],
                }
            )

        fieldnames = [
            "Mark ID",
            "Reg No",
            "Student Name",
            "Department",
            "Section",
            "Subject Code",
            "Subject Name",
            "Faculty",
            "CT1-Q1",
            "CT1-Q2",
            "CT1-Q3",
            "CT1-Q4",
            "CT1-Q5",
            "CT1 Total",
            "CT2-Q1",
            "CT2-Q2",
            "CT2-Q3",
            "CT2-Q4",
            "CT2-Q5",
            "CT2 Total",
            "Project Implementation",
            "Project Research Paper",
            "Project Final Review",
            "Project Marks",
            "Assignment Marks",
            "Last Updated At",
            "Updated By",
        ]
        return make_csv_response("marks_export.csv", fieldnames, rows)

    @app.route("/attendance/all")
    def attendance_all_view():
        if not require_role("ADMIN", "FACULTY"):
            flash("Only admin or faculty can view attendance.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        is_faculty = user and user.get("role") == "FACULTY" and user.get("faculty_id")
        faculty_id = user.get("faculty_id") if is_faculty else None

        selected_department = request.args.get("department", "")
        selected_section = request.args.get("section", "")

        engine = app.config["DB_ENGINE"]
        with engine.begin() as conn:
            if is_faculty:
                departments = conn.execute(
                    text(
                        """
                        SELECT DISTINCT s.department
                        FROM students s
                        JOIN enrollments e ON e.student_id = s.student_id
                        WHERE e.faculty_id = :fid
                        ORDER BY s.department
                        """
                    ),
                    {"fid": faculty_id},
                ).scalars().all()
            else:
                departments = conn.execute(
                    text("SELECT DISTINCT department FROM students ORDER BY department")
                ).scalars().all()

            sections = []
            if selected_department:
                if is_faculty:
                    sections = conn.execute(
                        text(
                            """
                            SELECT DISTINCT s.section
                            FROM students s
                            JOIN enrollments e ON e.student_id = s.student_id
                            WHERE e.faculty_id = :fid
                              AND s.department = :department
                            ORDER BY s.section
                            """
                        ),
                        {"fid": faculty_id, "department": selected_department},
                    ).scalars().all()
                else:
                    sections = conn.execute(
                        text(
                            "SELECT DISTINCT section FROM students WHERE department = :department ORDER BY section"
                        ),
                        {"department": selected_department},
                    ).scalars().all()

            where_clauses = []
            params = {}
            if is_faculty:
                where_clauses.append("e.faculty_id = :fid")
                params["fid"] = faculty_id
            if selected_department:
                where_clauses.append("s.department = :department")
                params["department"] = selected_department
            if selected_section:
                where_clauses.append("COALESCE(s.section, '') = :section")
                params["section"] = selected_section

            where_sql = "" if not where_clauses else "WHERE " + " AND ".join(where_clauses)

            raw_records = conn.execute(
                text(
                    f"""
                    SELECT a.*, e.enroll_id,
                           s.reg_no, s.name AS student_name, s.department AS student_department, s.section AS student_section,
                           sub.subject_code, sub.subject_name,
                           f.emp_no AS faculty_emp_no, f.name AS faculty_name
                    FROM attendance a
                    JOIN enrollments e ON e.enroll_id = a.enroll_id
                    JOIN students s ON s.student_id = e.student_id
                    JOIN subjects sub ON sub.subject_id = e.subject_id
                    JOIN faculty f ON f.faculty_id = e.faculty_id
                    {where_sql}
                    ORDER BY s.department, s.section, s.reg_no, sub.subject_code, a.attendance_date
                    """
                ),
                params,
            ).mappings().all()

            # Convert to mutable dict objects for easier updates
            records = [dict(r) for r in raw_records]

            attendance_by_enroll = defaultdict(list)
            for rec in records:
                eid = rec.get("enroll_id")
                attendance_by_enroll[eid].append(rec)

            collapsed = []
            for eid, recs in attendance_by_enroll.items():
                recs.sort(key=lambda r: r.get("attendance_date") or date.min)

                total_attended = sum(int(r.get("attended_classes") or 0) for r in recs)
                current_pct, _ = term_attendance_pct_and_eligibility(total_attended, ATTENDANCE_TERM_CLASS_COUNT)

                previous_attended = None
                previous_pct = None
                if len(recs) > 1:
                    previous_attended = total_attended - int(recs[-1].get("attended_classes") or 0)
                    previous_pct, _ = term_attendance_pct_and_eligibility(previous_attended, ATTENDANCE_TERM_CLASS_COUNT)

                delta_pct = None
                if previous_pct is not None:
                    delta_pct = round(current_pct - previous_pct, 2)

                latest = recs[-1]
                collapsed.append(
                    {
                        "enroll_id": eid,
                        "attendance_id": latest.get("attendance_id"),
                        "reg_no": latest.get("reg_no"),
                        "student_name": latest.get("student_name"),
                        "student_department": latest.get("student_department"),
                        "student_section": latest.get("student_section"),
                        "subject_code": latest.get("subject_code"),
                        "subject_name": latest.get("subject_name"),
                        "faculty_emp_no": latest.get("faculty_emp_no"),
                        "faculty_name": latest.get("faculty_name"),
                        "last_attendance_date": latest.get("attendance_date"),
                        "attended_sum": total_attended,
                        "term_total": ATTENDANCE_TERM_CLASS_COUNT,
                        "current_pct": current_pct,
                        "previous_pct": previous_pct,
                        "delta_pct": delta_pct,
                        "last_updated_at": latest.get("last_updated_at"),
                        "last_updated_by": latest.get("last_updated_by"),
                    }
                )

            records = collapsed

        return render_template(
            "attendance_all.html",
            attendance=records,
            departments=departments,
            sections=sections,
            selected_department=selected_department,
            selected_section=selected_section,
        )

    @app.route("/attendance/all/download")
    def attendance_all_download():
        if not require_role("ADMIN", "FACULTY"):
            flash("Only admin or faculty can download attendance.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        is_faculty = user and user.get("role") == "FACULTY" and user.get("faculty_id")
        faculty_id = user.get("faculty_id") if is_faculty else None
        selected_department = request.args.get("department", "")
        selected_section = request.args.get("section", "")

        engine = app.config["DB_ENGINE"]
        with engine.begin() as conn:
            where_clauses = []
            params = {}
            if is_faculty:
                where_clauses.append("e.faculty_id = :fid")
                params["fid"] = faculty_id
            if selected_department:
                where_clauses.append("s.department = :department")
                params["department"] = selected_department
            if selected_section:
                where_clauses.append("COALESCE(s.section, '') = :section")
                params["section"] = selected_section

            where_sql = "" if not where_clauses else "WHERE " + " AND ".join(where_clauses)

            raw_records = conn.execute(
                text(
                    f"""
                    SELECT a.*, e.enroll_id,
                           s.reg_no, s.name AS student_name, s.department AS student_department, s.section AS student_section,
                           sub.subject_code, sub.subject_name,
                           f.emp_no AS faculty_emp_no, f.name AS faculty_name
                    FROM attendance a
                    JOIN enrollments e ON e.enroll_id = a.enroll_id
                    JOIN students s ON s.student_id = e.student_id
                    JOIN subjects sub ON sub.subject_id = e.subject_id
                    JOIN faculty f ON f.faculty_id = e.faculty_id
                    {where_sql}
                    ORDER BY s.department, s.section, s.reg_no, sub.subject_code, a.attendance_date
                    """
                ),
                params,
            ).mappings().all()

            attendance_by_enroll = defaultdict(list)
            for rec in raw_records:
                eid = rec.get("enroll_id")
                attendance_by_enroll[eid].append(rec)

            rows = []
            for eid, recs in attendance_by_enroll.items():
                recs.sort(key=lambda r: r.get("attendance_date") or date.min)
                total_attended = sum(int(r.get("attended_classes") or 0) for r in recs)
                current_pct, _ = term_attendance_pct_and_eligibility(total_attended, ATTENDANCE_TERM_CLASS_COUNT)
                latest = recs[-1]
                rows.append(
                    {
                        "Enroll ID": eid,
                        "Attendance ID": latest.get("attendance_id"),
                        "Reg No": latest.get("reg_no"),
                        "Student Name": latest.get("student_name"),
                        "Department": latest.get("student_department"),
                        "Section": latest.get("student_section"),
                        "Subject Code": latest.get("subject_code"),
                        "Subject Name": latest.get("subject_name"),
                        "Faculty": f"{latest.get('faculty_name')} ({latest.get('faculty_emp_no')})",
                        "Last Date": latest.get("attendance_date"),
                        "Attended": total_attended,
                        "Term Total": ATTENDANCE_TERM_CLASS_COUNT,
                        "Current %": current_pct,
                        "Last Updated": latest.get("last_updated_at"),
                        "Updated By": latest.get("last_updated_by"),
                    }
                )

        fieldnames = [
            "Enroll ID",
            "Attendance ID",
            "Reg No",
            "Student Name",
            "Department",
            "Section",
            "Subject Code",
            "Subject Name",
            "Faculty",
            "Last Date",
            "Attended",
            "Term Total",
            "Current %",
            "Last Updated",
            "Updated By",
        ]

        return make_csv_response("attendance_export.csv", fieldnames, rows)

    @app.route("/anomalies")
    def anomaly_dashboard():
        if not require_role("ADMIN", "FACULTY"):
            flash("Only admin or faculty can view anomalies.", "danger")
            return redirect(url_for("login"))
        engine = app.config["DB_ENGINE"]
        with engine.begin() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT a.*, s.reg_no, s.name AS student_name, sub.subject_code
                    FROM anomalies a
                    JOIN enrollments e ON e.enroll_id = a.enroll_id
                    JOIN students s ON s.student_id = e.student_id
                    JOIN subjects sub ON sub.subject_id = e.subject_id
                    ORDER BY a.detected_at DESC
                    """
                )
            ).mappings().all()
        return render_template("anomaly_dashboard.html", anomalies=rows)

    @app.route("/anomalies/run", methods=["POST"])
    def run_anomaly_detection():
        if not require_role("ADMIN", "FACULTY"):
            flash("Only admin or faculty can trigger anomaly detection.", "danger")
            return redirect(url_for("login"))

        try:
            run_detection()
            flash("AI anomaly detection completed and dashboard refreshed.", "success")
        except Exception as exc:
            flash(f"Error running anomaly detection: {exc}", "danger")

        return redirect(url_for("anomaly_dashboard"))

    @app.route("/risk-scores")
    def risk_scores_dashboard():
        if not require_role("ADMIN", "FACULTY"):
            flash("Only admin or faculty can view risk scores.", "danger")
            return redirect(url_for("login"))
        engine = app.config["DB_ENGINE"]
        with engine.begin() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT srs.*, s.reg_no, s.name AS student_name, sub.subject_code,
                           m.internal_total, a.attendance_pct
                    FROM student_risk_scores srs
                    JOIN enrollments e ON e.enroll_id = srs.enroll_id
                    JOIN students s ON s.student_id = e.student_id
                    JOIN subjects sub ON sub.subject_id = e.subject_id
                    LEFT JOIN (
                        SELECT m1.*
                        FROM marks m1
                        JOIN (
                            SELECT enroll_id, MAX(mark_id) AS latest_mark_id
                            FROM marks
                            GROUP BY enroll_id
                        ) lm ON lm.enroll_id = m1.enroll_id AND lm.latest_mark_id = m1.mark_id
                    ) m ON m.enroll_id = srs.enroll_id
                    LEFT JOIN (
                        SELECT a1.*
                        FROM attendance a1
                        JOIN (
                            SELECT enroll_id, MAX(attendance_id) AS latest_attendance_id
                            FROM attendance
                            GROUP BY enroll_id
                        ) la ON la.enroll_id = a1.enroll_id AND la.latest_attendance_id = a1.attendance_id
                    ) a ON a.enroll_id = srs.enroll_id
                    ORDER BY srs.risk_score DESC
                    """
                )
            ).mappings().all()
        return render_template("risk_scores.html", risk_scores=rows)

    @app.route("/audit")
    def audit_log_view():
        if not require_role("ADMIN"):
            flash("Only admin can view audit log.", "danger")
            return redirect(url_for("login"))

        engine = app.config["DB_ENGINE"]
        with engine.begin() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT table_name, operation, record_id,
                           changed_by, changed_at, old_values, new_values
                    FROM audit_log
                    ORDER BY changed_at DESC
                    LIMIT 200
                    """
                )
            ).mappings().all()
        return render_template("audit_log.html", logs=rows)

    @app.route("/login-activity")
    def login_activity_view():
        if not require_role("ADMIN"):
            flash("Only admin can view login activity.", "danger")
            return redirect(url_for("login"))

        selected_role = request.args.get("role", "")
        selected_department = request.args.get("department", "")
        selected_section = request.args.get("section", "")
        selected_year = request.args.get("year", "")

        from zoneinfo import ZoneInfo
        ist_zone = ZoneInfo("Asia/Kolkata")

        engine = app.config["DB_ENGINE"]
        with engine.begin() as conn:
            roles = [r[0] for r in conn.execute(text("SELECT DISTINCT role FROM users ORDER BY role")).all()]

            where_clauses = []
            params = {}
            if selected_role:
                where_clauses.append("la.role = :role")
                params["role"] = selected_role
            if selected_department:
                where_clauses.append("la.department = :department")
                params["department"] = selected_department
            if selected_section:
                where_clauses.append("COALESCE(la.section, '') = :section")
                params["section"] = selected_section
            if selected_year:
                where_clauses.append("la.year_level = :year")
                try:
                    params["year"] = int(selected_year)
                except ValueError:
                    params["year"] = None

            where_sql = "" if not where_clauses else "WHERE " + " AND ".join(where_clauses)

            records = conn.execute(
                text(
                    f"""
                    SELECT la.*, u.username,
                           s.reg_no AS student_reg_no, s.name AS student_name,
                           f.emp_no AS faculty_emp_no, f.name AS faculty_name,
                           TIMESTAMPDIFF(MINUTE, la.login_at, la.logout_at) AS duration_minutes
                    FROM login_activity la
                    LEFT JOIN users u ON u.user_id = la.user_id
                    LEFT JOIN students s ON s.student_id = la.student_id
                    LEFT JOIN faculty f ON f.faculty_id = la.faculty_id
                    {where_sql}
                    ORDER BY la.login_at DESC
                    LIMIT 500
                    """
                ),
                params,
            ).mappings().all()

            formatted_records = []
            for r in records:
                item = dict(r)
                if item.get("login_at"):
                    if item["login_at"].tzinfo is None:
                        login_ist = item["login_at"].replace(tzinfo=ist_zone)
                    else:
                        login_ist = item["login_at"].astimezone(ist_zone)
                    item["login_at_ist"] = login_ist
                    item["login_dt"] = login_ist.strftime("%Y-%m-%d %H:%M:%S")
                    item["login_time"] = login_ist.strftime("%H:%M:%S")
                else:
                    item["login_at_ist"] = None
                    item["login_dt"] = None
                    item["login_time"] = None
                if item.get("logout_at"):
                    if item["logout_at"].tzinfo is None:
                        logout_ist = item["logout_at"].replace(tzinfo=ist_zone)
                    else:
                        logout_ist = item["logout_at"].astimezone(ist_zone)
                    item["logout_at_ist"] = logout_ist
                    item["logout_dt"] = logout_ist.strftime("%Y-%m-%d %H:%M:%S")
                    item["logout_time"] = logout_ist.strftime("%H:%M:%S")
                else:
                    item["logout_at_ist"] = None
                    item["logout_dt"] = None
                    item["logout_time"] = None
                formatted_records.append(item)

            departments = [d[0] for d in conn.execute(text("SELECT DISTINCT department FROM students ORDER BY department")).all()]
            sections = [s[0] for s in conn.execute(text("SELECT DISTINCT section FROM students ORDER BY section")).all()]
            years = [y[0] for y in conn.execute(text("SELECT DISTINCT year_level FROM students ORDER BY year_level")).all()]

        return render_template(
            "login_activity.html",
            activity=formatted_records,
            roles=roles,
            departments=departments,
            sections=sections,
            years=years,
            selected_role=selected_role,
            selected_department=selected_department,
            selected_section=selected_section,
            selected_year=selected_year,
        )

    @app.route("/me")
    def my_performance():
        if not require_role("STUDENT"):
            flash("Student login required to view personal performance.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        engine = app.config["DB_ENGINE"]

        student_id = user.get("student_id")
        if not student_id:
            # fallback: if student accounts use reg_no as username, try link automatically
            with engine.begin() as conn:
                fallback = conn.execute(
                    text(
                        "SELECT student_id FROM students WHERE reg_no = :reg_no OR name = :name LIMIT 1"
                    ),
                    {"reg_no": user.get("username"), "name": user.get("username")},
                ).mappings().first()

                if fallback:
                    student_id = fallback["student_id"]
                    session_user = session.get("user", {})
                    session_user["student_id"] = student_id
                    session["user"] = session_user
                    conn.execute(
                        text("UPDATE users SET student_id = :sid WHERE user_id = :uid"),
                        {"sid": student_id, "uid": user["user_id"]},
                    )
                    flash(
                        "Student account auto-linked by identifier; you should now see marks.",
                        "success",
                    )
                else:
                    flash("No student record is linked to this account.", "danger")
                    return redirect(url_for("index"))

        with engine.begin() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT e.enroll_id,
                           sub.subject_code,
                           sub.subject_name,
                           m.mark_id,
                           m.cycle_test_1,
                           m.cycle_test_2,
                           m.project_marks,
                           m.assignment_marks,
                           m.internal_total,
                           a.attendance_pct,
                           a.attended_classes,
                           a.total_classes,
                           a.eligibility
                    FROM enrollments e
                    JOIN subjects sub ON sub.subject_id = e.subject_id
                    LEFT JOIN (
                        SELECT m1.*
                        FROM marks m1
                        JOIN (
                            SELECT enroll_id, MAX(mark_id) AS latest_mark_id
                            FROM marks
                            GROUP BY enroll_id
                        ) t ON t.enroll_id = m1.enroll_id AND t.latest_mark_id = m1.mark_id
                    ) m ON m.enroll_id = e.enroll_id
                    LEFT JOIN (
                        SELECT a1.*
                        FROM attendance a1
                        JOIN (
                            SELECT enroll_id, MAX(attendance_id) AS latest_attendance_id
                            FROM attendance
                            GROUP BY enroll_id
                        ) t ON t.enroll_id = a1.enroll_id AND t.latest_attendance_id = a1.attendance_id
                    ) a ON a.enroll_id = e.enroll_id
                    WHERE e.student_id = :sid
                    ORDER BY sub.subject_code
                    """
                ),
                {"sid": user["student_id"]},
            ).mappings().all()

            attended_by_enroll = {
                r["enroll_id"]: float(r["attended_sum"] or 0)
                for r in conn.execute(
                    text(
                        """
                        SELECT e.enroll_id,
                               COALESCE(SUM(a.attended_classes), 0) AS attended_sum
                        FROM enrollments e
                        LEFT JOIN attendance a ON a.enroll_id = e.enroll_id
                        WHERE e.student_id = :sid
                        GROUP BY e.enroll_id
                        """
                    ),
                    {"sid": user["student_id"]},
                ).mappings().all()
            }

            # Fetch detailed marks breakdown for each enrollment
            rows = [dict(r) for r in rows]  # make mutable dicts for augmentation
            for row in rows:
                att_sum = attended_by_enroll.get(row["enroll_id"], 0.0)
                pct, elig = term_attendance_pct_and_eligibility(
                    att_sum, ATTENDANCE_TERM_CLASS_COUNT
                )
                row["attendance_pct"] = pct
                row["eligibility"] = elig
                row["attended_sessions_total"] = int(att_sum)
                if row["mark_id"]:
                    # Fetch cycle test questions
                    ct_questions = conn.execute(
                        text(
                            """
                            SELECT test_number, question_number, marks_obtained, max_marks
                            FROM cycle_test_questions
                            WHERE mark_id = :mid
                            ORDER BY test_number, question_number
                            """
                        ),
                        {"mid": row["mark_id"]}
                    ).mappings().all()
                    
                    ct1_qs = {}
                    ct2_qs = {}
                    for q in ct_questions:
                        if q["test_number"] == 1:
                            ct1_qs[q["question_number"]] = q["marks_obtained"]
                        else:
                            ct2_qs[q["question_number"]] = q["marks_obtained"]
                    
                    row["ct1_questions"] = ct1_qs
                    row["ct2_questions"] = ct2_qs
                    
                    # Fetch project components
                    components = conn.execute(
                        text(
                            """
                            SELECT component_name, marks_obtained, max_marks
                            FROM project_components
                            WHERE mark_id = :mid
                            """
                        ),
                        {"mid": row["mark_id"]}
                    ).mappings().all()
                    row["project_components"] = components
                else:
                    row["ct1_questions"] = {}
                    row["ct2_questions"] = {}
                    row["project_components"] = []

        # Single-student chart data (term-based %, same rule as daily attendance page)
        subject_labels = [r["subject_code"] for r in rows]
        attendance_values = [float(r["attendance_pct"] or 0) for r in rows]
        attended_classes = sum(int(r.get("attended_sessions_total") or 0) for r in rows)
        total_classes = len(rows) * ATTENDANCE_TERM_CLASS_COUNT
        absent_classes = max(total_classes - attended_classes, 0)

        import json

        return render_template(
            "my_performance.html",
            records=rows,
            chart_labels=json.dumps(subject_labels),
            chart_attendance=json.dumps(attendance_values),
            total_classes=total_classes,
            attended_classes=attended_classes,
            absent_classes=absent_classes,
        )

    @app.route("/me/download")
    def my_performance_download():
        if not require_role("STUDENT"):
            flash("Student login required to download your performance.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        student_id = user.get("student_id")
        if not student_id:
            flash("No student record is linked to this account.", "danger")
            return redirect(url_for("my_performance"))

        engine = app.config["DB_ENGINE"]
        with engine.begin() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT e.enroll_id,
                           m.mark_id,
                           sub.subject_code,
                           sub.subject_name,
                           m.cycle_test_1,
                           m.cycle_test_2,
                           m.project_marks,
                           m.assignment_marks,
                           m.internal_total,
                           a.attendance_pct,
                           a.attended_classes,
                           a.total_classes,
                           a.eligibility
                    FROM enrollments e
                    JOIN subjects sub ON sub.subject_id = e.subject_id
                    LEFT JOIN (
                        SELECT m1.*
                        FROM marks m1
                        JOIN (
                            SELECT enroll_id, MAX(mark_id) AS latest_mark_id
                            FROM marks
                            GROUP BY enroll_id
                        ) t ON t.enroll_id = m1.enroll_id AND t.latest_mark_id = m1.mark_id
                    ) m ON m.enroll_id = e.enroll_id
                    LEFT JOIN (
                        SELECT a1.*
                        FROM attendance a1
                        JOIN (
                            SELECT enroll_id, MAX(attendance_id) AS latest_attendance_id
                            FROM attendance
                            GROUP BY enroll_id
                        ) t ON t.enroll_id = a1.enroll_id AND t.latest_attendance_id = a1.attendance_id
                    ) a ON a.enroll_id = e.enroll_id
                    WHERE e.student_id = :sid
                    ORDER BY sub.subject_code
                    """,
                ),
                {"sid": student_id},
            ).mappings().all()

            attended_by_enroll = {
                r["enroll_id"]: float(r["attended_sum"] or 0)
                for r in conn.execute(
                    text(
                        """
                        SELECT e.enroll_id,
                               COALESCE(SUM(a.attended_classes), 0) AS attended_sum
                        FROM enrollments e
                        LEFT JOIN attendance a ON a.enroll_id = e.enroll_id
                        WHERE e.student_id = :sid
                        GROUP BY e.enroll_id
                        """
                    ),
                    {"sid": student_id},
                ).mappings().all()
            }

            mark_ids = [int(r["mark_id"]) for r in rows if r["mark_id"] is not None]
            ct1_questions_by_mark = defaultdict(lambda: {q: None for q in range(1, 6)})
            ct2_questions_by_mark = defaultdict(lambda: {q: None for q in range(1, 6)})
            project_components_by_mark = defaultdict(lambda: {"Implementation": None, "Research Paper": None, "Final Review": None})

            if mark_ids:
                id_list = ",".join(str(mid) for mid in mark_ids)
                ct_rows = conn.execute(
                    text(
                        f"""
                        SELECT mark_id, test_number, question_number, marks_obtained
                        FROM cycle_test_questions
                        WHERE mark_id IN ({id_list})
                        ORDER BY mark_id, test_number, question_number
                        """
                    )
                ).mappings().all()
                for q in ct_rows:
                    if q["test_number"] == 1:
                        ct1_questions_by_mark[q["mark_id"]][q["question_number"]] = q["marks_obtained"]
                    else:
                        ct2_questions_by_mark[q["mark_id"]][q["question_number"]] = q["marks_obtained"]

                project_rows = conn.execute(
                    text(
                        f"""
                        SELECT mark_id, component_name, marks_obtained
                        FROM project_components
                        WHERE mark_id IN ({id_list})
                        ORDER BY mark_id, component_id
                        """
                    )
                ).mappings().all()
                for c in project_rows:
                    project_components_by_mark[c["mark_id"]][c["component_name"]] = c["marks_obtained"]

        rows_export = []
        for r in rows:
            mark_id = r["mark_id"]
            ct1 = ct1_questions_by_mark.get(mark_id, {q: None for q in range(1, 6)})
            ct2 = ct2_questions_by_mark.get(mark_id, {q: None for q in range(1, 6)})
            pc = project_components_by_mark.get(mark_id, {"Implementation": None, "Research Paper": None, "Final Review": None})
            att_sum = attended_by_enroll.get(r["enroll_id"], 0.0)
            pct, elig = term_attendance_pct_and_eligibility(att_sum, ATTENDANCE_TERM_CLASS_COUNT)
            rows_export.append(
                {
                    "Subject Code": r["subject_code"],
                    "Subject Name": r["subject_name"],
                    "CT1-Q1": ct1.get(1),
                    "CT1-Q2": ct1.get(2),
                    "CT1-Q3": ct1.get(3),
                    "CT1-Q4": ct1.get(4),
                    "CT1-Q5": ct1.get(5),
                    "CT1 Total": r["cycle_test_1"],
                    "CT2-Q1": ct2.get(1),
                    "CT2-Q2": ct2.get(2),
                    "CT2-Q3": ct2.get(3),
                    "CT2-Q4": ct2.get(4),
                    "CT2-Q5": ct2.get(5),
                    "CT2 Total": r["cycle_test_2"],
                    "Project Implementation": pc.get("Implementation"),
                    "Project Research Paper": pc.get("Research Paper"),
                    "Project Final Review": pc.get("Final Review"),
                    "Project Total": r["project_marks"],
                    "Assignment": r["assignment_marks"],
                    "Internal Total": r["internal_total"],
                    "Attendance %": pct,
                    "Attended Sessions": int(att_sum),
                    "Term Total": ATTENDANCE_TERM_CLASS_COUNT,
                    "Eligibility": elig,
                }
            )

        fieldnames = [
            "Subject Code",
            "Subject Name",
            "CT1-Q1",
            "CT1-Q2",
            "CT1-Q3",
            "CT1-Q4",
            "CT1-Q5",
            "CT1 Total",
            "CT2-Q1",
            "CT2-Q2",
            "CT2-Q3",
            "CT2-Q4",
            "CT2-Q5",
            "CT2 Total",
            "Project Implementation",
            "Project Research Paper",
            "Project Final Review",
            "Project Total",
            "Assignment",
            "Internal Total",
            "Attendance %",
            "Attended Sessions",
            "Term Total",
            "Eligibility",
        ]
        return make_csv_response("my_performance.csv", fieldnames, rows_export)

    @app.route("/my/attendance")
    def my_daily_attendance():
        """Students view their daily attendance records for each subject"""
        if not require_role("STUDENT"):
            flash("Student login required to view attendance.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        engine = app.config["DB_ENGINE"]
        student_id = user.get("student_id")

        if not student_id:
            with engine.begin() as conn:
                fallback = conn.execute(
                    text(
                        "SELECT student_id FROM students WHERE reg_no = :reg_no OR name = :name LIMIT 1"
                    ),
                    {"reg_no": user.get("username"), "name": user.get("username")},
                ).mappings().first()

                if fallback:
                    student_id = fallback["student_id"]
                    session_user = session.get("user", {})
                    session_user["student_id"] = student_id
                    session["user"] = session_user
                else:
                    flash("No student record is linked to this account.", "danger")
                    return redirect(url_for("index"))

        attendance_data = {}

        with engine.begin() as conn:
            # Fetch all daily attendance records for this student
            records = conn.execute(
                text(
                    """
                    SELECT 
                        e.enroll_id,
                        sub.subject_code,
                        sub.subject_name,
                        a.attendance_date,
                        a.attended_classes,
                        a.total_classes
                    FROM enrollments e
                    JOIN subjects sub ON sub.subject_id = e.subject_id
                    LEFT JOIN attendance a ON a.enroll_id = e.enroll_id
                    WHERE e.student_id = :sid
                    ORDER BY sub.subject_code, a.attendance_date DESC
                    """
                ),
                {"sid": student_id},
            ).mappings().all()

            # Group by subject
            for record in records:
                subject_key = f"{record['subject_code']} - {record['subject_name']}"
                
                if subject_key not in attendance_data:
                    attendance_data[subject_key] = {
                        "subject_code": record["subject_code"],
                        "subject_name": record["subject_name"],
                        "enroll_id": record["enroll_id"],
                        "daily_records": []
                    }
                
                if record["attendance_date"]:
                    attended = int(record["attended_classes"] or 0)
                    total = int(record["total_classes"] or 0)
                    if total <= 0:
                        total = 1
                    attendance_data[subject_key]["daily_records"].append({
                        "date": record["attendance_date"],
                        "present": attended,
                        "total": total,
                        "status": "Present" if attended >= 1 else "Absent",
                    })

            # Sum all daily (and legacy) attendance rows per enrollment; % = attended / term total (e.g. 65)
            attended_by_enroll = {
                r["enroll_id"]: float(r["attended_sum"] or 0)
                for r in conn.execute(
                    text(
                        """
                        SELECT e.enroll_id,
                               COALESCE(SUM(a.attended_classes), 0) AS attended_sum
                        FROM enrollments e
                        LEFT JOIN attendance a ON a.enroll_id = e.enroll_id
                        WHERE e.student_id = :sid
                        GROUP BY e.enroll_id
                        """
                    ),
                    {"sid": student_id},
                ).mappings().all()
            }
            for subj in attendance_data.values():
                eid = subj.get("enroll_id")
                att_sum = attended_by_enroll.get(eid, 0.0) if eid is not None else 0.0
                pct, elig = term_attendance_pct_and_eligibility(
                    att_sum, ATTENDANCE_TERM_CLASS_COUNT
                )
                subj["record_attendance_pct"] = pct
                subj["eligibility"] = elig
                subj["attended_sessions_total"] = int(att_sum)

        def finalize_daily_attendance(data):
            """Build course summary and monthly breakdown from daily attendance rows."""
            daily = data.get("daily_records") or []
            if not daily:
                data["summary"] = {
                    "sessions_marked": 0,
                    "present_sessions": 0,
                    "absent_marked": 0,
                    "term_total": ATTENDANCE_TERM_CLASS_COUNT,
                    "term_pct": None,
                }
                data["monthly_rows"] = []
                return
            daily.sort(key=lambda r: r["date"])
            cum_att = 0
            cum_tot = 0
            by_month = defaultdict(lambda: {"present": 0, "absent": 0})
            for r in daily:
                att = int(r.get("present") or 0)
                tot = int(r.get("total") or 0)
                if tot <= 0:
                    tot = 1
                cum_att += att
                cum_tot += tot
                d = r["date"]
                if isinstance(d, date):
                    by_month[(d.year, d.month)]["present"] += att
                    by_month[(d.year, d.month)]["absent"] += tot - att
            term_total = ATTENDANCE_TERM_CLASS_COUNT
            # Prefer DB aggregate (same as eligibility card) if already set on this subject
            att_for_term = int(data.get("attended_sessions_total", cum_att))
            term_pct = (
                min(100.0, round((att_for_term * 100.0) / term_total, 2))
                if term_total > 0
                else 0.0
            )
            data["summary"] = {
                "sessions_marked": cum_tot,
                "present_sessions": att_for_term,
                "absent_marked": max(0, cum_tot - att_for_term),
                "term_total": term_total,
                "term_pct": term_pct,
            }
            data["monthly_rows"] = []
            for ym in sorted(by_month.keys()):
                y, m = ym
                label = date(y, m, 1).strftime("%b").upper() + f" / {y}"
                pr = by_month[ym]["present"]
                ab = by_month[ym]["absent"]
                data["monthly_rows"].append(
                    {"label": label, "present": pr, "absent": ab}
                )

        for _key, subj in attendance_data.items():
            finalize_daily_attendance(subj)

        return render_template(
            "my_daily_attendance.html",
            attendance_data=attendance_data,
            term_class_total=ATTENDANCE_TERM_CLASS_COUNT,
            eligibility_threshold_pct=ATTENDANCE_ELIGIBILITY_PCT,
        )

    @app.route("/my/attendance/download")
    def my_daily_attendance_download():
        if not require_role("STUDENT"):
            flash("Student login required to download attendance.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        student_id = user.get("student_id")
        if not student_id:
            flash("No student record is linked to this account.", "danger")
            return redirect(url_for("my_daily_attendance"))

        engine = app.config["DB_ENGINE"]
        rows_export = []
        with engine.begin() as conn:
            records = conn.execute(
                text(
                    """
                    SELECT e.enroll_id,
                           sub.subject_code,
                           sub.subject_name,
                           a.attendance_date,
                           a.attended_classes,
                           a.total_classes
                    FROM enrollments e
                    JOIN subjects sub ON sub.subject_id = e.subject_id
                    LEFT JOIN attendance a ON a.enroll_id = e.enroll_id
                    WHERE e.student_id = :sid
                    ORDER BY sub.subject_code, a.attendance_date DESC
                    """
                ),
                {"sid": student_id},
            ).mappings().all()

            for record in records:
                total = int(record["total_classes"] or 0)
                present = int(record["attended_classes"] or 0)
                status = "Present" if present >= 1 else "Absent"
                rows_export.append(
                    {
                        "Subject Code": record["subject_code"],
                        "Subject Name": record["subject_name"],
                        "Date": record["attendance_date"],
                        "Present": present,
                        "Total Classes": total,
                        "Status": status,
                    }
                )

        fieldnames = [
            "Subject Code",
            "Subject Name",
            "Date",
            "Present",
            "Total Classes",
            "Status",
        ]
        return make_csv_response("my_daily_attendance.csv", fieldnames, rows_export)

    @app.route("/feedback", methods=["GET", "POST"])
    def feedback():
        if not require_role("STUDENT"):
            flash("Student login required to submit feedback.", "danger")
            return redirect(url_for("login"))

        user = get_current_user()
        engine = app.config["DB_ENGINE"]
        student_id = user.get("student_id")

        if not student_id:
            flash("Student account not linked.", "danger")
            return redirect(url_for("index"))

        if request.method == "POST":
            enroll_id = request.form.get("enroll_id")
            teaching_quality = request.form.get("teaching_quality")
            subject_knowledge = request.form.get("subject_knowledge")
            communication = request.form.get("communication")
            preparation = request.form.get("preparation")
            responsiveness = request.form.get("responsiveness")
            punctuality = request.form.get("punctuality")
            overall_rating = request.form.get("overall_rating")
            comments = request.form.get("comments", "").strip()
            selected_faculty_id = request.form.get("faculty_id")

            if not enroll_id or not all([teaching_quality, subject_knowledge, communication, preparation, responsiveness, punctuality, overall_rating]):
                flash("All rating fields are required.", "danger")
                return redirect(url_for("feedback", faculty_id=selected_faculty_id))

            try:
                with engine.begin() as conn:
                    enroll_check = conn.execute(
                        text("SELECT e.enroll_id, e.faculty_id, e.subject_id FROM enrollments e WHERE e.enroll_id = :eid AND e.student_id = :sid"),
                        {"eid": enroll_id, "sid": student_id}
                    ).first()

                    if not enroll_check:
                        flash("Invalid enrollment.", "danger")
                        return redirect(url_for("feedback"))

                    conn.execute(
                        text("""
                            INSERT INTO feedback (enroll_id, student_id, faculty_id, subject_id, teaching_quality, subject_knowledge, communication, preparation, responsiveness, punctuality, overall_rating, comments)
                            VALUES (:enroll_id, :student_id, :faculty_id, :subject_id, :teaching_quality, :subject_knowledge, :communication, :preparation, :responsiveness, :punctuality, :overall_rating, :comments)
                            ON DUPLICATE KEY UPDATE
                                teaching_quality = VALUES(teaching_quality),
                                subject_knowledge = VALUES(subject_knowledge),
                                communication = VALUES(communication),
                                preparation = VALUES(preparation),
                                responsiveness = VALUES(responsiveness),
                                punctuality = VALUES(punctuality),
                                overall_rating = VALUES(overall_rating),
                                comments = VALUES(comments),
                                submitted_at = CURRENT_TIMESTAMP
                        """),
                        {
                            "enroll_id": enroll_id,
                            "student_id": student_id,
                            "faculty_id": enroll_check.faculty_id,
                            "subject_id": enroll_check.subject_id,
                            "teaching_quality": teaching_quality,
                            "subject_knowledge": subject_knowledge,
                            "communication": communication,
                            "preparation": preparation,
                            "responsiveness": responsiveness,
                            "punctuality": punctuality,
                            "overall_rating": overall_rating,
                            "comments": comments
                        }
                    )

                flash("Feedback submitted successfully!", "success")
                return redirect(url_for("feedback", faculty_id=selected_faculty_id))

            except SQLAlchemyError as e:
                flash(f"Error submitting feedback: {str(e)}", "danger")
                return redirect(url_for("feedback", faculty_id=selected_faculty_id))

        selected_faculty_id = request.args.get("faculty_id")
        selected_enroll_id = request.args.get("enroll_id")

        with engine.begin() as conn:
            rows = conn.execute(
                text("""
                    SELECT e.enroll_id,
                           e.faculty_id,
                           f.name AS faculty_name,
                           f.emp_no,
                           s.subject_id,
                           s.subject_code,
                           s.subject_name
                    FROM enrollments e
                    JOIN subjects s ON s.subject_id = e.subject_id
                    JOIN faculty f ON f.faculty_id = e.faculty_id
                    WHERE e.student_id = :sid
                    ORDER BY f.name, s.subject_code
                """),
                {"sid": student_id}
            ).mappings().all()

            faculty_map = {}
            for row in rows:
                fid = row["faculty_id"]
                if fid not in faculty_map:
                    faculty_map[fid] = {
                        "faculty_id": fid,
                        "faculty_name": row["faculty_name"],
                        "emp_no": row["emp_no"],
                        "assignments": [],
                    }
                faculty_map[fid]["assignments"].append(
                    {
                        "enroll_id": row["enroll_id"],
                        "subject_id": row["subject_id"],
                        "subject_code": row["subject_code"],
                        "subject_name": row["subject_name"],
                    }
                )

            faculty_options = list(faculty_map.values())
            selected_faculty = None
            if selected_faculty_id:
                try:
                    selected_faculty_id = int(selected_faculty_id)
                    selected_faculty = faculty_map.get(selected_faculty_id)
                except (TypeError, ValueError):
                    selected_faculty = None

            if not selected_faculty and faculty_options:
                selected_faculty = faculty_options[0]

            selected_assignment = None
            if selected_faculty:
                if selected_enroll_id:
                    try:
                        selected_enroll_id = int(selected_enroll_id)
                    except (TypeError, ValueError):
                        selected_enroll_id = None
                if selected_enroll_id:
                    selected_assignment = next(
                        (item for item in selected_faculty["assignments"] if item["enroll_id"] == selected_enroll_id),
                        None,
                    )
                if not selected_assignment and selected_faculty["assignments"]:
                    selected_assignment = selected_faculty["assignments"][0]
                    selected_enroll_id = selected_assignment["enroll_id"]

            feedback_data = {}
            for row in rows:
                feedback_row = conn.execute(
                    text("SELECT * FROM feedback WHERE enroll_id = :eid"),
                    {"eid": row["enroll_id"]}
                ).mappings().first()
                feedback_data[row["enroll_id"]] = feedback_row

        return render_template(
            "feedback.html",
            faculty_options=faculty_options,
            selected_faculty=selected_faculty,
            selected_assignment=selected_assignment,
            selected_faculty_id=selected_faculty["faculty_id"] if selected_faculty else None,
            selected_enroll_id=selected_enroll_id,
            feedback_data=feedback_data,
        )

    # Custom Jinja filter to convert 24-hour time to 12-hour IST format
    def convert_to_ist(time_str):
        """Convert 24-hour format (HH:MM) to 12-hour IST format (H:MM AM/PM)"""
        if not time_str:
            return time_str
        try:
            hours, minutes = map(int, time_str.split(':'))
            period = 'AM' if hours < 12 else 'PM'
            display_hours = hours if hours <= 12 else hours - 12
            if display_hours == 0:
                display_hours = 12
            return f"{display_hours}:{minutes:02d} {period}"
        except:
            return time_str

    app.jinja_env.filters['convert_to_ist'] = convert_to_ist

    return app


if __name__ == "__main__":
    flask_app = create_app()
    flask_app.run(debug=True)

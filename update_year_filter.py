from pathlib import Path
import re

path = Path('app.py')
text = path.read_text(encoding='utf-8')

marks_start = text.find('@app.route("/marks/new")')
if marks_start == -1:
    raise SystemExit('marks route not found')

# Expand variable block
pattern_vars = re.compile(r"subjects_for_faculty = \[\]\n\s*sections_for_subject = \[\]\n\s*departments_for_subject = \[\]\n\s*selected_subject_id = None\n\s*selected_section = \"\"\n\s*selected_department = \"\"", re.S)
text, count = pattern_vars.subn(
    "subjects_for_faculty = []\n        sections_for_subject = []\n        departments_for_subject = []\n        years_for_subject = []\n        selected_subject_id = None\n        selected_year = None\n        selected_section = \"\"\n        selected_department = \"\"",
    text,
    count=1,
)
if count == 0:
    raise SystemExit('marks vars block replacement failed')

# Insert year parse after raw_department_str = raw_department in marks route
pattern_year = re.compile(r"raw_department_str = raw_department\n\n\s*with engine\.begin\(\) as conn:", re.S)
text, count = pattern_year.subn(
    "raw_department_str = raw_department\n\n        raw_year = request.args.get(\"year\") if request.method == \"GET\" else request.form.get(\"year\")\n        if raw_year is None or raw_year == \"\":\n            raw_year_int = None\n        else:\n            try:\n                raw_year_int = int(raw_year)\n            except ValueError:\n                raw_year_int = None\n\n        with engine.begin() as conn:",
    text,
    count=1,
)
if count == 0:
    raise SystemExit('marks year parse insertion failed')

# Replace student section block in marks with year selection logic
marks_slice = text[marks_start:]
pattern_block = re.compile(r"if selected_subject_id is not None:.*?# Enrollment list is constrained to faculty \+ selected subject \+ selected section \+ selected department\.\n", re.S)
mb = pattern_block.search(marks_slice)
if not mb:
    raise SystemExit('marks block not found')
old_block = mb.group(0)

new_block = """if selected_subject_id is not None:
                    years_for_subject = conn.execute(
                        text(
                            '''
                            SELECT DISTINCT s.year_level AS year
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                            ORDER BY s.year_level
                            '''
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
                            '''
                            SELECT DISTINCT s.department AS department
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                              AND s.year_level = :year
                            ORDER BY s.department
                            '''
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
                            '''
                            SELECT DISTINCT COALESCE(s.section,'') AS section
                            FROM enrollments e
                            JOIN students s ON s.student_id = e.student_id
                            WHERE e.faculty_id = :fid
                              AND e.subject_id = :sid
                              AND s.department = :department
                              AND s.year_level = :year
                            ORDER BY section
                            '''
                        ),
                        {"fid": fid, "sid": selected_subject_id, "department": selected_department, "year": selected_year},
                    ).mappings().all()
                    allowed_sections = {r["section"] for r in sections_for_subject}
"""

text = text[:marks_start + mb.start()] + new_block + text[marks_start + mb.end():]

# Add selected_year check to condition
text = text.replace(
    "if selected_subject_id is None or selected_section == \"\" or selected_department == \"\":",
    "if selected_subject_id is None or selected_year is None or selected_section == \"\" or selected_department == \"\":",
    1,
)

# Add year filter to enrollments query and params
text = text.replace(
    "AND COALESCE(s.section,'') = :section\n                              AND s.department = :department",
    "AND COALESCE(s.section,'') = :section\n                              AND s.department = :department\n                              AND s.year_level = :year",
    1,
)
text = text.replace(
    "{\n                            \"fid\": fid,\n                            \"sid\": selected_subject_id,\n                            \"section\": selected_section,\n                            \"department\": selected_department,\n                        }",
    "{\n                            \"fid\": fid,\n                            \"sid\": selected_subject_id,\n                            \"section\": selected_section,\n                            \"department\": selected_department,\n                            \"year\": selected_year,\n                        }",
    1,
)

# Attendance entry changes similarly can be added after verifying marks works.

path.write_text(text, encoding='utf-8')
print('marks updates applied')

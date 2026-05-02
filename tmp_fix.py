from pathlib import Path
import re

path = Path(r'c:\Users\hp\OneDrive\ドキュメント\project db\app.py')
text = path.read_text(encoding='utf-8')

old = '''                    if updated == 0:
                        # Insert new row
                        result = conn.execute(
                            text(
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
                            ),
                            data,
                        )'''
new = '''                    if updated == 0:
                        # Insert new row
                        result = conn.execute(
                            text(
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
                            ),
                            data,
                        )'''
text = text.replace(old, new)

old2 = '''                    # Get student_id from enroll_id
                    enroll_data = conn.execute(
                        text("SELECT student_id FROM enrollments WHERE enroll_id = :eid"),
                        {"eid": int(enroll_id)}
                    ).mappings().first()
                    
                    if not enroll_data:
                        raise ValueError("Invalid enrollment")
                    
                    student_id = enroll_data["student_id"]
                    data["student_id"] = student_id
                    
                    # Check if marks exist and if faculty can edit
                    if is_faculty:'''
new2 = '''                    # Check if marks exist and if faculty can edit
                    if is_faculty:'''
text = text.replace(old2, new2)

path.write_text(text, encoding='utf-8')
print('done')

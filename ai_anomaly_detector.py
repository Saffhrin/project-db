import os

import pandas as pd
from sqlalchemy import create_engine, text


DB_URL = os.getenv(
    "ACADEMIC_DB_URL",
    "mysql+mysqlconnector://root:Amit948@localhost/academic_integrity",
)


def run_detection() -> None:
    engine = create_engine(DB_URL, future=True)
    anomalies = []

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS student_risk_scores (
                    enroll_id INT PRIMARY KEY,
                    risk_score DECIMAL(5,2),
                    marks_contribution DECIMAL(5,2),
                    attendance_contribution DECIMAL(5,2),
                    predicted_outcome VARCHAR(20),
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (enroll_id) REFERENCES enrollments(enroll_id)
                )
                """
            )
        )

    # MARKS-based anomalies (low and high outliers by z-score)
    marks_query = """
        SELECT m.mark_id,
               m.enroll_id,
               m.internal_total,
               e.subject_id,
               e.semester
        FROM marks m
        JOIN enrollments e ON e.enroll_id = m.enroll_id
        JOIN (
            SELECT enroll_id, MAX(mark_id) AS latest_mark_id
            FROM marks
            GROUP BY enroll_id
        ) lm ON lm.enroll_id = m.enroll_id AND lm.latest_mark_id = m.mark_id
    """

    with engine.begin() as conn:
        marks_df = pd.read_sql(marks_query, conn)

        if not marks_df.empty:
            for (subject_id, semester), group in marks_df.groupby(["subject_id", "semester"]):
                mean = group["internal_total"].mean()
                std = group["internal_total"].std(ddof=0)
                if std == 0 or pd.isna(std):
                    std = 1.0

                z_scores = (group["internal_total"] - mean) / std

                low_abnormal = group[(z_scores < -2.0)]
                high_abnormal = group[(z_scores > 2.0)]

                for idx, row in low_abnormal.iterrows():
                    anomalies.append(
                        {
                            "enroll_id": int(row["enroll_id"]),
                            "category": "MARKS_LOW",
                            "description": f"Internal {row['internal_total']:.1f} significantly below mean {mean:.1f}",
                            "score": float(z_scores.loc[idx]),
                        }
                    )

                for idx, row in high_abnormal.iterrows():
                    anomalies.append(
                        {
                            "enroll_id": int(row["enroll_id"]),
                            "category": "MARKS_HIGH",
                            "description": f"Internal {row['internal_total']:.1f} significantly above mean {mean:.1f}",
                            "score": float(z_scores.loc[idx]),
                        }
                    )

                pass_threshold = 30.0
                for idx, row in group[group["internal_total"] < pass_threshold].iterrows():
                    if idx in low_abnormal.index:
                        continue
                    anomalies.append(
                        {
                            "enroll_id": int(row["enroll_id"]),
                            "category": "MARKS_FAIL",
                            "description": f"Internal {row['internal_total']:.1f} below pass threshold {pass_threshold:.1f}",
                            "score": float(row["internal_total"]),
                        }
                    )

        # ATTENDANCE anomalies (debarred or very low attendance)
        attendance_query = """
            SELECT a.attendance_id,
                   a.enroll_id,
                   a.attendance_pct,
                   a.eligibility
            FROM attendance a
            JOIN (
                SELECT enroll_id, MAX(attendance_id) AS latest_attendance_id
                FROM attendance
                GROUP BY enroll_id
            ) la ON la.enroll_id = a.enroll_id AND la.latest_attendance_id = a.attendance_id
        """

        attendance_df = pd.read_sql(attendance_query, conn)
        attendance_df = attendance_df.copy()  # Ensure it's not a view

        if not attendance_df.empty:
            for _, row in attendance_df.iterrows():
                if row["attendance_pct"] is None:
                    continue

                if row["attendance_pct"] < 75 or str(row["eligibility"]).upper() == "DEBARRED":
                    anomalies.append(
                        {
                            "enroll_id": int(row["enroll_id"]),
                            "category": "ATTENDANCE",
                            "description": f"Attendance {row['attendance_pct']:.1f}% ({row['eligibility']})",
                            "score": float(row["attendance_pct"]),
                        }
                    )

        if not anomalies:
            # Clear legacy AI-marked anomalies when no current findings
            conn.execute(
                text("DELETE FROM anomalies WHERE category IN ('MARKS_LOW','MARKS_HIGH','ATTENDANCE')")
            )
            return

        # Remove stale AI anomalies before inserting current batch
        conn.execute(
            text("DELETE FROM anomalies WHERE category IN ('MARKS_LOW','MARKS_HIGH','ATTENDANCE')")
        )

        anomalies_df = pd.DataFrame(anomalies)
        anomalies_df.to_sql("anomalies", conn, if_exists="append", index=False)
        # PREDICTIVE ANALYTICS: Calculate risk scores for each enrollment
        risk_scores = []

        # Get all enrollments with latest marks and attendance
        risk_query = """
            SELECT e.enroll_id, e.student_id, e.subject_id, e.semester,
                   COALESCE(m.internal_total, 0) as internal_total,
                   COALESCE(a.attendance_pct, 0) as attendance_pct
            FROM enrollments e
            LEFT JOIN (
                SELECT m1.enroll_id, m1.internal_total
                FROM marks m1
                JOIN (
                    SELECT enroll_id, MAX(mark_id) AS latest_mark_id
                    FROM marks
                    GROUP BY enroll_id
                ) lm ON lm.enroll_id = m1.enroll_id AND lm.latest_mark_id = m1.mark_id
            ) m ON m.enroll_id = e.enroll_id
            LEFT JOIN (
                SELECT a1.enroll_id, a1.attendance_pct
                FROM attendance a1
                JOIN (
                    SELECT enroll_id, MAX(attendance_id) AS latest_attendance_id
                    FROM attendance
                    GROUP BY enroll_id
                ) la ON la.enroll_id = a1.enroll_id AND la.latest_attendance_id = a1.attendance_id
            ) a ON a.enroll_id = e.enroll_id
        """

        risk_df = pd.read_sql(risk_query, conn)

        if not risk_df.empty:
            # Calculate risk scores based on marks and attendance
            for _, row in risk_df.iterrows():
                marks_score = max(0, (30 - row["internal_total"]) / 30) * 100  # Higher risk if marks below 30
                attendance_score = max(0, (75 - row["attendance_pct"]) / 75) * 100  # Higher risk if attendance below 75

                total_risk = (marks_score * 0.7) + (attendance_score * 0.3)  # Weighted average

                # Predict outcome based on risk
                if total_risk > 70:
                    predicted_outcome = "HIGH_RISK"
                elif total_risk > 40:
                    predicted_outcome = "MEDIUM_RISK"
                else:
                    predicted_outcome = "LOW_RISK"

                risk_scores.append({
                    "enroll_id": int(row["enroll_id"]),
                    "risk_score": float(total_risk),
                    "marks_contribution": float(marks_score),
                    "attendance_contribution": float(attendance_score),
                    "predicted_outcome": predicted_outcome
                })

        if risk_scores:
            # Clear old risk scores and insert new ones
            conn.execute(text("DELETE FROM student_risk_scores"))
            risk_df = pd.DataFrame(risk_scores)
            risk_df.to_sql("student_risk_scores", conn, if_exists="append", index=False)

if __name__ == "__main__":
    run_detection()


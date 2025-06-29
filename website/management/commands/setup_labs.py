from django.core.management.base import BaseCommand
from website.models import Lab, Lesson, Question
from django.utils import timezone

class Command(BaseCommand):
    help = 'Sets up security labs with lessons and sample data'

    def handle(self, *args, **kwargs):
        self.stdout.write('Creating security labs...')
        
        # Create SQL Injection Lab
        sql_lab = Lab.objects.create(
            title="SQL Injection Fundamentals",
            description="Learn about SQL injection vulnerabilities and how to exploit them safely in a controlled environment.",
            order=1,
            created_at=timezone.now(),
            updated_at=timezone.now()
        )
        
        # SQL Injection Lessons
        sql_lessons = [
            {
                "title": "Introduction to SQL Injection",
                "content_type": "THEORY",
                "description": "Understanding what SQL injection is and its impact on security.",
                "content": """
                SQL Injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.
                
                Key Points:
                - What is SQL Injection?
                - How it affects applications
                - Common vulnerable points
                - Impact of successful exploitation
                """,
                "order": 1,
                "duration": 20
            },
            {
                "title": "Types of SQL Injection",
                "content_type": "THEORY",
                "description": "Different types of SQL injection techniques.",
                "content": """
                Learn about various types of SQL injection:
                
                1. In-band SQLi
                   - Error-based
                   - Union-based
                2. Blind SQLi
                   - Boolean-based
                   - Time-based
                3. Out-of-band SQLi
                """,
                "order": 2,
                "duration": 25
            },
            {
                "title": "Basic Login Bypass",
                "content_type": "SIMULATION",
                "description": "Practice bypassing a login form using simple SQL injection.",
                "content": "Try to bypass the login form using SQL injection techniques.",
                "simulation_config": Lesson.get_sql_injection_login_config(),
                "order": 3,
                "duration": 30
            },
            {
                "title": "UNION-Based Attacks",
                "content_type": "THEORY",
                "description": "Understanding and practicing UNION-based SQL injection attacks.",
                "content": """
                UNION-based SQL injection allows an attacker to extract data from different database tables.
                
                Topics covered:
                - UNION operator basics
                - Column matching
                - Data type compatibility
                - Extracting meaningful data
                """,
                "order": 4,
                "duration": 25
            },
            {
                "title": "Data Extraction Challenge",
                "content_type": "SIMULATION",
                "description": "Extract hidden data using UNION-based SQL injection.",
                "content": "Use UNION-based SQL injection to find and extract sensitive data.",
                "simulation_config": {
                    "type": "data_extraction",
                    "scenario": {
                        "title": "Employee Directory",
                        "description": "A vulnerable employee search system"
                    },
                    "database": {
                        "tables": {
                            "employees": {"columns": ["id", "name", "position", "salary"]},
                            "secrets": {"columns": ["id", "key_name", "secret_value"]}
                        },
                        "vulnerable_query": "SELECT name, position FROM employees WHERE name LIKE '%$INPUT%'"
                    },
                    "success_conditions": [
                        {"type": "extract_table", "target": "secrets", "points": 100},
                        {"type": "find_value", "target": "admin_password", "points": 50}
                    ]
                },
                "order": 5,
                "duration": 35
            },
            {
                "title": "Blind SQL Injection",
                "content_type": "THEORY",
                "description": "Understanding and identifying blind SQL injection vulnerabilities.",
                "content": """
                Blind SQL injection occurs when an application is vulnerable to SQL injection but doesn't display database errors.
                
                Learn about:
                - Boolean-based blind SQLi
                - Time-based blind SQLi
                - Data extraction techniques
                """,
                "order": 6,
                "duration": 30
            },
            {
                "title": "Blind SQLi Challenge",
                "content_type": "SIMULATION",
                "description": "Practice extracting data through blind SQL injection.",
                "content": "Extract sensitive information using blind SQL injection techniques.",
                "simulation_config": {
                    "type": "blind_sqli",
                    "scenario": {
                        "title": "Password Reset System",
                        "description": "A vulnerable password reset functionality"
                    },
                    "database": {
                        "target_table": "users",
                        "target_column": "password",
                        "response_type": "boolean"
                    },
                    "success_conditions": [
                        {"type": "extract_password", "target": "admin", "points": 150}
                    ]
                },
                "order": 7,
                "duration": 40
            },
            {
                "title": "Prevention Techniques",
                "content_type": "THEORY",
                "description": "Learn how to prevent SQL injection vulnerabilities.",
                "content": """
                Best practices for preventing SQL injection:
                
                1. Prepared Statements
                2. Input Validation
                3. Stored Procedures
                4. WAF Implementation
                5. Principle of Least Privilege
                """,
                "order": 8,
                "duration": 25
            },
            {
                "title": "Secure Coding Practice",
                "content_type": "PRACTICAL",
                "description": "Practice writing secure SQL queries.",
                "content": "Write secure database queries using prepared statements.",
                "simulation_config": {
                    "type": "coding_exercise",
                    "language": "python",
                    "initial_code": "def get_user(username, password):\n    query = f\"SELECT * FROM users WHERE username='{username}' AND password='{password}'\"\n    return execute_query(query)",
                    "test_cases": [
                        {"input": {"username": "admin", "password": "pass"}, "expected": "safe_query"},
                        {"input": {"username": "admin'--", "password": ""}, "should_fail": True}
                    ]
                },
                "order": 9,
                "duration": 35
            },
            {
                "title": "Final Assessment",
                "content_type": "QUIZ",
                "description": "Test your knowledge of SQL injection.",
                "content": "Final quiz covering all SQL injection concepts.",
                "order": 10,
                "duration": 20
            }
        ]

        # Create SQL Injection Lessons
        for lesson_data in sql_lessons:
            lesson = Lesson.objects.create(
                lab=sql_lab,
                title=lesson_data["title"],
                description=lesson_data["description"],
                content_type=lesson_data["content_type"],
                content=lesson_data["content"],
                order=lesson_data["order"],
                duration=lesson_data["duration"],
                simulation_config=lesson_data.get("simulation_config")
            )
            
            # Add questions for the final quiz
            if lesson_data["content_type"] == "QUIZ":
                questions = [
                    {
                        "question_type": "MCQ",
                        "question_text": "Which of the following is NOT a type of SQL injection?",
                        "options": {
                            "choices": [
                                "Error-based injection",
                                "Time-based blind injection",
                                "Python-based injection",
                                "UNION-based injection"
                            ],
                            "correct_index": 2
                        },
                        "explanation": "Python-based injection is not a type of SQL injection. The others are valid types."
                    },
                    {
                        "question_type": "CODING",
                        "question_text": "Fix the following vulnerable query to prevent SQL injection:",
                        "options": {
                            "initial_code": "SELECT * FROM users WHERE username='$username' AND password='$password'",
                            "test_cases": ["admin'--", "' OR '1'='1"]
                        },
                        "correct_answer": "Using prepared statements: cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', [username, password])",
                        "explanation": "Always use prepared statements or parameterized queries to prevent SQL injection."
                    }
                ]
                
                for q_data in questions:
                    Question.objects.create(
                        lesson=lesson,
                        question_type=q_data["question_type"],
                        question_text=q_data["question_text"],
                        options=q_data["options"],
                        correct_answer=q_data["correct_answer"] if "correct_answer" in q_data else "",
                        explanation=q_data["explanation"],
                        points=10
                    )

        # Create XSS Lab
        xss_lab = Lab.objects.create(
            title="Cross-Site Scripting (XSS) Attacks",
            description="Learn about XSS vulnerabilities and their exploitation techniques.",
            order=2
        )
        
        # Create Command Injection Lab
        cmd_lab = Lab.objects.create(
            title="Command Injection Fundamentals",
            description="Understanding and preventing command injection vulnerabilities.",
            order=3
        )
        
        # Create File Upload Lab
        upload_lab = Lab.objects.create(
            title="File Upload Vulnerabilities",
            description="Learn about secure file upload handling and common vulnerabilities.",
            order=4
        )

        # Add some sample lessons for XSS Lab with simulation
        xss_lessons = [
            {
                "title": "XSS in Comment Systems",
                "content_type": "SIMULATION",
                "description": "Practice XSS attacks in a comment system.",
                "content": "Exploit XSS vulnerabilities in a blog comment system.",
                "simulation_config": Lesson.get_xss_simulation_config(),
                "order": 3,
                "duration": 30
            }
        ]

        for lesson_data in xss_lessons:
            Lesson.objects.create(
                lab=xss_lab,
                title=lesson_data["title"],
                description=lesson_data["description"],
                content_type=lesson_data["content_type"],
                content=lesson_data["content"],
                order=lesson_data["order"],
                duration=lesson_data["duration"],
                simulation_config=lesson_data.get("simulation_config")
            )

        # Add some sample lessons for File Upload Lab with simulation
        upload_lessons = [
            {
                "title": "Exploiting File Upload",
                "content_type": "SIMULATION",
                "description": "Practice exploiting vulnerable file upload systems.",
                "content": "Learn how to bypass file upload restrictions.",
                "simulation_config": Lesson.get_file_upload_simulation_config(),
                "order": 3,
                "duration": 35
            }
        ]

        for lesson_data in upload_lessons:
            Lesson.objects.create(
                lab=upload_lab,
                title=lesson_data["title"],
                description=lesson_data["description"],
                content_type=lesson_data["content_type"],
                content=lesson_data["content"],
                order=lesson_data["order"],
                duration=lesson_data["duration"],
                simulation_config=lesson_data.get("simulation_config")
            )

        self.stdout.write(self.style.SUCCESS('Successfully created security labs with lessons and simulations!')) 
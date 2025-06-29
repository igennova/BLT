from django.core.management.base import BaseCommand
from website.models import Lab, Lesson, Question
from django.utils import timezone

class Command(BaseCommand):
    help = 'Sets up security labs with lessons and sample data'

    def handle(self, *args, **kwargs):
        self.stdout.write('Creating security labs...')
        
        # Create SQL Injection Lab
        sql_lab, created = Lab.objects.get_or_create(
            title="SQL Injection Lab",
            defaults={
                'description': "Learn about SQL injection vulnerabilities and how to exploit them.",
                'order': 1
            }
        )
        self.stdout.write(f'{"Created" if created else "Found"} SQL Injection Lab')

        # Create Theory Lesson
        theory_lesson, created = Lesson.objects.get_or_create(
            lab=sql_lab,
            title="Introduction to SQL Injection",
            defaults={
                'description': "Learn the basics of SQL injection attacks",
                'content': """
# Introduction to SQL Injection

SQL Injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.

## What is SQL Injection?

SQL injection occurs when user input is not properly sanitized and is directly included in SQL queries. This can allow attackers to:

- Bypass authentication
- Access unauthorized data
- Modify or delete data
- Execute administrative operations

## Common SQL Injection Techniques

1. Using quotes to break out of strings
2. Using OR statements to make conditions always true
3. Using comments to ignore rest of the query
4. Using UNION to combine results

## Example Vulnerable Query

```sql
SELECT * FROM users WHERE username='$username' AND password='$password'
```

If user input is not properly sanitized, an attacker can manipulate this query by providing special input.
                """,
                'lesson_type': 'theory',
                'order': 1
            }
        )
        self.stdout.write(f'{"Created" if created else "Found"} Theory Lesson')

        # Create Practice Lesson
        practice_lesson, created = Lesson.objects.get_or_create(
            lab=sql_lab,
            title="Basic Login Bypass",
            defaults={
                'description': "Practice SQL injection on a login form",
                'content': """
# SQL Injection Practice: Login Bypass

In this exercise, you'll practice SQL injection techniques on a login form. The form is vulnerable to SQL injection, allowing you to bypass authentication.

## Your Task

Try to log in without knowing the correct credentials. The login query looks like this:

```sql
SELECT * FROM users WHERE username='$username' AND password='$password'
```

Think about:
- How can you manipulate the query to always return true?
- What happens if you comment out part of the query?
- Can you use the OR operator to your advantage?

Good luck!
                """,
                'lesson_type': 'simulation',
                'simulation_type': 'sql_injection',
                'order': 2
            }
        )
        self.stdout.write(f'{"Created" if created else "Found"} Practice Lesson')

        self.stdout.write(self.style.SUCCESS('Successfully set up SQL Injection lab'))

        # SQL Injection Lessons
        sql_lessons = [
            {
                "title": "Introduction to SQL Injection",
                "content_type": "THEORY",
                "description": "Understanding what SQL injection is and its impact on security.",
                "content": """
                # SQL Injection: A Comprehensive Introduction

                SQL Injection (SQLi) is a critical web security vulnerability that occurs when an attacker can manipulate a web application's database queries by injecting malicious SQL code through user input fields.

                ## Question 1:
                What is the main purpose of SQL injection attacks?

                - Overloading the server
                - Manipulating database queries to gain unauthorized access
                - Creating new user accounts
                - Changing the website's design

                ## How Does it Work?
                Consider this vulnerable query:
                ```sql
                SELECT * FROM users WHERE username = '$user_input' AND password = '$password_input'
                ```
                
                If the application doesn't properly sanitize inputs, an attacker can inject code like:
                ```sql
                admin' OR '1'='1
                ```

                ## Question 2:
                Why does the input "admin' OR '1'='1" work as a SQL injection?

                - It creates a new admin account
                - It makes the WHERE clause always true
                - It deletes the users table
                - It crashes the database server

                ## Impact of SQL Injection
                - Unauthorized data access
                - Data manipulation or deletion
                - Authentication bypass
                - Privilege escalation
                - Remote code execution (in some cases)

                ## Question 3:
                Which of these is NOT a common impact of SQL injection?

                - Data theft
                - Server shutdown
                - Authentication bypass
                - Data manipulation

                ## Common Vulnerable Points
                1. Login forms
                2. Search fields
                3. URL parameters
                4. Hidden form fields
                5. Cookie values

                ## Question 4:
                Which part of a web application is most commonly vulnerable to SQL injection?

                - Image uploads
                - Login forms
                - CSS files
                - Font files

                ## Prevention Methods
                1. Use Prepared Statements
                2. Input Validation
                3. Stored Procedures
                4. WAF Implementation
                5. Principle of Least Privilege

                ## Question 5:
                What is the best way to prevent SQL injection?

                - Remove all user input fields
                - Use prepared statements and parameterized queries
                - Disable the database
                - Hide the login form
                """,
                "order": 1,
                "duration": 20,
                "questions": [
                    {
                        "id": "q1",
                        "type": "MCQ",
                        "question": "What is the main purpose of SQL injection attacks?",
                        "options": [
                            "Overloading the server",
                            "Manipulating database queries to gain unauthorized access",
                            "Creating new user accounts",
                            "Changing the website's design"
                        ],
                        "correct_index": 1,
                        "explanation": "SQL injection is primarily used to manipulate database queries, allowing attackers to gain unauthorized access to data or bypass authentication.",
                        "points": 20
                    },
                    {
                        "id": "q2",
                        "type": "MCQ",
                        "question": "Why does the input \"admin' OR '1'='1\" work as a SQL injection?",
                        "options": [
                            "It creates a new admin account",
                            "It makes the WHERE clause always true",
                            "It deletes the users table",
                            "It crashes the database server"
                        ],
                        "correct_index": 1,
                        "explanation": "This injection works by making the WHERE clause always true with '1'='1', effectively bypassing the password check.",
                        "points": 20
                    },
                    {
                        "id": "q3",
                        "type": "MCQ",
                        "question": "Which of these is NOT a common impact of SQL injection?",
                        "options": [
                            "Data theft",
                            "Server shutdown",
                            "Authentication bypass",
                            "Data manipulation"
                        ],
                        "correct_index": 1,
                        "explanation": "While SQL injection can be serious, it typically doesn't directly cause server shutdowns. The other options are common impacts.",
                        "points": 20
                    },
                    {
                        "id": "q4",
                        "type": "MCQ",
                        "question": "Which part of a web application is most commonly vulnerable to SQL injection?",
                        "options": [
                            "Image uploads",
                            "Login forms",
                            "CSS files",
                            "Font files"
                        ],
                        "correct_index": 1,
                        "explanation": "Login forms are most commonly vulnerable because they directly interact with the database and handle user input.",
                        "points": 20
                    },
                    {
                        "id": "q5",
                        "type": "MCQ",
                        "question": "What is the best way to prevent SQL injection?",
                        "options": [
                            "Remove all user input fields",
                            "Use prepared statements and parameterized queries",
                            "Disable the database",
                            "Hide the login form"
                        ],
                        "correct_index": 1,
                        "explanation": "Prepared statements and parameterized queries are the most effective way to prevent SQL injection by properly handling user input.",
                        "points": 20
                    }
                ]
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
                duration=lesson_data["duration"]
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
                duration=lesson_data["duration"]
            )

        # Add some sample lessons for File Upload Lab with simulation
        upload_lessons = [
            {
                "title": "Exploiting File Upload",
                "content_type": "SIMULATION",
                "description": "Practice exploiting vulnerable file upload systems.",
                "content": "Learn how to bypass file upload restrictions.",
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
                duration=lesson_data["duration"]
            )

        self.stdout.write(self.style.SUCCESS('Successfully created security labs with lessons and simulations!')) 
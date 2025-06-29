from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils import timezone
from website.models import Lab, Lesson, UserProgress
from django.views.decorators.http import require_POST
import json

@login_required
def lab_list(request):
    """Display list of all available labs"""
    labs = Lab.objects.all().order_by('order')
    
    # Calculate completion for each lab
    for lab in labs:
        total_lessons = lab.lessons.count()
        completed_lessons = UserProgress.objects.filter(
            user=request.user,
            lesson__lab=lab,
            completed=True
        ).count()
        lab.completion = (completed_lessons / total_lessons * 100) if total_lessons > 0 else 0
    
    return render(request, 'labs/lab_list.html', {
        'labs': labs
    })

@login_required
def lab_detail(request, lab_id):
    """Display details of a specific lab and its lessons"""
    lab = get_object_or_404(Lab, id=lab_id)
    lessons = lab.lessons.all().order_by('order')
    
    # Get progress for each lesson
    for lesson in lessons:
        lesson.progress, _ = UserProgress.objects.get_or_create(
            user=request.user,
            lesson=lesson
        )
    
    return render(request, 'labs/lab_detail.html', {
        'lab': lab,
        'lessons': lessons
    })

@login_required
def lesson_detail(request, lesson_id):
    """Display and handle a specific lesson"""
    lesson = get_object_or_404(Lesson, id=lesson_id)
    progress, _ = UserProgress.objects.get_or_create(user=request.user, lesson=lesson)

    if request.method == 'POST' and lesson.lesson_type == 'simulation':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        
        # Check for SQL injection patterns
        sql_injection_patterns = [
            "'='", 
            "' OR '1'='1", 
            "' OR 1=1--",
            "' OR '1'='1'--",
            "admin'--"
        ]
        
        success = False
        for pattern in sql_injection_patterns:
            if pattern.lower() in username.lower() or pattern.lower() in password.lower():
                success = True
                break
        
        if success:
            progress.completed = True
            progress.points_earned = 100
            progress.save()
            return render(request, 'labs/sql_injection.html', {
                'lesson': lesson,
                'progress': progress,
                'success_message': 'Congratulations! You successfully exploited the SQL injection vulnerability!'
            })
        else:
            return render(request, 'labs/sql_injection.html', {
                'lesson': lesson,
                'progress': progress,
                'error_message': 'Login failed. Try using SQL injection techniques!'
            })

    # Choose template based on lesson type and simulation type
    if lesson.lesson_type == 'theory':
        template_name = 'labs/theory_lesson.html'
    elif lesson.lesson_type == 'simulation':
        if lesson.simulation_type == 'sql_injection':
            template_name = 'labs/sql_injection.html'
        else:
            template_name = 'labs/theory_lesson.html'  # fallback
    else:
        template_name = 'labs/theory_lesson.html'  # fallback

    return render(request, template_name, {
        'lesson': lesson,
        'progress': progress
    })

@login_required
def simulation_handler(request, lab_id, lesson_id):
    """Handle simulation interactions and track progress"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)
    
    lesson = get_object_or_404(Lesson, id=lesson_id, lab_id=lab_id)
    if not lesson.simulation_config:
        return JsonResponse({'error': 'This lesson does not have a simulation'}, status=400)
    
    # Get or create user progress
    progress, created = UserProgress.objects.get_or_create(
        user=request.user.userprofile,
        lab_id=lab_id,
        lesson=lesson,
        defaults={'status': 'IN_PROGRESS'}
    )
    
    # Get user input
    user_input = request.POST.get('input', '')
    simulation_type = lesson.simulation_config.get('type')
    
    # Handle different simulation types
    if simulation_type == 'login_form':
        result = handle_sql_injection_simulation(user_input, lesson.simulation_config)
        
        # Record the attempt and update progress
        if result['success']:
            # Extract technique from the result
            technique = next((pattern for pattern, response in sql_patterns.items() 
                            if pattern in user_input.lower().strip()), None)
            progress.record_attempt(
                technique=technique,
                success=True,
                points=result.get('points', 0)
            )
        else:
            progress.record_attempt(success=False)
            
    elif simulation_type == 'comment_system':
        result = handle_xss_simulation(user_input, lesson.simulation_config)
    elif simulation_type == 'file_upload':
        result = handle_file_upload_simulation(request.FILES.get('file'), lesson.simulation_config)
    else:
        return JsonResponse({'error': 'Unknown simulation type'}, status=400)
    
    # Add progress information to the response
    result.update({
        'total_points': progress.points_earned,
        'completed_techniques': progress.completed_techniques,
        'attempts': progress.attempts
    })
    
    return JsonResponse(result)

def handle_sql_injection_simulation(user_input, config):
    """Handle SQL injection simulation logic"""
    if not user_input:  # Handle empty or None input
        return {
            'success': False,
            'message': 'Please provide input for the simulation.',
            'details': 'The input field cannot be empty. Try entering a SQL injection payload.'
        }
    
    # Normalize input for pattern matching
    normalized_input = user_input.lower().strip()
    
    # Define SQL injection patterns and their explanations
    sql_patterns = {
        "' or '1'='1": {
            'success': True,
            'message': 'Excellent! You successfully used a basic SQL injection technique.',
            'details': 'This works by making the WHERE clause always true with OR 1=1.',
            'points': 50
        },
        "' or 1=1--": {
            'success': True,
            'message': 'Great job! You used comment-based SQL injection.',
            'details': 'The -- comments out the rest of the query, bypassing the password check.',
            'points': 75
        },
        "admin'--": {
            'success': True,
            'message': 'Perfect! You used the admin account with comment injection.',
            'details': 'By commenting out the password check, you logged in as admin.',
            'points': 100
        },
        "' union select": {
            'success': True,
            'message': 'Advanced technique! You used UNION-based injection.',
            'details': 'UNION allows you to combine results from multiple SELECT statements.',
            'points': 150
        }
    }

    # Check for successful patterns
    for pattern, response in sql_patterns.items():
        if pattern in normalized_input:
            return response
    
    # Provide specific feedback based on partial patterns
    learning_patterns = {
        "'": {
            'message': "Good start! You're using SQL string manipulation.",
            'details': "Single quotes can help break out of the SQL string. Try combining it with other SQL keywords."
        },
        "or": {
            'message': "You're on the right track with the OR operator!",
            'details': "The OR operator can help make conditions always true. Try combining it with string manipulation."
        },
        "admin": {
            'message': "Good thinking targeting the admin account!",
            'details': "Now try to bypass the password check for this account."
        },
        "--": {
            'message': "You found the SQL comment syntax!",
            'details': "Comments can help remove unwanted parts of the query. Try combining with other techniques."
        }
    }

    # Check for learning patterns and provide guidance
    for pattern, feedback in learning_patterns.items():
        if pattern in normalized_input:
            return {
                'success': False,
                'message': feedback['message'],
                'details': feedback['details'],
                'hint_level': 1
            }
    
    # Default response for unsuccessful attempts
    return {
        'success': False,
        'message': 'Keep trying! Your input did not successfully exploit the vulnerability.',
        'details': 'Hint: Try using SQL keywords like OR, UNION, or comment symbols (--) along with string manipulation.',
        'hint_level': 0
    }

def handle_xss_simulation(user_input, config):
    """Handle XSS simulation logic"""
    if not user_input:  # Handle empty or None input
        return {
            'success': False,
            'message': 'Please provide input for the simulation.',
            'details': 'The input field cannot be empty. Try entering a JavaScript payload.'
        }
    
    # Check for XSS patterns
    if ("<script>" in user_input.lower() and "</script>" in user_input.lower()):
        return {
            'success': True,
            'message': 'Congratulations! You successfully demonstrated an XSS vulnerability using script tags.',
            'details': 'You managed to inject JavaScript code that would execute when the page loads.'
        }
    elif "onerror=" in user_input.lower():
        return {
            'success': True,
            'message': 'Excellent! You demonstrated an XSS vulnerability using event handlers.',
            'details': 'You found a way to execute JavaScript through the onerror event handler.'
        }
    elif "onload=" in user_input.lower():
        return {
            'success': True,
            'message': 'Great job! You demonstrated an XSS vulnerability using the onload event.',
            'details': 'You successfully injected JavaScript using the onload event handler.'
        }
    
    # Provide specific feedback based on input patterns
    if "<" in user_input and ">" in user_input:
        return {
            'success': False,
            'message': "Getting closer! You're using HTML tags.",
            'details': "Good start with HTML tags. Now, how can you include JavaScript code?"
        }
    elif "javascript:" in user_input.lower():
        return {
            'success': False,
            'message': "Almost there! You're trying to include JavaScript.",
            'details': "You're on the right track. Try using script tags or event handlers."
        }
    
    return {
        'success': False,
        'message': 'Try again. Your input did not trigger the XSS vulnerability.',
        'details': 'Hint: Can you inject JavaScript code that would execute when the page loads? Try using script tags or event handlers.'
    }

def handle_file_upload_simulation(file_obj, config):
    """Handle file upload simulation logic"""
    if not file_obj:
        return {
            'success': False,
            'message': 'Please select a file to upload.',
            'details': 'You need to choose a file to test the upload vulnerability.'
        }
    
    filename = file_obj.name.lower()
    
    # Check for file extension bypass
    if '.' not in filename:
        return {
            'success': True,
            'message': 'Congratulations! You demonstrated a file extension validation bypass.',
            'details': 'You successfully bypassed validation by uploading a file without an extension.'
        }
    
    # Check for double extension
    if filename.count('.') > 1:
        return {
            'success': True,
            'message': 'Congratulations! You demonstrated a double extension bypass.',
            'details': 'You successfully bypassed validation using multiple file extensions.'
        }
    
    # Check for null byte injection
    if '\x00' in filename:
        return {
            'success': True,
            'message': 'Congratulations! You demonstrated a null byte injection bypass.',
            'details': 'You successfully bypassed validation using a null byte in the filename.'
        }
    
    # Provide specific feedback based on filename patterns
    if any(ext in filename for ext in ['.php', '.asp', '.jsp']):
        return {
            'success': False,
            'message': "Getting closer! You're trying to upload a server-side script.",
            'details': "Good thinking with script files. Now, how can you bypass the extension check?"
        }
    
    return {
        'success': False,
        'message': 'Try again. Your upload did not bypass the security checks.',
        'details': 'Hint: Can you trick the extension validation? Try using multiple extensions or special characters.'
    }

@login_required
@require_POST
def complete_theory_lesson(request, lesson_id):
    """Mark a theory lesson as completed"""
    lesson = get_object_or_404(Lesson, id=lesson_id, lesson_type='theory')
    progress, _ = UserProgress.objects.get_or_create(user=request.user, lesson=lesson)
    
    if not progress.completed:
        progress.completed = True
        progress.points_earned = 50  # Award points for completing theory lesson
        progress.save()
    
    return JsonResponse({
        'status': 'success',
        'message': 'Lesson completed successfully',
        'points_earned': progress.points_earned
    }) 
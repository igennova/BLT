from django.urls import path
from .views import labs

app_name = 'website'

urlpatterns = [
    # Lab URLs
    path('labs/', labs.lab_list, name='lab_list'),
    path('labs/<int:lab_id>/', labs.lab_detail, name='lab_detail'),
    path('labs/lesson/<int:lesson_id>/', labs.lesson_detail, name='lesson_detail'),
    path('labs/lesson/<int:lesson_id>/complete/', labs.complete_theory_lesson, name='complete_theory_lesson'),
] 
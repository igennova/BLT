# website/views.py

from django.shortcuts import render

def video_call(request):
    return render(request, 'website/video_call.html')
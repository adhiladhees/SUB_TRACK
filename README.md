Project Description

This is a web application that helps users manage and track their online subscriptions by securely scanning their emails (with permission). It automatically detects subscription-related emails, extracts important details, and shows them in a clear dashboard so users can see their monthly expenses and active subscriptions in one place.

How to Run This Project

1)Clone the repository 
-git clone https://github.com/adhiladhees/SUB_TRACK.git 
-cd SUBTRACK

2️)Create virtual environment 
-python -m venv .venv

3)Activate virtual environment 
-Windows: .venv\Scripts\activate 
-Mac/Linux: source .venv/bin/activate

4)Install requirements 
-pip install -r requirements.txt

5)Apply migrations 
-python manage.py migrate

6)Create superuser 
-python manage.py createsuperuser

7)Open project/settings.py, at the bottom of the file, paste the EMAIL_HOST_PASSWORD 

8)Open credentials.json, paste the api client

9)Run the server 
-python manage.py runserver

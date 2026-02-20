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
-Password : jmlimjohgpisqdbw

8)Open credentials.json, replace the below content there
-Paste : {"web":{"client_id":"756758147559-hr3dnhc4o0oj82t7287mu3mme860f7ee.apps.googleusercontent.com","project_id":"subtrack-487916","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"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","redirect_uris":["http://127.0.0.1:8000/oauth2callback/"]}}

9)Run the server 
-python manage.py runserver

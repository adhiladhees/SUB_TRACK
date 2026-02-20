from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import Subscription, ScanHistory, UserSettings
from datetime import date, datetime, timedelta
from django.db.models import Sum

import os
import re
import base64
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

from django.core.mail import send_mail
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags



os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def index(request):
    return HttpResponse("<h1>HELLO</h1>")


def home(request):
    return render(request, 'homepage.html')


def signup(request):
    print("SIGNUP VIEW CALLED")  # Debug

    if request.method == "POST":
        name = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        print("POST DATA:", name, email)  # Debug

        # Password mismatch
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'signup.html')

        # Email exists
        if User.objects.filter(username=email).exists():
            messages.error(request, "Email already registered.")
            return render(request, 'signup.html')

        # Create inactive user
        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            first_name=name
        )
        user.is_active = False
        user.save()

        print("User created:", user.email)  # Debug

        # Create activation link
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        activation_link = request.build_absolute_uri(
            reverse('activate', kwargs={'uidb64': uid, 'token': token})
        )

        print("Activation link:", activation_link)  # Debug

        # Send activation email
        subject = "Activate Your SubTrack Account"

        html_content = f"""
        <html>
            <body>
                <p>Hi {user.first_name},</p>
                <p>Click the button below to activate your account:</p>

                <a href="{activation_link}"
                style="
                    display:inline-block;
                    padding:12px 25px;
                    font-size:16px;
                    color:#ffffff;
                    background-color:#28a745;
                    text-decoration:none;
                    border-radius:5px;
                    font-weight:bold;">
                Activate Account
                </a>
            </body>
            </html>
            """

        text_content = strip_tags(html_content)

        email = EmailMultiAlternatives(
                subject,
                text_content,
                settings.EMAIL_HOST_USER,
                [user.email],
            )

        email.attach_alternative(html_content, "text/html")
        email.send()

        print("Email sent to:", user.email)  # Debug

        return render(request, 'verify_pending.html')

    return render(request, 'signup.html')


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Account activated. Please log in.")
        return redirect('login')
    else:
        messages.error(request, "Invalid or expired activation link.")
        return redirect('login')




def user_login(request):
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')

        user = authenticate(request, username=email, password=password)

        if user:
            login(request, user)
            request.session.pop("renewal_alert_shown", None)
            return redirect('dashboard')

        messages.error(request, "Invalid credentials.")
        return redirect('login')

    return render(request, 'login.html')


def user_logout(request):
    request.session.flush()
    logout(request)
    return redirect('homepage')

@login_required
def dashboard(request):

    subscriptions = Subscription.objects.filter(user=request.user)
    total = subscriptions.count()
    today = date.today()

    monthly_spend = subscriptions.filter(
        billing_cycle="Monthly"
    ).aggregate(total=Sum("amount"))["total"] or 0

    upcoming_renewals = subscriptions.filter(
        renewal_date__gte=today
    ).count()

    user_settings, _ = UserSettings.objects.get_or_create(user=request.user)
    reminder_enabled = user_settings.renewal_reminder

    # Get nearest upcoming renewal
    next_renewal = subscriptions.filter(
        renewal_date__gte=today
    ).order_by('renewal_date').first()

    show_alert = False
    if reminder_enabled and next_renewal is not None:
        if not request.session.get("renewal_alert_shown"):
            show_alert = True
            request.session["renewal_alert_shown"] = True

    
    last_scan_obj = ScanHistory.objects.filter(
        user=request.user
    ).order_by('-scan_time').first()

    if last_scan_obj:
        gmail_count = last_scan_obj.emails_found
        last_scan = last_scan_obj.scan_time.strftime("%d-%m-%Y")
    else:
        gmail_count = 0
        last_scan = None

    display_name = request.user.first_name or request.user.username

    context = {
        'display_name': display_name,
        'total_subscriptions': total,
        'gmail_count': gmail_count,
        'last_scan': last_scan,
        'monthly_spend': monthly_spend,
        'upcoming_renewals': upcoming_renewals,
        'show_alert': show_alert,
        'next_renewal': next_renewal,
    }

    return render(request, 'dashboard.html', context)

# SUBSCRIPTIONS
@login_required
def subscriptions(request):
    return render(request, 'subscriptions.html', {
        'subscriptions': Subscription.objects.filter(user=request.user)
    })

# ANALYTICS
@login_required
def analytics(request):
    subs = Subscription.objects.filter(user=request.user)
    today = date.today()

    monthly_spend = subs.filter(
        billing_cycle="Monthly"
    ).aggregate(total=Sum("amount"))["total"] or 0

    yearly_estimate = 0
    for s in subs:
        if s.billing_cycle == "Monthly":
            yearly_estimate += s.amount * 12
        elif s.billing_cycle == "Yearly":
            yearly_estimate += s.amount
        else:
            yearly_estimate += s.amount

    upcoming = subs.filter(renewal_date__gte=today).count()

    return render(request, 'analytics.html', {
        'total_subscriptions': subs.count(),
        'monthly_spend': monthly_spend,
        'yearly_estimate': yearly_estimate,
        'upcoming_renewals': upcoming
    })


@login_required
def user_settings(request):

    from .models import UserSettings

    user_settings, created = UserSettings.objects.get_or_create(user=request.user)

    if request.method == "POST":
        reminder_value = request.POST.get("renewal_reminder")
        user_settings.renewal_reminder = True if reminder_value == "on" else False
        user_settings.save()
        if user_settings.renewal_reminder:
            request.session.pop("renewal_alert_shown", None)
        return redirect("settings")

    return render(request, 'settings.html', {
        'renewal_reminder': user_settings.renewal_reminder
    })


# GMAIL SCAN WITH HISTORY TRACKING
@login_required
def scan_emails(request):

    token_path = f"token_{request.user.id}.json"

    if os.path.exists(token_path):

        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
        service = build('gmail', 'v1', credentials=creds)

        one_year_ago = datetime.now() - timedelta(days=365)
        formatted_date = one_year_ago.strftime('%Y/%m/%d')

        keywords = "(payment OR invoice OR receipt OR renewal OR charged)"
        query = f"after:{formatted_date} {keywords} -subject:(offer OR discount OR upgrade OR deal)"

        results = service.users().messages().list(
            userId='me',
            q=query,
            maxResults=200
        ).execute()

        messages = results.get('messages', [])

        ALLOWED_SERVICES = [
            'netflix','primevideo','amazon','disneyplus','jiohotstar',
            'hulu','hbomax','paramountplus','peacock','discoveryplus','manoramamax',
            'sonyliv','zee5','jiocinema',
            'spotify','youtubepremium','youtube','applemusic',
            'amazonmusic','gaana','wynk',
            'adobe','canva','notion','slack','zoom','microsoft',
            'office','office365','github','gitlab','figma',
            'dropbox','grammarly',
            'google','googleone','icloud','onedrive',
            'playstation','xbox','steam','epicgames','ea','ubisoft',
            'coursera','udemy','skillshare','unacademy','byjus',
        ]

        created = 0

        for msg in messages:

            msg_data = service.users().messages().get(
                userId='me',
                id=msg['id']
            ).execute()

            headers = msg_data.get('payload', {}).get('headers', [])

            subject = ""
            sender = ""

            for h in headers:
                if h['name'] == 'Subject':
                    subject = h['value']
                if h['name'] == 'From':
                    sender = h['value']

            if not sender:
                continue

            if "<" in sender:
                email_part = sender.split("<")[1].split(">")[0]
            else:
                email_part = sender.strip()

            if "@" not in email_part:
                continue

            domain = email_part.split("@")[1]
            service_name = domain.split(".")[0].lower()

            if service_name not in ALLOWED_SERVICES:
                continue

            payload = msg_data.get('payload', {})
            body_text = ""

            if 'parts' in payload:
                for part in payload['parts']:
                    mime = part.get('mimeType')
                    if mime in ('text/plain', 'text/html'):
                        data = part.get('body', {}).get('data')
                        if data:
                            decoded = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                            body_text += decoded
            else:
                data = payload.get('body', {}).get('data')
                if data:
                    decoded = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    body_text += decoded

            if not body_text:
                body_text = msg_data.get('snippet', '') or ''

            text_for_amount = f"{subject} {body_text}".lower()

            RECEIPT_KEYWORDS = [
                "payment successful",
                "transaction id",
                "invoice number",
                "receipt",
                "charged",
                "amount paid",
                "order id",
                "billing statement",
                "order processed"
            ]

            if not any(word in text_for_amount for word in RECEIPT_KEYWORDS):
                continue

            MARKETING_KEYWORDS = [
                "offer",
                "limited time",
                "discount",
                "save",
                "upgrade now",
                "try now",
                "get premium",
                "only ₹",
                "starting at",
                "as low as"
            ]

            if any(word in text_for_amount for word in MARKETING_KEYWORDS):
                continue

            # ============================================================
            # AMOUNT EXTRACTION (UNCHANGED)
            # ============================================================

            amount_matches = re.findall(
                r'(?:₹\s?\d+(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?\s?INR|USD\s?\d+(?:\.\d{1,2})?)',
                text_for_amount,
                flags=re.IGNORECASE
            )

            amounts = []
            for match in amount_matches:
                number = re.findall(r'\d+(?:\.\d{1,2})?', match)
                if number:
                    value = float(number[0])
                    if 0 <= value <= 5000:
                        amounts.append(value)

            amount = max(amounts) if amounts else 0

            # ============================================================
            # 🔥 NEW CLASSIFICATION LOGIC (ONLY ADDITION)
            # ============================================================

            billing_cycle = "Monthly"
            plan = ""

            RECURRING_KEYWORDS = [
                "renews",
                "auto-renew",
                "per month",
                "monthly",
                "annual subscription",
                "per year"
            ]

            LICENSE_KEYWORDS = [
                "install",
                "product key",
                "lifetime",
                "one-time purchase",
                "perpetual",
                "digital download"
            ]

            # If strong license indicators and no recurring language
            if any(word in text_for_amount for word in LICENSE_KEYWORDS) and \
               not any(word in text_for_amount for word in RECURRING_KEYWORDS):
                billing_cycle = "One-time"
                plan = "License"

            # Yearly detection (original behavior preserved)
            elif "year" in text_for_amount or "annual" in text_for_amount:
                billing_cycle = "Yearly"

            elif "lifetime" in text_for_amount or "one-time" in text_for_amount:
                billing_cycle = "One-time"

            if "trial" in text_for_amount:
                plan = "Trial"
                billing_cycle = "Monthly"

            # ============================================================

            exists = Subscription.objects.filter(
                user=request.user,
                service_name__iexact=service_name
            ).exists()

            if not exists:
                Subscription.objects.create(
                    user=request.user,
                    service_name=service_name.capitalize(),
                    email=email_part,
                    amount=amount,
                    billing_cycle=billing_cycle,
                    plan=plan
                )
                created += 1

        ScanHistory.objects.create(
            user=request.user,
            emails_found=len(messages),
            subscriptions_added=created
        )

        return redirect('dashboard')

    flow = Flow.from_client_secrets_file(
        'credentials.json',
        scopes=SCOPES,
        redirect_uri='http://127.0.0.1:8000/oauth2callback/'
    )

    auth_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent'
    )

    request.session['state'] = state
    return redirect(auth_url)




@login_required
def oauth2callback(request):

    state = request.session['state']

    flow = Flow.from_client_secrets_file(
        'credentials.json',
        scopes=SCOPES,
        state=state,
        redirect_uri='http://127.0.0.1:8000/oauth2callback/'
    )

    flow.fetch_token(authorization_response=request.build_absolute_uri())

    creds = flow.credentials

    with open(f"token_{request.user.id}.json", 'w') as token:
        token.write(creds.to_json())

    return redirect('scan_emails')

@login_required
def add_subscription(request):
    if request.method == "POST":

        service_name = request.POST.get("service_name")
        billing_cycle = request.POST.get("billing_cycle")
        renewal_date = request.POST.get("renewal_date")
        amount = request.POST.get("amount")

        if billing_cycle == "Free":
            amount = 0

        if not amount:
            amount = 0

        Subscription.objects.create(
            user=request.user,
            service_name=service_name,
            email=request.user.email,
            billing_cycle=billing_cycle,
            renewal_date=renewal_date if renewal_date else None,
            amount=amount
        )

        return redirect("subscriptions")

    return redirect("dashboard")


@login_required
def edit_subscription(request, sub_id):
    subscription = Subscription.objects.filter(
        id=sub_id,
        user=request.user
    ).first()

    if not subscription:
        return redirect("subscriptions")

    if request.method == "POST":
        service_name = request.POST.get("service_name")
        billing_cycle = request.POST.get("billing_cycle")
        renewal_date = request.POST.get("renewal_date")
        amount = request.POST.get("amount")

        subscription.service_name = service_name
        subscription.billing_cycle = billing_cycle
        subscription.renewal_date = renewal_date if renewal_date else None
        subscription.amount = amount if amount else 0
        subscription.save()

    return redirect("subscriptions")


@login_required
def delete_subscription(request, sub_id):
    if request.method == "POST":
        Subscription.objects.filter(
            id=sub_id,
            user=request.user
        ).delete()

    return redirect("subscriptions")
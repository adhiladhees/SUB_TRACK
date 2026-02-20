from django.db import models
from django.contrib.auth.models import User


class Subscription(models.Model):
    BILLING_CHOICES = [
        ("Monthly", "Monthly"),
        ("Yearly", "Yearly"),
        ("One-time", "One-time"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)

    service_name = models.CharField(max_length=100)
    email = models.EmailField()

    amount = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        default=0
    )

    billing_cycle = models.CharField(
        max_length=20,
        choices=BILLING_CHOICES,
        blank=True
    )

    plan = models.CharField(
        max_length=100,
        blank=True
    )

    renewal_date = models.DateField(
        null=True,
        blank=True
    )

    detected_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"{self.service_name} - {self.user.email}"

class ScanHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scan_time = models.DateTimeField(auto_now_add=True)
    emails_found = models.IntegerField(default=0)
    subscriptions_added = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.user.email} - {self.scan_time.strftime('%Y-%m-%d %H:%M')}"




class UserSettings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    renewal_reminder = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username

class EmailOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - {self.otp}"
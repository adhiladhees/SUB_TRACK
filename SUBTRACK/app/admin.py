from django.contrib import admin
from django import forms
from datetime import date
from .models import Subscription, ScanHistory

class SubscriptionAdminForm(forms.ModelForm):
    class Meta:
        model = Subscription
        fields = "__all__"

    def clean_renewal_date(self):
        renewal_date = self.cleaned_data.get("renewal_date")

        if renewal_date and renewal_date < date.today():
            raise forms.ValidationError(
                "Renewal date cannot be in the past."
            )

        return renewal_date


class SubscriptionAdmin(admin.ModelAdmin):
    form = SubscriptionAdminForm
    list_display = (
        "service_name",
        "user",
        "amount",
        "billing_cycle",
        "plan",
        "renewal_date",
    )
    search_fields = ("service_name", "user__email")
    list_filter = ("billing_cycle", "plan")


admin.site.register(Subscription, SubscriptionAdmin)

class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "scan_time",
        "emails_found",
        "subscriptions_added",
    )
    ordering = ("-scan_time",)
    readonly_fields = (
        "user",
        "scan_time",
        "emails_found",
        "subscriptions_added",
    )

    def has_add_permission(self, request):
        return False  # Prevent manual creation


admin.site.register(ScanHistory, ScanHistoryAdmin)

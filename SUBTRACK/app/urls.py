from django.urls import path,include
from . import views

urlpatterns = [
    path('',views.home,name='homepage'),
    path('signup/', views.signup, name='signup'),
    
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('subscriptions/', views.subscriptions, name='subscriptions'),
    path('analytics/', views.analytics, name='analytics'),
    path('settings/', views.user_settings, name='settings'),

    path('scan-emails/', views.scan_emails, name='scan_emails'),
    path('oauth2callback/', views.oauth2callback, name='oauth2callback'),

    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('add-subscription/', views.add_subscription, name='add_subscription'),
    path('subscriptions/<int:sub_id>/edit/', views.edit_subscription, name='edit_subscription'),
    path('subscriptions/<int:sub_id>/delete/', views.delete_subscription, name='delete_subscription'),

]

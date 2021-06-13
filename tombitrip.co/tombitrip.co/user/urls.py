from django.urls import path

from home.views import ReservationView, UpdateReservationView, MyAdvertiseView, DeleteAdvertiseView, \
    UpdateAdvertiseView, AddAdvertiseView, ReservationSupplierView
from . import views

from django.contrib.auth import views as auth_views

urlpatterns = [
    path('profile/', views.user_profile, name='user_profile'),
    path('profile/reservation/user', ReservationView.as_view(), name='user_reservation'),
    path('profile/reservation/supplier', ReservationSupplierView.as_view(), name='supply_reservation'),
    path('my_advertise/', MyAdvertiseView.as_view(), name='my-advertise'),
    path('my_advertise/add/', AddAdvertiseView.as_view(), name='add-advertise'),
    path('password/',views.user_password,name='password'),
    path('update/', views.user_update,name='user_update'),
    path('profile/reservation/update/<str:pk>/', UpdateReservationView.as_view() ,name='update_user_reservation'),
    path('my_advertise/delete/<str:pk>/', DeleteAdvertiseView.as_view() ,name='delete-my-advertise'),
    path('my_advertise/update/<str:pk>/', UpdateAdvertiseView.as_view() ,name='update-my-advertise'),
    path('payment/<int:pk>/<int:ck>/', views.stripePayment, name="payment"),
    path('payment/charge/<str:pk>/<str:ck>', views.charge, name="payment-charge"),
    path('payment/success/<str:args>/', views.successPayment, name="payment-success"),
    
    path('signup_for_user', views.signup_for_user, name='signup_for_user'),
    
    path('check_email_exist/', views.check_email_exist, name="check_email_exist"),
    path('check_username_exist/', views.check_username_exist, name="check_username_exist"),
    path('check_login_user/', views.check_login_user, name="check_login_user"),
    
    
    path('password_reset/',auth_views.PasswordResetView.as_view(),name='password_reset'),
    path('password_reset/done/',auth_views.PasswordResetDoneView.as_view(),name='password_reset_done'),
    path('reset/<uidb64>/<token>/',auth_views.PasswordResetConfirmView.as_view(),name='password_reset_confirm'),
    path('reset/done/',auth_views.PasswordResetCompleteView.as_view(),name='password_reset_complete'),
    
    # activation email
    path('email/confirmation/<str:activation_key>/', views.email_confirm, name='email_activation'  ),
    
    
  
    

]
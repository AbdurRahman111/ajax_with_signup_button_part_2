from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import HttpResponse, HttpResponseRedirect

from home.models import Supply, ProductAttribute, Reservation
from .forms import SignUpForm, UserUpdateForm, ProfileUpdateForm
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from user.models import UserProfile
from django.contrib.auth.forms import PasswordChangeForm
from django.urls import reverse
import stripe

from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from .models import EmailConfirmed
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt

stripe.api_key = "sk_test_51IkV7mJS8r1hMN7QBqVvhz1RFieDcq8HfkYfS2S45agCFCjiNBC1N3mvKnGdJWZyxyw8UBlpWKuwiUMdvPmRuPfD00G8GiJgeu"


@csrf_exempt
def check_email_exist(request):
    email = request.POST.get("email")
    user_obj = User.objects.filter(email=email).exists()
    if user_obj:
        return HttpResponse(True)
    else:
        return HttpResponse(False)



@csrf_exempt
def check_username_exist(request):
    username = request.POST.get("username")
    user_obj = User.objects.filter(username=username).exists()
    if user_obj:
        return HttpResponse(True)
    else:
        return HttpResponse(False)


@csrf_exempt
def check_login_user(request):
    username1_value = request.POST.get("username1_value")
    password1_value = request.POST.get("password1_value")
    
    user = authenticate(request, username=username1_value, password=password1_value)
    if user is not None:
        return HttpResponse(True)
    else:
        return HttpResponse(False)


# create user
def signup_for_user(request):
    if request.method == "POST":
        username = request.POST.get('username')
        email_sign = request.POST.get('email')
        password_sign = request.POST.get('password')
        
        # create user
        myuser = User.objects.create_user(username, email_sign, password_sign)
        myuser.is_active = False
        myuser.save()
        
        # Create data in profile table for user
        # current_user = request.user
        data = UserProfile()
        data.user_id = myuser.id
        data.image = "images/users/user.png"
        data.save()
        
        # send mail
        user = EmailConfirmed.objects.get(user=myuser)
        site = get_current_site(request)
        email = myuser.email
        username = myuser.username
            

        sub_of_email = "Activation Email From Tombitrip."
        email_body = render_to_string(
            'user/verify_email.html',
            {
                'username': username,
                    
                'email': email,
                'domain': site.domain,
                'activation_key': user.activation_key
            }
        )

        send_mail(
            sub_of_email,  # Subject of message
            email_body,  # Message
            '',  # From Email
            [email],  # To Email

            fail_silently=True
        )

        messages.success(request, 'Check Your Email for Activate Your Account !!!')
        return redirect('/')
        




# Create your views here.
def signup_form(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            signup_request = form.save(commit=False)
            signup_request.is_active=False
            
            signup_request.save()  # completed sign up
            
            
            # username = form.cleaned_data.get('username')
            # password = form.cleaned_data.get('password1')
            # user = authenticate(username=username, password=password)
            # login(request, user)
            
            
            # Create data in profile table for user
            # current_user = request.user
            data = UserProfile()
            data.user_id = signup_request.id
            data.image = "images/users/user.png"
            data.save()
            
            
            
            # send mail
            user = EmailConfirmed.objects.get(user=signup_request)
            site = get_current_site(request)
            email = signup_request.email
            username = signup_request.username
            

            sub_of_email = "Activation Email From Tombitrip."
            email_body = render_to_string(
                'user/verify_email.html',
                {
                    'username': username,
                    
                    'email': email,
                    'domain': site.domain,
                    'activation_key': user.activation_key
                }
            )

            send_mail(
                sub_of_email,  # Subject of message
                email_body,  # Message
                '',  # From Email
                [email],  # To Email

                fail_silently=True
            )

            messages.success(request, 'Check Your Email for Activate Your Account !!!')

            
            return HttpResponseRedirect('/login')
        else:
            messages.warning(request, form.errors)
            return HttpResponseRedirect('/signup')

    form = SignUpForm()

    context = {
        'form': form,
    }
    return render(request, 'user/signup.html', context)




def email_confirm(request, activation_key):
    user= get_object_or_404(EmailConfirmed, activation_key=activation_key)
    if user is not None:
        user.email_confirmed=True
        user.save()

        myuser=User.objects.get(email=user)
        myuser.is_active=True
        myuser.save()
        username=myuser.username
        
        condict = {'username': username}
        return render(request, 'user/registration_complete.html', condict)



def login_form(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            current_user = request.user
            userprofile = UserProfile.objects.get(user_id=current_user.id)
            request.session['userimage'] = userprofile.image.url

            # Redirect to a success page.
            messages.success(request, 'Wellcome to our website, Please Update your profile')
            return HttpResponseRedirect('/user/profile')
        else:
            messages.warning(request, "Login Error !! Username or Password is incorrect")
            return HttpResponseRedirect('/login')

    return render(request, 'user/login_form.html')


def logout_func(request):
    logout(request)
    # if translation.LANGUAGE_SESSION_KEY in request.session:
    #     del request.session[translation.LANGUAGE_SESSION_KEY]
    #     del request.session['currency']
    return HttpResponseRedirect('/login')


@login_required(login_url='/login')  # Check login
def user_profile(request):
    current_user = request.user  # Access User Session information
    profile = UserProfile.objects.get(user_id=current_user.id)
    context = {

        'profile': profile}
    return render(request, 'user/user_profile.html', context)


@login_required(login_url='/login')  # Check login
def user_update(request):
    if request.method == 'POST':
        user_form = UserUpdateForm(request.POST, instance=request.user)  # request.user is user  data
        profile_form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user.userprofile)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your account has been updated!')
            return HttpResponseRedirect('/user/update')
    else:

        user_form = UserUpdateForm(instance=request.user)
        profile_form = ProfileUpdateForm(
            instance=request.user.userprofile)  # "userprofile" model -> OneToOneField relatinon with user
        context = {

            'user_form': user_form,
            'profile_form': profile_form
        }
        return render(request, 'user/user_update.html', context)


@login_required(login_url='/login')  # Check login
def user_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, 'Your password was successfully updated!')
            return HttpResponseRedirect('/user/profile')
        else:
            messages.error(request, 'Please correct the error below.<br>' + str(form.errors))
            return HttpResponseRedirect('/user/password')
    else:

        form = PasswordChangeForm(request.user)
        return render(request, 'user/user_password.html', {'form': form})

def stripePayment(request, pk, ck):
    supply = Supply.objects.get(id=pk)
    productatr = ProductAttribute.objects.get(supply=supply)
    print(productatr.price)
    context = {
        'price': productatr.price,
        's_id':pk,
        'r_id':ck
    }
    return render(request, 'user/stripe_payment.html', context=context)

def charge(request, pk,ck):
    if request.method == 'POST':
        print('Data:', request.POST)
        supply = Supply.objects.get(id=pk)
        reservation = Reservation.objects.get(id=ck ,supply=supply, user=request.user)
        reservation.paid = True
        reservation.save()
        amount = int(request.POST['amount'])

        customer = stripe.Customer.create(
                email=request.POST['email'],
                name=request.POST['nickname'],
                source=request.POST['stripeToken']
            )

        charge = stripe.Charge.create(
                customer=customer,
                amount=amount * 100,
                currency='usd',
                description="Donation"
            )

    return redirect(reverse('payment-success', args=[amount]))

def successPayment(request, args):
    amount = args
    context = {
        'amount': amount
    }
    return render(request, 'user/stripe_payment_success.html', context=context)
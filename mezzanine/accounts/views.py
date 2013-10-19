
from django.contrib.auth import (authenticate, login as auth_login,
                                               logout as auth_logout)
from django.contrib.auth.decorators import login_required
from django.contrib.messages import info, error
from django.core.urlresolvers import NoReverseMatch
from django.shortcuts import get_object_or_404, redirect
from django.utils.translation import ugettext_lazy as _

from mezzanine.utils.models import get_user_model
from mezzanine.accounts import get_profile_form
from mezzanine.accounts.forms import LoginForm, PasswordResetForm
from mezzanine.conf import settings
from mezzanine.utils.email import send_verification_mail, send_approve_mail
#from mezzanine.utils.email import send_approve_mail
#from stores.checkout import send_verification_mail

from mezzanine.utils.urls import login_redirect, next_url
from mezzanine.utils.views import render

from stores import location_utils
import ast
from stores.checkout import new_location_get_ids

User = get_user_model()


def login(request, template="accounts/account_login.html"):
    """
    Login form.
    """
    form = LoginForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        authenticated_user = form.save()
        info(request, _("Successfully logged in"))
        auth_login(request, authenticated_user)

        customer = request.user.get_profile()
        request.session['location'] = customer.location
        request.session['address'] = customer.address
        request.session['age'] = True

        loc = ast.literal_eval(request.session['location'])
        avail_store_ids, avail_store_names, avail_liquor_types, loc, store_locs = new_location_get_ids(request, loc)

#        return login_redirect(request)
        if 'cart loaded' in request.session:
            return redirect('/shop/cart/')
        else:
            return redirect('/shop/')

    context = {"form": form, "title": _("Log in")}
    return render(request, template, context)


def logout(request):
    """
    Log the user out.
    """
    auth_logout(request)
    info(request, _("Successfully logged out"))

    if 'stores' in request.session:
        del request.session['stores']
    if 'cart loaded' in request.session:
        del request.session['cart loaded']
    if 'location' in request.session:
        del request.session['location']
        del request.session['address']
        del request.session['store ids']
        del request.session['available store names']
        del request.session['available liquor types']
    if 'age' in request.session:
        del request.session['age']

#    return redirect('/')
    return redirect(next_url(request) or "/")


def signup(request, template="accounts/account_signup.html"):
    """
    Signup form.
    """
    profile_form = get_profile_form()
    form = profile_form(request.POST or None, request.FILES or None)
    if request.method == "POST" and form.is_valid():
        new_user = form.save()
        if not new_user.is_active:
            if settings.ACCOUNTS_APPROVAL_REQUIRED:
                send_approve_mail(request, new_user)
                info(request, _("Thanks for signing up! You'll receive "
                                "an email when your account is activated."))
            else:
                send_verification_mail(request, new_user, "signup_verify")
                info(request, _("A verification email has been sent with "
                                "a link for activating your account."))
#            return redirect(request.GET.get("next", "/"))
            return redirect(next_url(request) or "/")
        else:
            info(request, _("Successfully signed up"))
            auth_login(request, new_user)

            customer = request.user.get_profile()
            customer_address = customer.address + ', ' + customer.zip_code
            loc = location_utils.getLocation(customer_address)
            correct_address = location_utils.getAddress(loc[0],loc[1])
            customer.location = loc
            customer.address = correct_address
            customer.save()

            request.session['location'] = (loc[0],loc[1])
            request.session['age'] = True
            request.session['address'] = correct_address
            request.session['map'] = True

            avail_store_ids, avail_store_names, avail_liquor_types, loc, store_locs = new_location_get_ids(request, loc)

#            return login_redirect(request)
            if 'cart loaded' in request.session:
                return redirect('/shop/cart/')
            else:
                return redirect('/shop/')
    context = {"form": form, "title": _("Sign up")}
    return render(request, template, context)


def signup_verify(request, uidb36=None, token=None):
    """
    View for the link in the verification email sent to a new user
    when they create an account and ``ACCOUNTS_VERIFICATION_REQUIRED``
    is set to ``True``. Activates the user and logs them in,
    redirecting to the URL they tried to access when signing up.
    """
    user = authenticate(uidb36=uidb36, token=token, is_active=False)
    if user is not None:
        user.is_active = True
        user.save()
        auth_login(request, user)
        info(request, _("Successfully signed up"))

        customer = request.user.get_profile()
        customer_address = customer.address + ', ' + customer.zip_code
        loc = location_utils.getLocation(customer_address)
        correct_address = location_utils.getAddress(loc[0],loc[1])
        customer.location = loc
        customer.address = correct_address
        customer.save()

        request.session['location'] = (loc[0],loc[1])
        request.session['age'] = True
        request.session['address'] = correct_address
        request.session['map'] = True

        avail_store_ids, avail_store_names, avail_liquor_types, loc, store_locs = new_location_get_ids(request, loc)

#        return login_redirect(request)
        if 'cart loaded' in request.session:
            return redirect('/shop/cart/')
        else:
            return redirect('/shop/')
    else:
        error(request, _("The link you clicked is no longer valid."))
        return redirect("/")

@login_required
def profile_redirect(request):
    """
    Just gives the URL prefix for profiles an action - redirect
    to the logged in user's profile.
    """
    return redirect("profile", username=request.user.username)


def profile(request, username, template="accounts/account_profile.html"):
    """
    Display a profile.
    """
    lookup = {"username__iexact": username, "is_active": True}
    context = {"profile_user": get_object_or_404(User, **lookup)}
    return render(request, template, context)


@login_required
def account_redirect(request):
    """
    Just gives the URL prefix for accounts an action - redirect
    to the profile update form.
    """
    return redirect("profile_update")


@login_required
def profile_update(request, template="accounts/account_profile_update.html"):
    """
    Profile update form.
    """
    profile_form = get_profile_form()
    form = profile_form(request.POST or None, request.FILES or None,
                        instance=request.user)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        info(request, _("Profile updated"))
        try:

            customer = request.user.get_profile()
            customer_address = customer.address + ', ' + customer.zip_code
            loc = location_utils.getLocation(customer_address)
            correct_address = location_utils.getAddress(loc[0],loc[1])
            customer.location = loc
            customer.address = correct_address
            customer.save()

            request.session['location'] = (loc[0],loc[1])
            request.session['age'] = True
            request.session['address'] = correct_address
            request.session['map'] = True

            avail_store_ids, avail_store_names, avail_liquor_types, loc, store_locs = new_location_get_ids(request, loc)

            return redirect("profile", username=user.username)
        except NoReverseMatch:
            return redirect("profile_update")
    context = {"form": form, "title": _("Update Profile")}
    return render(request, template, context)


def password_reset(request, template="accounts/account_password_reset.html"):
    form = PasswordResetForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        send_verification_mail(request, user, "password_reset_verify")
        info(request, _("A verification email has been sent with "
                        "a link for resetting your password."))
    context = {"form": form, "title": _("Password Reset")}
    return render(request, template, context)


def password_reset_verify(request, uidb36=None, token=None):
    user = authenticate(uidb36=uidb36, token=token, is_active=True)
    if user is not None:
        auth_login(request, user)
        return redirect("profile_update")
    else:
        error(request, _("The link you clicked is no longer valid."))
        return redirect("/")

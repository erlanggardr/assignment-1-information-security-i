from allauth.account.forms import ChangePasswordForm, LoginForm, SignupForm

from . import service


class VaultLoginForm(LoginForm):
    def login(self, request, redirect_url=None):
        muk = service.unlock_user(self.user, self.cleaned_data["password"])
        if muk is not None:
            request._vault_muk = muk
        return super().login(request, redirect_url)


class VaultSignupForm(SignupForm):
    def save(self, request):
        user = super().save(request)
        request._vault_muk = service.provision_user_key(user, self.cleaned_data["password1"])
        return user


class VaultChangePasswordForm(ChangePasswordForm):
    def save(self):
        old_password = self.cleaned_data["oldpassword"]
        new_password = self.cleaned_data["password1"]
        super().save()
        service.change_password(self.user, old_password, new_password)

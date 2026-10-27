from allauth.account.forms import ChangePasswordForm, LoginForm, SignupForm
from django import forms

from . import service, storage


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


class ProfileForm(forms.Form):
    full_name = forms.CharField(label="Full legal name", max_length=120)
    nik = forms.CharField(label="NIK (national ID number)", min_length=16, max_length=16)
    mother_maiden_name = forms.CharField(label="Mother's maiden name", max_length=120)
    date_of_birth = forms.DateField(label="Date of birth", widget=forms.DateInput(attrs={"type": "date"}))
    address = forms.CharField(label="Residential address", max_length=300, widget=forms.Textarea(attrs={"rows": 2}))
    bank_account = forms.CharField(label="Bank account number", max_length=32)
    net_worth = forms.DecimalField(label="Declared net worth (IDR)", min_value=0, max_digits=18, decimal_places=0)

    def clean_nik(self):
        nik = self.cleaned_data["nik"].strip()
        if not nik.isdigit():
            raise forms.ValidationError("NIK must be 16 digits.")
        return nik

    def clean_bank_account(self):
        value = self.cleaned_data["bank_account"].strip()
        if not value.replace("-", "").isdigit():
            raise forms.ValidationError("Use digits only.")
        return value

    def to_fields(self) -> dict:
        data = dict(self.cleaned_data)
        data["date_of_birth"] = data["date_of_birth"].isoformat()
        data["net_worth"] = str(data["net_worth"])
        return data


class UploadForm(forms.Form):
    file = forms.FileField()

    def __init__(self, *args, category, **kwargs):
        super().__init__(*args, **kwargs)
        self.category = category
        exts = sorted(storage.RULES[category]["exts"])
        self.fields["file"].widget.attrs["accept"] = ",".join(f".{e}" for e in exts)
        self.fields["file"].help_text = (
            f"Allowed: {', '.join(exts)}. Maximum {storage.RULES[category]['max'] // storage.MB} MB."
        )

    def clean_file(self):
        upload = self.cleaned_data["file"]
        try:
            storage.validate_file(self.category, storage.clean_filename(upload.name), upload.size)
        except storage.UploadRejected as exc:
            raise forms.ValidationError(str(exc)) from exc
        return upload

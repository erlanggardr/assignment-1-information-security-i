import functools
import logging
import time
import uuid

from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import redirect_to_login
from django.core.cache import cache
from django.http import Http404, HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.http import content_disposition_header
from django.views.decorators.http import require_POST

from . import bench, bench_vault, keys, sealing, service, storage
from . import crypto_engine as ce
from . import liveness as live
from .forms import LoanForm, ProfileForm, UploadForm

log = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = 64 * 1024 * 1024


def vault_unlocked(view):
    @login_required
    @functools.wraps(view)
    def wrapper(request, *args, **kwargs):
        muk = service.get_muk(request)
        if muk is None:
            next_url = request.get_full_path()
            logout(request)
            messages.warning(request, "Your vault is locked. Sign in again to unlock it.")
            return redirect_to_login(next_url)
        return view(request, muk, *args, **kwargs)

    return wrapper


@vault_unlocked
def encrypt_demo(request, muk):
    if request.method != "POST":
        return render(request, "vault/demo.html")

    upload = request.FILES.get("file")
    data = upload.read() if upload else request.POST.get("text", "").encode("utf-8")
    error = None
    if not data:
        error = "Provide a file or some text."
    elif len(data) > MAX_UPLOAD_BYTES:
        error = "File is larger than 64 MB."
    if error:
        return render(request, "vault/demo.html", {"error": error}, status=400)

    aad = keys.record_aad(request.user.pk, uuid.uuid4())
    sealed = sealing.seal(data, muk, aad)
    rows = []
    for name in ce.CIPHERS:
        t0 = time.perf_counter_ns()
        try:
            sealing.open_sealed(sealed, name, muk, aad)
            intact = True
        except ce.IntegrityError:
            intact = False
        total_ns = time.perf_counter_ns() - t0
        blob = sealed.blobs[name]
        rows.append({
            "cipher": name.upper(),
            "enc_ms": sealed.encrypt_ns[name] / 1e6,
            "dec_ms": total_ns / 1e6,
            "size": len(blob),
            "overhead": len(blob) - len(data),
            "intact": intact,
            "preview": blob[:24].hex() + "...",
        })
    return render(request, "vault/demo.html", {"rows": rows, "plain_size": len(data), "digest": sealed.digest.hex()})


@vault_unlocked
def benchmark(request, muk):
    context = {"sizes": list(bench.DEFAULT_SIZES), "default_sizes": ["1 KB", "1 MB"]}
    if request.method != "POST":
        return render(request, "vault/benchmark.html", context)

    if request.POST.get("kind") in ("items", "analysis"):
        context["env"] = bench.environment()
        if request.POST.get("kind") == "items":
            downloads = _bounded_int(request.POST.get("downloads"), default=10, low=1, high=30)
            context.update(item_rows=bench_vault.run_item_downloads(request.user, muk, downloads), item_downloads=downloads, ran_items=True)
        else:
            context["analysis_rows"] = bench_vault.compare_ciphertexts()
        return render(request, "vault/benchmark.html", context)

    chosen = request.POST.getlist("sizes")
    sizes = {k: v for k, v in bench.DEFAULT_SIZES.items() if k in chosen} or {"1 MB": 1024**2}
    context["env"] = bench.environment()
    if request.POST.get("kind") == "download":
        downloads = _bounded_int(request.POST.get("downloads"), default=10, low=1, high=30)
        context.update(download_rows=bench.run_download_benchmark(sizes, downloads), downloads=downloads)
    else:
        runs = _bounded_int(request.POST.get("runs"), default=5, low=1, high=20)
        context.update(rows=bench.run_benchmark(sizes, runs=runs), runs=runs)
    return render(request, "vault/benchmark.html", context)


def _bounded_int(raw, default, low, high):
    try:
        return max(low, min(int(raw), high))
    except (TypeError, ValueError):
        return default


STEPS = [
    {
        "category": storage.PROFILE,
        "title": "Personal details",
        "why": "We use these details to check who you are and to match you against your ID card.",
        "kind": "General and financial personal data",
        "url": "vault_profile",
        "action": "Fill in",
    },
    {
        "category": storage.ID_CARD,
        "title": "ID card (e-KTP)",
        "why": "A photo of your e-KTP proves who you are. It carries your face photo, signature and religion.",
        "kind": "Biometric data (face, signature)",
        "slug": "id-card",
        "action": "Upload",
    },
    {
        "category": storage.OFFICE,
        "title": "Proof of income",
        "why": "A payslip, employer letter or tax return (PDF, DOC, XLS) shows that you can repay a loan.",
        "kind": "Personal financial data",
        "slug": "office",
        "action": "Upload",
    },
    {
        "category": storage.VIDEO,
        "title": "Liveness video",
        "why": "A short selfie video confirms a real person is applying and matches the face on your ID.",
        "kind": "Biometric data (face, voice)",
        "slug": "video",
        "action": "Upload",
    },
]
STEP_BY_SLUG = {s["slug"]: s for s in STEPS if "slug" in s}
PROFILE_STEP = STEPS[0]


LOAN_STEP = {
    "kind": "Personal financial data",
    "why": "Tell us how much you want to borrow. You can only apply once every KYC step is done.",
}

UPLOAD_SLUGS = {
    "id-card": (storage.ID_CARD, "Upload ID card image"),
    "office": (storage.OFFICE, "Upload office document"),
    "video": (storage.VIDEO, "Upload liveness video"),
}


@vault_unlocked
def dashboard(request, muk):
    entries = storage.list_entries(request.user, muk)
    steps = []
    for number, step in enumerate(STEPS, start=1):
        items = [e for e in entries if e["category"] == step["category"]]
        if step["category"] == storage.VIDEO and live.enabled():
            step = {**step, "action": "Open camera"}
        steps.append({**step, "number": number, "items": items, "done": bool(items)})
    done = sum(1 for step in steps if step["done"])
    complete = done == len(steps)
    loan = storage.load_loan(request.user, muk) if complete else None
    if loan:
        loan["purpose_label"] = dict(LoanForm.PURPOSES).get(loan["purpose"], loan["purpose"])
    loan_items = [e for e in entries if e["category"] == storage.LOAN]
    context = {
        "steps": steps,
        "loan": loan,
        "loan_items": loan_items,
        "loan_why": LOAN_STEP["why"],
        "done": done,
        "total": len(steps),
        "percent": done * 100 // len(steps),
        "complete": complete,
        "ciphers": ce.CIPHERS,
    }
    return render(request, "vault/dashboard.html", context)


@vault_unlocked
def profile(request, muk):
    existing = storage.load_profile(request.user, muk)
    if request.method == "POST":
        form = ProfileForm(request.POST)
        if form.is_valid():
            storage.store_profile(request.user, muk, form.to_fields())
            messages.success(request, "Personal data saved, encrypted with AES, DES and RC4.")
            return redirect("vault_dashboard")
        return render(request, "vault/profile.html", {"form": form, "step": PROFILE_STEP}, status=400)
    context = {"form": ProfileForm(initial=existing), "has_profile": bool(existing), "step": PROFILE_STEP}
    return render(request, "vault/profile.html", context)


@vault_unlocked
def upload(request, muk, slug):
    if slug not in UPLOAD_SLUGS:
        raise Http404
    category, title = UPLOAD_SLUGS[slug]
    if category == storage.VIDEO and live.enabled():
        return redirect("vault_liveness")
    if request.method == "POST":
        form = UploadForm(request.POST, request.FILES, category=category)
        if form.is_valid():
            f = form.cleaned_data["file"]
            data = b"".join(f.chunks())
            try:
                storage.store_file(request.user, muk, category, f.name, data)
            except storage.UploadRejected as exc:
                form.add_error("file", str(exc))
            else:
                messages.success(request, f"{STEP_BY_SLUG[slug]['title']} stored, encrypted with AES, DES and RC4.")
                return redirect("vault_dashboard")
        return render(request, "vault/upload.html", {"form": form, "title": title, "step": STEP_BY_SLUG[slug]}, status=400)
    return render(
        request, "vault/upload.html", {"form": UploadForm(category=category), "title": title, "step": STEP_BY_SLUG[slug]}
    )


LIVENESS_CHALLENGE_TTL = 120
LIVENESS_ATTEMPTS = 10  # per hour


def _json_error(message, status):
    return JsonResponse({"error": message}, status=status)


@vault_unlocked
def liveness(request, muk):
    if not live.enabled():
        return redirect("vault_upload", slug="video")
    return render(request, "vault/liveness.html", {"step": STEP_BY_SLUG["video"], "title": "Record liveness video"})


@require_POST
@vault_unlocked
def liveness_challenge(request, muk):
    if not live.enabled():
        raise Http404
    try:
        challenge, question = live.get_engine().new_challenge()
    except Exception:
        log.exception("liveness engine unavailable")
        return _json_error("The check is unavailable right now. Please try again later.", 503)
    request.session["liveness"] = {"challenge": challenge, "question": question, "issued": time.time()}
    text = question[0] if isinstance(question, (list, tuple)) else question
    return JsonResponse({"instruction": text})


@require_POST
@vault_unlocked
def liveness_submit(request, muk):
    """Check the challenge on the uploaded video; store it encrypted only if it passes."""
    if not live.enabled():
        raise Http404
    state = request.session.pop("liveness", None)  # single use
    if not state or time.time() - state["issued"] > LIVENESS_CHALLENGE_TTL:
        return _json_error("That challenge expired. Please start again.", 400)
    key = f"liveness:{request.user.pk}"
    tries = cache.get(key, 0)
    if tries >= LIVENESS_ATTEMPTS:
        return _json_error("Too many attempts. Please try again in an hour.", 429)
    cache.set(key, tries + 1, 3600)

    upload_file = request.FILES.get("video")
    if upload_file is None:
        return _json_error("The video upload was incomplete. Please try again.", 400)
    data = b"".join(upload_file.chunks())
    filename = storage.clean_filename(upload_file.name)
    try:
        storage.validate_file(storage.VIDEO, filename, len(data), data)
    except storage.UploadRejected as exc:
        return _json_error(str(exc), 400)

    try:
        frames = live.extract_frames(data)
        result = live.get_engine().check(frames, state["challenge"], state["question"])
    except live.VideoUnreadable as exc:
        return _json_error(str(exc), 400)
    except Exception:
        log.exception("liveness check failed")
        return _json_error("The check is unavailable right now. Please try again later.", 503)
    if not result.passed:
        return JsonResponse({"passed": False, "message": "We could not confirm the instruction. Face the camera in good light and try again."})

    storage.store_file(request.user, muk, storage.VIDEO, filename, data)
    messages.success(request, f"{STEP_BY_SLUG['video']['title']} stored, encrypted with AES, DES and RC4.")
    return JsonResponse({"passed": True, "redirect": reverse("vault_dashboard")})


@vault_unlocked
def download(request, muk, object_id):
    cipher = request.GET.get("cipher", "aes")
    if cipher not in ce.CIPHERS:
        return HttpResponseBadRequest("Unknown cipher.")
    try:
        item = storage.load_object(request.user, muk, object_id, cipher)
    except storage.ObjectNotFound:
        raise Http404
    except ce.IntegrityError:
        return render(request, "vault/integrity_error.html", {"cipher": cipher.upper()}, status=409)
    resp = HttpResponse(item.data, content_type=item.mime)
    resp["Content-Disposition"] = content_disposition_header(True, item.filename)
    resp["X-Content-Type-Options"] = "nosniff"
    resp["Cache-Control"] = "no-store"
    resp["Server-Timing"] = (
        f"io;dur={item.io_ns / 1e6:.3f}, unwrap;dur={item.unwrap_ns / 1e6:.3f}, "
        f"decrypt;dur={item.decrypt_ns / 1e6:.3f}, verify;dur={item.verify_ns / 1e6:.3f}"
    )
    return resp


@require_POST
@vault_unlocked
def delete(request, muk, object_id):
    try:
        storage.delete_object(request.user, object_id)
    except storage.ObjectNotFound:
        raise Http404
    messages.success(request, "Item deleted.")
    return redirect("vault_dashboard")


@vault_unlocked
def loan(request, muk):
    if storage.kyc_missing(request.user):
        messages.warning(request, "Finish all four KYC steps before requesting a loan.")
        return redirect("vault_dashboard")
    if request.method == "POST":
        form = LoanForm(request.POST)
        if form.is_valid():
            try:
                storage.store_loan(request.user, muk, form.cleaned_data["amount"], form.cleaned_data["purpose"])
            except storage.LoanRejected as exc:
                messages.error(request, str(exc))
                return redirect("vault_dashboard")
            messages.success(request, "Loan request sent.")
            return redirect("vault_dashboard")
        return render(request, "vault/loan.html", {"form": form, "step": LOAN_STEP}, status=400)
    return render(request, "vault/loan.html", {"form": LoanForm(), "step": LOAN_STEP})

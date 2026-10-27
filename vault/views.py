import functools
import time
import uuid

from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import redirect_to_login
from django.shortcuts import render

from . import bench, keys, sealing, service
from . import crypto_engine as ce

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

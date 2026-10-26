import os
import time
import uuid

from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from . import bench, keys, sealing
from . import crypto_engine as ce

MAX_UPLOAD_BYTES = 64 * 1024 * 1024


@login_required
def encrypt_demo(request):
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

    muk = os.urandom(keys.MUK_SIZE)  # replaced by the logged-in user's key in the next commit
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


@login_required
def benchmark(request):
    if request.method != "POST":
        return render(request, "vault/benchmark.html")
    try:
        runs = max(1, min(int(request.POST.get("runs", 5)), 20))
    except ValueError:
        runs = 5
    chosen = request.POST.getlist("sizes")
    sizes = {k: v for k, v in bench.DEFAULT_SIZES.items() if k in chosen} or {"1 MB": 1024**2}
    rows = bench.run_benchmark(sizes, runs=runs)
    return render(request, "vault/benchmark.html", {"rows": rows, "runs": runs, "env": bench.environment()})

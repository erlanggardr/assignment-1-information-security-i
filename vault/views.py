import time

from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from . import bench
from . import crypto_engine as ce

MAX_UPLOAD_BYTES = 64 * 1024 * 1024


@login_required
def encrypt_demo(request):
    if request.method != "POST":
        return render(request, "vault/demo.html")

    password = request.POST.get("password", "")
    upload = request.FILES.get("file")
    data = upload.read() if upload else request.POST.get("text", "").encode("utf-8")
    error = None
    if not password:
        error = "Password is required."
    elif not data:
        error = "Provide a file or some text."
    elif len(data) > MAX_UPLOAD_BYTES:
        error = "File is larger than 64 MB."
    if error:
        return render(request, "vault/demo.html", {"error": error}, status=400)

    keys = ce.derive_user_keys(password, ce.new_salt())
    digest, results = ce.encrypt_all(data, keys)
    rows = []
    for name in ce.CIPHERS:
        res = results[name]
        t0 = time.perf_counter_ns()
        try:
            ce.decrypt_and_verify(name, res.blob, keys, digest)
            intact = True
        except ce.IntegrityError:
            intact = False
        dec_ns = time.perf_counter_ns() - t0
        rows.append({
            "cipher": name.upper(),
            "enc_ms": res.encrypt_ns / 1e6,
            "dec_ms": dec_ns / 1e6,
            "size": res.size,
            "overhead": res.size - len(data),
            "intact": intact,
            "preview": res.blob[:24].hex() + "...",
        })
    return render(request, "vault/demo.html", {"rows": rows, "plain_size": len(data), "digest": digest})


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

import csv
import os
import tempfile

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.test import override_settings

from vault import bench, bench_vault, keys, storage


def sample_files(video_mb):
    body = os.urandom
    return [
        (storage.ID_CARD, "ktp.png", b"\x89PNG\r\n\x1a\n" + body(1_500_000)),
        (storage.OFFICE, "slip_gaji.pdf", b"%PDF-1.7\n" + body(500_000)),
        (storage.OFFICE, "laporan.xlsx", b"PK\x03\x04" + body(200_000)),
        (storage.VIDEO, "liveness.mp4", b"\x00\x00\x00\x18ftypmp42" + body(video_mb * 1024 * 1024)),
    ]


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)


class Command(BaseCommand):
    help = "Download stored items many times per cipher and compare the ciphertexts"

    def add_arguments(self, parser):
        parser.add_argument("--downloads", type=int, default=20)
        parser.add_argument("--video-mb", type=int, default=20)
        parser.add_argument("--out", default="bench_out")

    def handle(self, *args, **opts):
        os.makedirs(opts["out"], exist_ok=True)
        muk = os.urandom(keys.MUK_SIZE)
        with tempfile.TemporaryDirectory() as media, override_settings(MEDIA_ROOT=media):
            user = get_user_model().objects.create_user("bench_tmp")
            try:
                storage.store_profile(
                    user, muk, {"full_name": "Budi Santoso", "nik": "3174010101900001", "net_worth": "250000000"}
                )
                for category, name, data in sample_files(opts["video_mb"]):
                    storage.store_file(user, muk, category, name, data)
                rows = bench_vault.run_item_downloads(user, muk, opts["downloads"])
            finally:
                user.delete()

        self.stdout.write(f"{bench.environment()} | median of {opts['downloads']} downloads\n")
        self.stdout.write(f"{'item':<18}{'size KB':>9} {'cipher':>6}{'io':>9}{'key':>8}{'decrypt':>10}{'verify':>9}{'total':>10}{'MB/s':>9}")
        for r in rows:
            self.stdout.write(
                f"{r['item']:<18}{r['bytes'] / 1024:9.0f} {r['cipher']:>6}{r['io_ms']:9.3f}{r['key_ms']:8.3f}"
                f"{r['decrypt_ms']:10.3f}{r['verify_ms']:9.3f}{r['total_ms']:10.3f}{r['mb_s']:9.1f}"
            )
        write_csv(os.path.join(opts["out"], "downloads.csv"), rows)

        analysis = bench_vault.compare_ciphertexts()
        self.stdout.write("\nsame plaintext encrypted twice with the same key")
        self.stdout.write(f"{'sample':<15}{'cipher':>6}{'plain H':>9}{'cipher H':>10}{'overhead':>10}{'same?':>7}{'equal %':>9}")
        for r in analysis:
            self.stdout.write(
                f"{r['sample']:<15}{r['cipher']:>6}{r['plain_entropy']:9.3f}{r['cipher_entropy']:10.4f}"
                f"{r['overhead']:10d}{str(r['same_output']):>7}{r['equal_pct']:9.3f}"
            )
        write_csv(os.path.join(opts["out"], "ciphertext.csv"), analysis)
        self.stdout.write(f"\nCSV written to {opts['out']}/")

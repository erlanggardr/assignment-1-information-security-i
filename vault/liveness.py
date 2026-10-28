"""Liveness check on the selfie video, using the models from github.com/manhcuong02/eKYC.

That repo is a desktop app, so only its model classes are imported. The browser records one
video; the same bytes are checked here and, if the check passes, stored encrypted. Frames only
exist in memory and are never written to disk.
"""

import io
import logging
import sys
import threading
from functools import lru_cache
from pathlib import Path

import numpy as np
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

log = logging.getLogger(__name__)

MAX_FRAMES = 600  # about 20 s at 30 fps
SAMPLE_EVERY = 2
FRAME_SIDE = 640
MIN_FACE_PROB = 0.9
BLINK_CONSEC_FRAMES = 2  # the repo uses 3, which misses short blinks at ~15 fps
# a pose only counts after a neutral state, otherwise one still photo passes smile/turn
NEEDS_CHANGE = ("smile", "surprise", "right", "left")


class LivenessError(Exception):
    pass


class VideoUnreadable(LivenessError):
    pass


def enabled() -> bool:
    return settings.LIVENESS_ENGINE == "ekyc"


def extract_frames(data: bytes) -> list:
    """Decode the video into RGB frames (every SAMPLE_EVERY-th, downscaled)."""
    import cv2

    buf = io.BytesIO(data)  # must outlive the capture: release() touches it and segfaults otherwise
    cap = cv2.VideoCapture(buf, cv2.CAP_FFMPEG, [])
    if not cap.isOpened():
        raise VideoUnreadable("The video could not be decoded.")
    frames, seen = [], 0
    try:
        while True:
            ok, bgr = cap.read()
            if not ok:
                break
            seen += 1
            if seen > MAX_FRAMES:
                raise VideoUnreadable("The video is too long.")
            if seen % SAMPLE_EVERY:
                continue
            h, w = bgr.shape[:2]
            scale = FRAME_SIDE / max(h, w)
            if scale < 1:
                bgr = cv2.resize(bgr, (round(w * scale), round(h * scale)), interpolation=cv2.INTER_AREA)
            frames.append(cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB))
    finally:
        cap.release()
    if not frames:
        raise VideoUnreadable("The video has no frames.")
    return frames


class Result:
    def __init__(self, passed, frames, with_face, detail):
        self.passed, self.frames, self.with_face, self.detail = passed, frames, with_face, detail


class Engine:
    def __init__(self, root: Path):
        if not (root / "liveness_detection").is_dir():
            raise ImproperlyConfigured(f"eKYC repository not found at {root} (see README).")
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        try:
            import torch
            import challenge_response as cr
            from facenet.models.mtcnn import MTCNN
            from liveness_detection.blink_detection import BlinkDetector
            from liveness_detection.emotion_prediction import EmotionPredictor
            from liveness_detection.face_orientation import FaceOrientationDetector
            from utils.functions import extract_face
        except ImportError as exc:
            raise ImproperlyConfigured(f"Could not import the eKYC models ({exc}).") from exc

        self._torch, self._cr, self._extract_face = torch, cr, extract_face
        self._BlinkDetector = BlinkDetector
        self._lock = threading.Lock()  # one inference at a time bounds RAM and CPU
        device = "cuda" if torch.cuda.is_available() else "cpu"
        self.mtcnn = MTCNN(device=torch.device(device))
        self.emotion = EmotionPredictor(device=device)
        self.orientation = FaceOrientationDetector()

    def new_challenge(self):
        return self._cr.get_challenge_and_question()

    def _observe(self, frame, challenge, question, blink):
        """None when no face is visible, else (done, neutral)."""
        face, box, landmarks = self._extract_face(frame, self.mtcnn, padding=10, min_prob=MIN_FACE_PROB)
        if box is None or face is None or face.size == 0:
            return None
        if challenge in ("smile", "surprise"):
            label = self.emotion.predict(face)
            return label == challenge, label == "neutral"
        if challenge in ("right", "left", "front"):
            label = self.orientation.detect(landmarks)
            return label == challenge, label == "front"
        if challenge == "blink eyes":
            return bool(self._cr.blink_response(frame, box, question, blink)), False
        raise LivenessError(f"Unknown challenge {challenge!r}")

    def check(self, frames, challenge, question) -> Result:
        with_face = errors = 0
        needs_change = challenge in NEEDS_CHANGE
        seen_neutral = pose_without_neutral = False
        with self._lock, self._torch.no_grad():
            blink = self._BlinkDetector()  # keeps counters between frames
            blink.EYE_AR_CONSEC_FRAMES = BLINK_CONSEC_FRAMES
            for frame in frames:
                # the repo's GUI mirrors the camera, so "turn right" is judged on a mirrored frame
                mirrored = np.ascontiguousarray(frame[:, ::-1])
                try:
                    seen = self._observe(mirrored, challenge, question, blink)
                except LivenessError:
                    raise
                except Exception:
                    errors += 1
                    log.debug("frame skipped", exc_info=True)
                    continue
                if seen is None:
                    continue
                with_face += 1
                done, neutral = seen
                if done:
                    if not needs_change or seen_neutral:
                        return Result(True, len(frames), with_face, "challenge completed")
                    pose_without_neutral = True
                elif neutral:
                    seen_neutral = True
        detail = "challenge not completed"
        if pose_without_neutral:
            detail = "pose seen without a neutral state first"
        if errors:
            detail += f" ({errors} frames raised detector errors)"
        return Result(False, len(frames), with_face, detail)


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    return Engine(Path(settings.EKYC_PATH))

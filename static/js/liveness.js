// Records a short video while the user follows a server-chosen instruction, then uploads it.
// The server decides; nothing here is trusted. The preview is mirrored with CSS only.
(() => {
  const root = document.getElementById("liveness");
  if (!root) return;

  const SECONDS = 7;
  const csrf = root.querySelector("[name=csrfmiddlewaretoken]").value;
  const video = document.getElementById("camera");
  const instruction = document.getElementById("instruction");
  const status = document.getElementById("status");
  const button = document.getElementById("start-btn");
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  async function post(url, body) {
    const response = await fetch(url, { method: "POST", body, headers: { "X-CSRFToken": csrf }, credentials: "same-origin" });
    let data = null;
    try {
      data = await response.json();
    } catch (_) {
      // an HTML error page, e.g. the session expired
    }
    return { ok: response.ok, data };
  }

  function record(stream) {
    const type = ["video/webm;codecs=vp8", "video/webm", "video/mp4"].find((t) => MediaRecorder.isTypeSupported(t));
    const recorder = new MediaRecorder(stream, type ? { mimeType: type } : undefined);
    const chunks = [];
    return new Promise((resolve) => {
      recorder.ondataavailable = (e) => e.data.size && chunks.push(e.data);
      recorder.onstop = () => resolve(new Blob(chunks, { type: recorder.mimeType }));
      recorder.start();
      setTimeout(() => recorder.stop(), SECONDS * 1000);
    });
  }

  async function run() {
    button.hidden = true;
    status.textContent = "";
    let stream;
    try {
      if (!navigator.mediaDevices || !window.MediaRecorder) {
        status.textContent = "This browser cannot record video. The camera also needs HTTPS or localhost.";
        return;
      }
      status.textContent = "Starting the camera...";
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user" }, audio: false });
      video.srcObject = stream;
      await video.play();
      status.textContent = "";

      const challenge = await post(root.dataset.challengeUrl);
      if (!challenge.ok || !challenge.data) {
        status.textContent = (challenge.data && challenge.data.error) || "Could not start the check. Reload the page and sign in again.";
        return;
      }
      instruction.textContent = "Look at the camera and hold still";
      await sleep(2000);
      instruction.textContent = challenge.data.instruction;
      const blob = await record(stream);

      instruction.textContent = "Checking...";
      const body = new FormData();
      body.append("video", blob, "liveness." + (blob.type.includes("mp4") ? "mp4" : "webm"));
      const result = await post(root.dataset.submitUrl, body);
      const data = result.data || {};
      if (data.passed) {
        window.location.assign(data.redirect);
        return;
      }
      instruction.textContent = "Not quite";
      status.textContent = data.message || data.error || "The check failed. Please try again.";
    } catch (err) {
      status.textContent = err && err.name === "NotAllowedError" ? "Camera permission was denied." : "Could not use the camera.";
    } finally {
      if (stream) stream.getTracks().forEach((t) => t.stop());
      video.srcObject = null;
      button.hidden = false;
      button.textContent = "Try again";
    }
  }

  button.addEventListener("click", run);
  run();
})();

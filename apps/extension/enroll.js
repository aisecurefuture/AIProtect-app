import { joinDevice, enrollDevice, saveEnrollment } from "./src/api.js";

const msg = document.getElementById("msg");
const show = (text) => { msg.textContent = text; };

document.getElementById("join").addEventListener("click", async () => {
  const code = document.getElementById("code").value.trim().toUpperCase();
  if (!code) return show("Enter the code from your other install.");
  show("Joining…");
  const res = await joinDevice(code);
  if (!res.ok) return show(res.body?.detail?.reason || res.body?.reason || "That code didn't work.");
  await saveEnrollment({
    credential: res.body.credential, deviceId: res.body.device.id,
  });
  show(`Done. This browser joined “${res.body.device.name}” and didn't use another device slot.`);
});

document.getElementById("enroll").addEventListener("click", async () => {
  const name = document.getElementById("name").value.trim();
  if (!name) return show("Give this computer a name.");
  show("Setting up…");
  const res = await enrollDevice(name);
  if (!res.ok) {
    const d = res.body?.detail ?? res.body;
    // At the cap the API refuses and names the upgrade -- there is no
    // per-device add-on, so that is the only route to more devices.
    return show(d?.reason || "We couldn't set this up.");
  }
  if (res.body.needs_confirmation) {
    return show(res.body.question + " Open the dashboard to confirm.");
  }
  await saveEnrollment({
    credential: res.body.credential, deviceId: res.body.device.id,
  });
  show("Done. This browser is protected.");
});

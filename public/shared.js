async function deviceLogin(deviceId, deviceSecret) {
  const res = await fetch("/api/auth/device", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ deviceId, deviceSecret })
  });
  if (!res.ok) {
    const err = await res.json().catch(()=>({error:"unknown"}));
    throw new Error(err.error || "auth_failed");
  }
  const data = await res.json();
  localStorage.setItem("token", data.token);
  localStorage.setItem("device", JSON.stringify(data.device));
  return data;
}

function getToken() {
  return localStorage.getItem("token");
}

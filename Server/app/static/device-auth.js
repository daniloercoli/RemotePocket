// SCRAM-SHA-256 proof construction, with literal UTF-8 passwords (no SASLprep).
const DeviceAuth = (() => {
  const encode = value => btoa(String.fromCharCode(...value));
  const decode = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));
  const utf8 = value => new TextEncoder().encode(value);
  async function hmac(key, message) {
    const imported = await crypto.subtle.importKey("raw", key,
      {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", imported, message));
  }
  async function proof(key, challenge) {
    const {deviceId, clientNonce, nonce, salt, iterations} = challenge;
    const saltBytes = decode(salt);
    if (saltBytes.length !== 16 || !Number.isInteger(iterations) || iterations < 4096 || iterations > 1000000) {
      throw new Error("Parametri di autenticazione non validi.");
    }
    const name = deviceId.replace(/=/g, "=3D").replace(/,/g, "=2C");
    const transcript = utf8(`n=${name},r=${clientNonce},r=${nonce},s=${salt},i=${iterations},c=biws,r=${nonce}`);
    const salted = new Uint8Array(await crypto.subtle.deriveBits(
      {name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations}, key, 256));
    let clientKey, serverKey;
    try {
      clientKey = await hmac(salted, utf8("Client Key"));
      serverKey = await hmac(salted, utf8("Server Key"));
      const storedKey = new Uint8Array(await crypto.subtle.digest("SHA-256", clientKey));
      const signature = await hmac(storedKey, transcript);
      return {
        proof: encode(clientKey.map((byte, index) => byte ^ signature[index])),
        serverProof: encode(await hmac(serverKey, transcript)),
      };
    } finally {
      salted.fill(0);
      clientKey?.fill(0);
      serverKey?.fill(0);
    }
  }
  return {
    nonce: () => Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, "0")).join(""),
    importPassword: bytes => crypto.subtle.importKey("raw", bytes, "PBKDF2", false, ["deriveBits"]),
    proof,
  };
})();

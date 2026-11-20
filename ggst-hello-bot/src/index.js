function hexToBytes(hex) {
  const clean = hex.trim();
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return bytes;
}

async function verifyDiscordSignature(rawBody, signatureHex, timestamp, publicKeyHex) {
  try {
    const keyData = hexToBytes(publicKeyHex);
    const signature = hexToBytes(signatureHex);
    const message = new TextEncoder().encode(timestamp + rawBody);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "Ed25519" },
      false,
      ["verify"]
    );

    return await crypto.subtle.verify("Ed25519", cryptoKey, signature, message);
  } catch {
    return false;
  }
}

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const signature = request.headers.get("X-Signature-Ed25519") || "";
    const timestamp = request.headers.get("X-Signature-Timestamp") || "";
    const rawBody = await request.text();

    const isValid = await verifyDiscordSignature(
      rawBody,
      signature,
      timestamp,
      env.DISCORD_PUBLIC_KEY
    );

    if (!isValid) {
      return new Response("Bad request signature", { status: 401 });
    }

    const interaction = JSON.parse(rawBody);

    // Discordからの疎通確認（PING）にPONGを返す
    if (interaction.type === 1) {
      return Response.json({ type: 1 });
    }

    // 「/hello」が打たれたら「hellow bot」と返す
    if (interaction.type === 2 && interaction.data?.name === "hello") {
      return Response.json({
        type: 4,
        data: {
          content: "hellow bot",
        },
      });
    }

    return new Response("Unknown interaction", { status: 400 });
  },
};
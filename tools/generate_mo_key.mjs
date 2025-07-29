// generate-keypair.mjs
import { generateKeyPair, exportJWK, calculateJwkThumbprint } from "jose";
import fs from "fs/promises";

const { publicKey, privateKey } = await generateKeyPair("ES256");

const publicJwk = await exportJWK(publicKey);
const privateJwk = await exportJWK(privateKey);

const kid = await calculateJwkThumbprint(publicJwk);
publicJwk.kid = kid;
privateJwk.kid = kid;
publicJwk.alg = "ES256";
privateJwk.alg = "ES256";

// Write to disk
await fs.mkdir("../dids/fake_go_did", { recursive: true });
await fs.writeFile("../dids/fake_go_did/go_private_key_jwk.json", JSON.stringify(privateJwk, null, 2));
await fs.writeFile("../dids/fake_go_did/go_public_key_jwk.json", JSON.stringify(publicJwk, null, 2));

console.log("✅ Generated new JWK key pair with kid:", kid);


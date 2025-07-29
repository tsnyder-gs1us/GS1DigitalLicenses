// issue_vc_jwk.js
import * as transmute from "@transmute/verifiable-credentials";
import * as jose from "jose";
import moment from "moment";
import fs from "fs/promises";

async function main() {
  const alg = "ES256";
  const statusListSize = 131072;
  const revocationIndex = 94567;
  const suspensionIndex = 23452;
  const baseURL = "https://vendor.example/api";

  // Load keys
  const privateKeyJwk = JSON.parse(
    await fs.readFile("../dids/fake_go_did/go_private_key_jwk.json", "utf-8")
  );
  const publicKeyJwk = JSON.parse(
    await fs.readFile("../dids/fake_go_did/go_public_key_jwk.json", "utf-8")
  );

  const issuer = "did:web:woodycreek.github.io:GS1DigitalLicenses:dids:fake_go_did";

  console.log("Public JWK for jwt.io:");
  console.log(JSON.stringify(publicKeyJwk, null, 2));

  const issuerSigner = {
    sign: async (bytes) => {
      // Use jose directly to avoid encoding confusion
      const keyLike = await jose.importJWK(privateKeyJwk, alg);

      const jws = await new jose.CompactSign(bytes)
        .setProtectedHeader({ kid: privateKeyJwk.kid, alg: privateKeyJwk.alg })
        .sign(keyLike);

      return transmute.text.encoder.encode(jws);
    },
  };

  // Load sample credential JSON
  const credentialJson = await fs.readFile(
    "../samples/gs1-prefix-license-sample.json",
    "utf-8"
  );
  const claimset = transmute.text.encoder.encode(credentialJson);

  const issued = await transmute
    .issuer({
      alg,
      type: "application/vc-ld+jwt",
      signer: issuerSigner,
    })
    .issue({
      claimset,
    });

  console.log("Issued Credential (vc-ld+jwt):");
  console.log(new TextDecoder().decode(issued));
}

main().catch(console.error);
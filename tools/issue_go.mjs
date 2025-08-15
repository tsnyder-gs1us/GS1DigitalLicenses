// issue_vc_jwk.js
import * as transmute from "@transmute/verifiable-credentials";
import * as jose from "jose";
import moment from "moment";
import fs from "fs/promises";

async function main() {
  const alg = "ES256";

  // Load keys
  const privateKeyJwk = JSON.parse(
    await fs.readFile("../dids/fake_go_did/go_private_key_jwk.json", "utf-8")
  );
  const publicKeyJwk = JSON.parse(
    await fs.readFile("../dids/fake_go_did/go_public_key_jwk.json", "utf-8")
  );

  const issuer = "did:web:gs1.github.io:GS1DigitalLicenses:dids:fake_go_did";

  console.log("Public JWK for jwt.io:");
  console.log(JSON.stringify(publicKeyJwk, null, 2));

  const issuerSigner = {
    sign: async (bytes) => {
      // Use jose directly to avoid encoding confusion
      const keyLike = await jose.importJWK(privateKeyJwk, alg);

      const fullKid = `${issuer}#${privateKeyJwk.kid}`;

      const jws = await new jose.CompactSign(bytes)
        .setProtectedHeader({ kid: fullKid, alg: privateKeyJwk.alg })
        .sign(keyLike);

      return transmute.text.encoder.encode(jws);
    },
  };

  const inputFiles = [
    "../jsons/gs1-prefix-license-sample.json",
    "../jsons/gtin8-prefix-sample.json",
  ];

  for (const filePath of inputFiles) {
    try {
      const json = await fs.readFile(filePath, "utf-8");
      const claimset = transmute.text.encoder.encode(json);

      const issued = await transmute
        .issuer({
          alg,
          type: "application/vc-ld+jwt",
          signer: issuerSigner,
        })
        .issue({ claimset });

      const jwt = new TextDecoder().decode(issued);
      console.log(`Issued JWT for ${filePath}:\n${jwt}`);

      const outputPath = filePath.replace(/jsons/, "samples").replace(/\.json$/, ".jwt");
      await fs.writeFile(outputPath, jwt, "utf-8");
    } catch (err) {
      console.error(`❌ Failed to process ${filePath}:`, err);
    }
  }
}

main().catch(console.error);
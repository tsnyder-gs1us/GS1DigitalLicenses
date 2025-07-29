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

  const issuer = "did:web:woodycreek.github.io:GS1DigitalLicenses:dids:fake_go_did";

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

  // Load sample credential JSON
  const prefixCredentialJson = await fs.readFile(
    "../samples/gs1-prefix-license-sample.json",
    "utf-8"
  );
  const claimset_prefix = transmute.text.encoder.encode(prefixCredentialJson);

  const issued_prefix = await transmute
    .issuer({
      alg,
      type: "application/vc-ld+jwt",
      signer: issuerSigner,
    })
    .issue({
      claimset: claimset_prefix,
    });

  console.log("Issued Prefix Credential (vc-ld+jwt):");
  console.log(new TextDecoder().decode(issued_prefix));
  await fs.writeFile("../samples/gs1-prefix-license-sample.jwt", issued_prefix, "utf-8");

  // Load sample credential JSON
  const prefix8CredentialJson = await fs.readFile(
    "../samples/gtin8-prefix-sample.json",
    "utf-8"
  );

  const claimset_prefix8 = transmute.text.encoder.encode(prefix8CredentialJson);

  const issued_prefix8 = await transmute
    .issuer({
      alg,
      type: "application/vc-ld+jwt",
      signer: issuerSigner,
    })
    .issue({
      claimset: claimset_prefix8,
    });

  console.log("Issued Prefix8 Credential (vc-ld+jwt):");
  console.log(new TextDecoder().decode(issued_prefix8));
  await fs.writeFile("../samples/gtin8-prefix-sample.jwt", issued_prefix8, "utf-8");

}

main().catch(console.error);
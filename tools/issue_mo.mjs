// issue_vc_jwk.js
import * as transmute from "@transmute/verifiable-credentials";
import * as jose from "jose";
import moment from "moment";
import fs from "fs/promises";

async function main() {
  const alg = "ES256";

  // Load keys
  const privateKeyJwk = JSON.parse(
    await fs.readFile("../dids/fake_mo_did/mo_private_key_jwk.json", "utf-8")
  );
  const publicKeyJwk = JSON.parse(
    await fs.readFile("../dids/fake_mo_did/mo_public_key_jwk.json", "utf-8")
  );

  const issuer = "did:web:woodycreek.github.io:GS1DigitalLicenses:dids:fake_mo_did";

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
  const gcpCredentialJson = await fs.readFile(
    "../samples/gcp-sample.json",
    "utf-8"
  );
  const claimset_gcp = transmute.text.encoder.encode(gcpCredentialJson);

  const issued_gcp = await transmute
    .issuer({
      alg,
      type: "application/vc-ld+jwt",
      signer: issuerSigner,
    })
    .issue({
      claimset: claimset_gcp,
    });

  console.log("Issued GCP Credential (vc-ld+jwt):");
  console.log(new TextDecoder().decode(issued_gcp));
  await fs.writeFile("../samples/gcp-sample.jwt", issued_gcp, "utf-8");

  // Load sample credential JSON
  const idKeyCredentialJson = await fs.readFile(
    "../samples/id-key-license-sample.json",
    "utf-8"
  );
  const claimset_idkey = transmute.text.encoder.encode(idKeyCredentialJson);

  const issued_idkey = await transmute
    .issuer({
      alg,
      type: "application/vc-ld+jwt",
      signer: issuerSigner,
    })
    .issue({
      claimset: claimset_idkey,
    });

  console.log("Issued ID Key Credential (vc-ld+jwt):");
  console.log(new TextDecoder().decode(issued_idkey));
  await fs.writeFile("../samples/id-key-license-sample.jwt", issued_idkey, "utf-8");

  // Load sample credential JSON
  const idKey8CredentialJson = await fs.readFile(
    "../samples/gtin8-id-key-license-sample.json",
    "utf-8"
  );
  const claimset_idkey8 = transmute.text.encoder.encode(idKey8CredentialJson);

  const issued_idkey8 = await transmute
    .issuer({
      alg,
      type: "application/vc-ld+jwt",
      signer: issuerSigner,
    })
    .issue({
      claimset: claimset_idkey8,
    });

  console.log("Issued ID Key Credential (vc-ld+jwt):");
  console.log(new TextDecoder().decode(issued_idkey8));
  await fs.writeFile("../samples/gtin8-id-key-license-sample.jwt", issued_idkey8, "utf-8");


}

main().catch(console.error);
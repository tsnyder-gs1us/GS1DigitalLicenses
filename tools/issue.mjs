// complete-issue-v2.js
import * as transmute from "@transmute/verifiable-credentials";
import * as jose from "jose";
import moment from "moment";
import fs from "fs/promises";

async function main() {
  const alg = `ES256`;
  const statusListSize = 131072;
  const revocationIndex = 94567;
  const suspensionIndex = 23452;
  const issuer = `did:example:123`;
  const baseURL = `https://vendor.example/api`;

  const privateKey = await transmute.key.generate({
    alg,
    type: "application/jwk+json",
  });
  const publicKey = await transmute.key.publicFromPrivate({
    type: "application/jwk+json",
    content: privateKey,
  });


  console.log("Public JWK for jwt.io:");
  const jwkObj = JSON.parse(new TextDecoder().decode(publicKey));
  console.log(JSON.stringify(jwkObj, null, 2));

  const issuerSigner = {
    sign: async (bytes) => {
      const jws = await new jose.CompactSign(bytes)
        .setProtectedHeader({ kid: `${issuer}#key-42`, alg })
        .sign(
          await transmute.key.importKeyLike({
            type: "application/jwk+json",
            content: privateKey,
          })
        );
      return transmute.text.encoder.encode(jws);
    },
  };

  const credentialJson = await fs.readFile("../samples/gs1-prefix-license-sample.json", "utf-8");
  const claimset = transmute.text.encoder.encode(credentialJson);

  const issued = await transmute
    .issuer({
      alg,
      type: "application/vc-ld+jwt",
      signer: issuerSigner,
    })
    .issue({
      claimset: claimset,
    });

  console.log("Issued Credential (vc-ld+jwt):");
  console.log(new TextDecoder().decode(issued));
}

main().catch(console.error);

// complete-issue-v2.js
import * as transmute from "@transmute/verifiable-credentials";
import * as jose from "jose";
import moment from "moment";

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

  const yaml = `
"@context":
  - https://www.w3.org/ns/credentials/v2
  - https://www.w3.org/ns/credentials/examples/v2

id: ${baseURL}/credentials/3732
type:
  - VerifiableCredential
  - ExampleDegreeCredential
issuer:
  id: ${issuer}
  name: "Example University"
validFrom: ${moment().toISOString()}
credentialSchema:
  id: ${baseURL}/schemas/product-passport
  type: JsonSchema
credentialStatus:
  - id: ${baseURL}/credentials/status/3#${revocationIndex}
    type: BitstringStatusListEntry
    statusPurpose: revocation
    statusListIndex: "${revocationIndex}"
    statusListCredential: "${baseURL}/credentials/status/3"
  - id: ${baseURL}/credentials/status/4#${suspensionIndex}
    type: BitstringStatusListEntry
    statusPurpose: suspension
    statusListIndex: "${suspensionIndex}"
    statusListCredential: "${baseURL}/credentials/status/4"
credentialSubject:
  id: did:example:ebfeb1f712ebc6f1c276e12ec21
  degree:
    type: ExampleBachelorDegree
    subtype: Bachelor of Science and Arts
`.trim();

  const issued = await transmute
    .issuer({
      alg,
      type: "application/vc-ld+jwt",
      signer: issuerSigner,
    })
    .issue({
      claimset: transmute.text.encoder.encode(yaml),
    });

  console.log("Issued Credential (vc-ld+jwt):");
  console.log(new TextDecoder().decode(issued));
}

main().catch(console.error);

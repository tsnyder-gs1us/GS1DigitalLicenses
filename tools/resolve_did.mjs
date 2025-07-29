import { Resolver } from 'did-resolver';
import { getResolver as webDidResolver } from 'web-did-resolver';

const did = 'did:web:woodycreek.github.io:GS1DigitalLicenses:dids:fake_go_did';

const resolver = new Resolver({
  ...webDidResolver()
});

try {
  const result = await resolver.resolve(did);
  console.log('✅ DID Document resolved successfully:');
  console.dir(result.didDocument, { depth: null });

  const vm = result.didDocument.verificationMethod?.[0];
  if (vm?.publicKeyJwk) {
    console.log('✅ Public key found:', vm.publicKeyJwk);
  } else {
    console.warn('⚠️ No publicKeyJwk found in verificationMethod');
  }
} catch (err) {
  console.error('❌ DID resolution failed:', err);
}


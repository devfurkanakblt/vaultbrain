# Self-hosted sync relay

The Phase 6 relay is a deliberately small, opaque transport. It accepts only encrypted change envelopes, encrypted owner-signed device registries and encrypted owner-signed freshness checkpoints. It has no vault key and cannot read object types, device IDs, timestamps, note content or attachment bytes.

## Security boundary

- A bearer token of at least 32 bytes protects every vault endpoint. Supply it only through `SBRAIN_RELAY_TOKEN`; it is never accepted as a CLI argument.
- Vault, change and artifact routes use 64-character opaque IDs. Writes are content-addressed and immutable.
- Request size, total vault bytes, change count, pagination, header time and request time are bounded.
- Storage paths are containment-checked and symbolic links are rejected.
- The default listener is `127.0.0.1`. Put TLS and normal network access controls in front of it before binding to a non-loopback interface.
- The relay is still an availability adversary: it can delete, delay or withhold ciphertext. A pinned owner-signed checkpoint detects rollback or selective withholding of history covered by that checkpoint. Discovering a newer checkpoint still requires its ID through a trusted out-of-band channel or an independent witness.
- An enrolled device remains trusted with the plaintext it can decrypt. Epoch content-key rotation is not implemented, so revocation blocks new signed changes but does not revoke data the device already received.

## Start and use the relay

Generate a random token with a password manager or cryptographic random generator, then set it on both server and client:

```bash
export SBRAIN_RELAY_TOKEN='<at-least-32-random-bytes>'
sbrain --experimental-trusted-sync sync relay serve ./relay-data --port 8787
```

Create a freshness checkpoint immediately before publishing a known-good state, transfer its printed ID through a trusted channel, and push:

```bash
sbrain --experimental-trusted-sync --vault ./vault sync checkpoint create
sbrain --experimental-trusted-sync --vault ./vault sync relay push https://relay.example
```

An existing device can pull with its already pinned authority and checkpoint chain:

```bash
sbrain --experimental-trusted-sync --vault ./vault sync relay pull https://relay.example
```

The first pull into a restored encrypted vault backup must pin the expected enrollment authority. Pin the expected checkpoint as well to make relay withholding detectable on that first contact:

```bash
sbrain --experimental-trusted-sync --vault ./restored-vault sync relay pull https://relay.example \
  --authority <owner-authority-sha256> \
  --checkpoint <owner-checkpoint-sha256>
```

The restored directory must come from an encrypted vault backup and therefore contain the original key-derivation metadata. The relay is not a key escrow or a standalone backup and cannot bootstrap an empty directory or recover a lost passphrase.

## Recovery drill

`npm run recovery:drill` performs a disposable end-to-end exercise:

1. create an enrolled source vault and an encrypted offline backup;
2. add a later change and owner-signed checkpoint;
3. upload only opaque ciphertext to a temporary relay;
4. restore the offline backup, catch up from the relay and verify the pinned checkpoint;
5. assert that the relay files do not contain the test plaintext.

Run this gate before a release and retain the command output as drill evidence. It is an automated engineering drill, not a substitute for an independent security audit or a human-operated disaster-recovery exercise.

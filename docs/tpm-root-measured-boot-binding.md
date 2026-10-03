# TPM measured-boot binding for the independent capability root

The TPM NV monotonic root already rejects rollback of companion state and state copied to a different TPM device. That is not sufficient to prove that the same TPM is still executing under the same boot trust state.

This proof binds each committed TPM root state to a deterministic fingerprint of the live SHA-256 PCR values selected for the capability-root boot boundary:

```text
PCRs 0, 2, 4, 7
        |
        v
ordered SHA-256 digest binding
        |
        v
measured_boot_identity
        |
        +-- stored in root companion state
        +-- covered by the state digest
```

On provisioning, Aegis records both:

```text
TPM endorsement-derived device identity
TPM selected-PCR measured-boot identity
```

On every root recovery and Effect Boundary revalidation, both must still match the live TPM.

The governing invariant is:

```text
same TPM device
AND same monotonic NV generation
BUT selected measured-boot PCR state changed
        =>
old capability authority must not cross the Effect Boundary
```

## Executable falsification

The simulator proof uses one TPM instance and one NV root throughout:

1. provision the TPM monotonic root;
2. issue a valid capability permit;
3. verify the live endorsement-derived device identity matches the enrolled device identity;
4. extend SHA-256 PCR 7;
5. verify the endorsement-derived device identity is unchanged;
6. verify the measured-boot identity changed;
7. call `Current` and require `ErrTPMMonotonicRootMeasuredBootChanged`;
8. present the previously valid permit to the EGE Effect Boundary;
9. require `CAPABILITY_ROOT_MEASURED_BOOT_CHANGED`;
10. require mutation-controller calls to remain zero.

This distinguishes two independent coordinates:

```text
device replacement       -> CAPABILITY_ROOT_DEVICE_CHANGED
same device / PCR drift  -> CAPABILITY_ROOT_MEASURED_BOOT_CHANGED
```

The root state format advances to:

```text
aegis.ege/tpm-nv-monotonic-root/v3
```

Older companion state does not contain this measured-boot binding and is not silently accepted as v3 state.

## Claim boundary

This proof establishes Effect Boundary binding to the selected TPM SHA-256 PCR values in the TPM2 simulator model.

It does not prove:

- that PCRs 0, 2, 4, and 7 are sufficient for every production platform;
- TCG event-log replay for this capability-root path;
- that a compromised TPM implementation reports truthful PCR values;
- Secure Boot correctness;
- IMA PCR 10 continuity for this root;
- legitimate migration between measured-boot states;
- cross-device root migration.

Those remain separate proof obligations. The existing remote-attestation subsystem already contains quote, platform-event-log, and IMA replay machinery; this change does not duplicate that verifier inside the capability root.

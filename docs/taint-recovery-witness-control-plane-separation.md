# Taint recovery witness control-plane separation

Status: executable runtime-separation proof.

This layer strengthens the remote recovery witness added in PR #185. The earlier protocol proved that the recovery controller can operate with Authority A's private key while Witness B performs its own policy-gated co-signing behind HTTPS. This proof moves B into a second Kubernetes control plane and removes shared runtime administration from the execution path.

## Topology

```text
GitHub runner / recovery controller
  |
  | A private key
  | verified recovery trust root
  | B public identity
  |
  +---------------- HTTPS ----------------+
                                           |
                                           v
                                  witness KinD cluster B
                                  NodePort 30443
                                           |
                                           v
                                  taint-recovery-witness Pod
                                  - B private key Secret
                                  - immutable policy ConfigMap
                                  - immutable trust ConfigMap
                                  - read-only mounts
                                  - NO ServiceAccount token
```

The workload control plane and witness control plane use different Kubernetes API servers.

## Provisioning boundary

One-time CI provisioning authority creates:

- workload runtime credential in cluster A;
- capability-root runtime credential in cluster B;
- recovery-witness Secret containing B's private key and TLS key;
- immutable recovery-witness ConfigMap containing public trust material and policy;
- recovery-witness Deployment and NodePort Service;
- controller bundle containing A's private key, signed public trust material, witness CA, TLS server name, and the public policy coordinates.

The controller bundle does **not** contain B's private key.

The B private key is generated in provisioning memory and persisted only into the witness-cluster Secret.

After the witness Deployment passes an HTTPS readiness probe, CI deletes both administrator kubeconfigs and removes the default local kubeconfig.

The runtime proof then executes using only:

```text
workload-runtime-kubeconfig
witness-runtime-kubeconfig
controller bundle
HTTPS witness endpoint
```

## Signer process boundary

The witness Deployment sets:

```text
automountServiceAccountToken: false
```

The witness executable also refuses to start if this path exists:

```text
/var/run/secrets/kubernetes.io/serviceaccount/token
```

Therefore successful readiness proves that the running signer process does not carry a Kubernetes API token.

The signer receives its Secret and configuration through read-only projected volumes only.

## Runtime falsification

The dedicated integration proof runs after provisioning credentials are removed.

It checks:

```text
workload runtime token
  -> witness cluster Secret(B)
  -> UNAUTHORIZED / FORBIDDEN

witness root-writer token
  -> Secret(B)
  -> FORBIDDEN

witness root-writer token
  -> update recovery witness policy ConfigMap
  -> FORBIDDEN

witness root-writer token
  -> update signer Deployment
  -> FORBIDDEN
```

The controller then creates a valid A-only authorization and sends it over TLS to the live signer in cluster B.

For the policy-approved coordinates:

```text
A signature
  -> cluster B witness
  -> B policy ALLOW
  -> B co-signature
  -> RecoveryTrustRoot verification PASS
```

The controller then signs a second syntactically valid authorization with a different plan digest:

```text
valid A signature
  +
pinned A identity
  +
same live B endpoint
  +
plan outside B policy
        |
        v
HTTP 403
no B co-signature
```

This proves that B remains an authorization principal rather than a blind signing extension of A.

## CI anti-skip rule

The dedicated proof is executed with an explicit PASS assertion and treats any SKIP as failure.

The CI therefore cannot report this boundary as green merely because the required runtime environment was absent.

## What is proven

For the tested runtime topology:

- A and B execute in different processes;
- B executes inside a second Kubernetes control plane;
- the controller runtime does not receive B's private key;
- neither available runtime kubeconfig can read B's private-key Secret;
- the available witness runtime credential cannot mutate B's policy or signer Deployment;
- the B signer itself runs without a Kubernetes API token;
- B can independently reject a valid A-signed authorization;
- successful B output remains bound to the pinned recovery trust root and the existing nonce/commitment protocol.

## Claim boundary

The proof still does not establish separate organizational ownership.

The CI provisioning principal initially creates both control planes and both identities. A repository/workflow administrator could therefore change provisioning code in a future run.

The next stronger boundary is external administrative ownership:

```text
repository/workload owner
        |
        +-- cannot provision B
        +-- cannot rotate B
        +-- cannot replace B policy
        +-- cannot access B infrastructure administration
        |
        v
B operated under an independently controlled account/service/HSM
```

That final property requires deployment evidence outside this repository. The current proof establishes process, credential, secret, policy, and control-plane separation inside the executable CI topology without overstating organizational independence.

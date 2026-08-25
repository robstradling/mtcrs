---
title: "Merkle Tree Certificates: Revocation Status (MTCRS)"
abbrev: "MTCRS"
category: exp

docname: draft-strad-plants-mtcrs-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "PKI, Logs, And Tree Signatures"
keyword:
 - merkle tree certificates
 - hash chain
 - revocation
 - micali
venue:
  group: "PKI, Logs, And Tree Signatures"
  type: "Working Group"
  mail: "plants@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/plants"
  github: "robstradling/mtcrs"
  latest: "https://robstradling.github.io/mtcrs/draft-strad-plants-mtcrs.html"

author:
 -
    fullname: Rob Stradling
    organization: Sectigo
    email: rob@sectigo.com

normative:
  X.690:
    title: "Information technology - ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
    author:
      org: ITU-T
    date: 2021
    target: https://www.itu.int/rec/T-REC-X.690

informative:
  MICALI:
    title: "Efficient Certificate Revocation"
    author:
      - name: Silvio Micali
    date: 1996-03
    seriesinfo:
      MIT: "Technical Memo TM-542b"
    target: https://dl.acm.org/doi/10.5555/889659
  CHROME-MTC:
    title: "Chrome Quantum-resistant Root Program Policy (Draft), Version 0.3.0"
    author:
      org: Google Chrome
    date: 2026-08-14
    target: https://googlechrome.github.io/chromerootprogram/cqrp/draft-policy
  CRLite:
    title: "CRLite: A Scalable System for Pushing All TLS Revocations to All Browsers"
    author:
      - name: James Larisch
      - name: David Choffnes
      - name: Dave Levin
      - name: Bruce Maggs
      - name: Alan Mislove
      - name: Christo Wilson
    date: 2017-05
    target: https://doi.org/10.1109/sp.2017.17
  CRLSets:
    title: "CRLSets"
    author:
      org: Chromium
    date: 2022-08
    target: https://www.chromium.org/Home/chromium-security/crlsets/
  SHORTLIVED:
    title: "How Meta uses short-lived certificates to protect TLS secrets"
    author:
      org: Engineering at Meta
    date: 2023-08
    target: https://engineering.fb.com/2023/08/07/security/short-lived-certificates-protect-tls-secrets/
  FRACTAL:
    title: "Fractal Hash Sequence Representation and Traversal"
    author:
      - name: Markus Jakobsson
    date: 2002
    target: https://doi.org/10.1109/ISIT.2002.1023709
  ALMOST-OPTIMAL:
    title: "Almost Optimal Hash Sequence Traversal"
    author:
      - name: Don Coppersmith
      - name: Markus Jakobsson
    date: 2003
    target: https://doi.org/10.1007/3-540-36504-4_8

...

--- abstract

This document defines a hash chain revocation mechanism for Merkle Tree Certificates (MTC).
A Merkle Tree CA includes a hash chain anchor in the certificate at issuance time.
Periodically, the CA reveals the previous hash chain value for each non-revoked certificate.
The authenticating party packages the current value with its period as a *tick* and embeds it in the certificate's MTCProof as the certificate's non-revocation proof, alongside the inclusion proof that establishes authenticity.
The relying party can then cryptographically verify that the certificate has not been revoked, with granularity as fine as a fraction of a day.

This mechanism provides timely revocation without requiring signatures per revocation check, without relying on the relying party to poll for revocation updates, and without introducing new trust relationships beyond the existing CA.


--- middle

# Introduction

Merkle Tree Certificates {{!I-D.ietf-plants-merkle-tree-certs}} authenticate TLS connections using compact inclusion proofs into a Merkle Tree maintained by a certification authority (CA).
The base MTC specification is designed around short-lived certificates and leaves certificate-level revocation out of scope.
It notes that existing mechanisms such as CRLs and OCSP apply unchanged ({{Section 12.7 of !I-D.ietf-plants-merkle-tree-certs}}).
Its own serial-range revocation ({{Section 7.5 of !I-D.ietf-plants-merkle-tree-certs}}) is a complementary mitigation for CA misbehaviour rather than a per-certificate revocation service.

However, deployments such as Chrome's draft Quantum-resistant Root Program policy {{CHROME-MTC}} permit certificate lifetimes of up to 47 days.
That policy recommends a 7-day validity and requires each MTC CA to operate at least one cosigner key limited to it, while permitting up to three further keys that issue at 47 days.
Without revocation, exposure to key compromise or certificate misissuance is bounded only by expiry: a week in the recommended case, and a month and a half at the permitted maximum.
Relying parties that have them may fall back to out-of-band systems such as {{CRLite}} or {{CRLSets}}, but these are vendor-controlled and not universal, and no in-band mechanism exists.

This document defines such a mechanism based on hash chains {{MICALI}}.
At issuance, the CA commits a hash chain anchor into the MTC log entry as an X.509 extension.
For each non-revoked certificate, once per tick interval (e.g., every hour), the CA reveals the previous hash chain value, walking the committed hash chain backward.
To revoke a certificate, the CA simply stops revealing values.
The authenticating party (server) embeds the current hash chain value in the certificate's MTCProof (the `signatureValue`), and the relying party (client) verifies it against the anchor committed in the log entry.

The MTCProof already carries a proof of inclusion: the evidence that a certificate is authentic, because its entry sits in a cosigned Merkle Tree.
This mechanism adds a proof of non-revocation to the same structure, so that together they let a relying party confirm not merely that the certificate was issued, but that it may be relied upon now.

This approach achieves the following properties:

- **Timely revocation:** Revocation takes effect within at most two periods (e.g., two hours) under the default acceptance window ({{clock-skew}}), regardless of when the relying party last updated its trusted subtrees.

- **No per-check signatures:** Unlike OCSP {{?RFC6960}}, verification requires only hash computations, not signature verification.
  The CA incurs no signing load for revocation status.

- **Mandatory enforcement:** The hash chain value is a required component of the certificate presentation.
  Unlike OCSP stapling, the mechanism cannot be silently omitted by the authenticating party.

- **Self-authenticating:** The hash chain value is verified against the anchor already committed in the Merkle Tree.
  No new trust relationships or authenticated channels are needed.

- **Minimal overhead:** A single tick (36 bytes for SHA-256: a 4-byte period and a 32-byte hash value) is added per handshake to the certificate's MTCProof; the committed anchor adds about 50 bytes to each log entry ({{assertion-integration}}).

These properties come with two deliberate trade-offs, treated in full later but noted here so they are visible from the outset.
First, enforcement introduces an availability dependency: because an authenticating party must refresh its tick each period, a tick-distribution outage that outlasts the certificate's buffer renders it unusable ({{availability-considerations}}).
Second, revocation is enforceable but not transparent.
Withholding a tick is not a signed, logged artifact, so monitors cannot observe revocation events in the Merkle Tree, and a deployment that needs an auditable revocation record obtains it from a mechanism outside MTC ({{revocation-transparency}}).
Both are intrinsic to fetch-free, hard-fail revocation rather than defects, and both are bounded.

This mechanism is designed to layer onto the base MTC specification {{!I-D.ietf-plants-merkle-tree-certs}} with a single required change.
{{base-spec-amendments}} collects what this document asks of the base specification, and {{open-questions}} the design choices it leaves open for the working group to settle.
The rationale for choosing this approach over the alternatives, and the argument that functional revocation is superior to passive expiry, are developed in {{rationale}}.

This document is published as Experimental to gather implementation and deployment experience with hash chain revocation for Merkle Tree Certificates.
The author's intent is that it advance to the Standards Track if the PLANTS working group is willing to adopt it, ideally with the single base-specification change it requests ({{base-spec-amendments}}) folded into the base MTC specification itself.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the TLS presentation language defined in {{Section 3 of !RFC9846}} for the HashChainInput ({{encoding}}), HashChainTick ({{cert-format}}), and amended MTCProof ({{tick-trailing-field}}) structures, and ASN.1 {{X.690}} for the certificate extension it defines ({{assertion-integration}}).
The HashValue and TrustAnchorID types are those of {{!I-D.ietf-plants-merkle-tree-certs}}.

This document uses the hash function HASH and its output length in bytes HASH_SIZE that a Merkle Tree CA defines for its issuance logs ({{Section 5 of !I-D.ietf-plants-merkle-tree-certs}}); for a CA using SHA-256, HASH is SHA-256 and HASH_SIZE is 32.
Hash chain values, the anchor, and the tick all use this hash.

<!-- TODO: delete the following paragraph once draft-ietf-plants-merkle-tree-certs-06 is published, since the renamed structures will then be in the published reference. -->

Structure names from the base specification follow its editor's copy, in which MerkleTreeCertEntry, MerkleTreeCertEntryExtension, MerkleTreeCertEntryExtensionType, and MTCSignature have been renamed to MTCLogEntry, MTCLogEntryExtension, MTCLogEntryExtensionType, and SubtreeSignature respectively.
Readers comparing against draft-ietf-plants-merkle-tree-certs-05 should substitute the older names.

## Terminology

This document uses the roles defined in {{!I-D.ietf-plants-merkle-tree-certs}}.
They are the *certification authority (CA)* that issues certificates, the *authenticating party* (in TLS, the server) that presents one, the *relying party* (in TLS, the client) that validates it, and the *monitor* that watches issuance logs.
It adds the following terms, each specified in full in the section cited.

Hash chain:
: The sequence of values `h[0]` through `h[hash_chain_length]` that the CA generates for a log entry at issuance, each the hash of its predecessor ({{construction}}).

Seed:
: The first value of a hash chain, `h[0]`.
  It is secret, is never revealed, and yields the entire hash chain to anyone who learns it ({{seed-confidentiality}}).

Anchor:
: The last value of a hash chain, `h[hash_chain_length]`.
  It is public, is committed to the Merkle Tree as part of the certificate, and is the value against which every tick is verified ({{assertion-integration}}).

Period:
: One interval of `tick_interval` seconds.
  Periods are numbered from 0, with period 0 beginning at the certificate's `notBefore` ({{construction}}).

`tick_interval`:
: The duration of one period, in seconds.
  It is a per-certificate value carried in the certificate, and defaults to 3600 ({{construction}}).

`hash_chain_length`:
: The number of periods in the certificate's lifetime, `ceil(lifetime / tick_interval)`, which is also the index of the anchor within the hash chain ({{construction}}).

Tick:
: The pair `{period, value}` that the CA reveals for a period and the authenticating party embeds in the MTCProof ({{cert-format}}).
  A tick is the certificate's *non-revocation proof*: the component of the MTCProof attesting that the certificate has not been revoked as of that period, complementing the inclusion proof and cosignatures that attest authenticity.

`tbs_cert_entry_hash`:
: The value that addresses an entry's tick in the distribution interface: the SHA-256 hash of the entry's `tbs_cert_entry_data`, always computed with SHA-256 independent of the CA's tree hash ({{distribution}}).

Tick distributor:
: A party other than the CA that serves ticks over the HTTP interface of {{distribution}}.
  Because ticks are self-authenticating, a distributor is trusted for availability only, never for integrity ({{delegated-distribution}}).

Self-authenticating:
: Verifiable offline by hashing forward to the anchor committed in the certificate ({{verification}}), needing no signature over the value and no trust beyond the CA's existing trust anchor.
  Every hash chain value in this mechanism has this property.
  Because a tampered or forged value cannot reach the committed anchor in the number of steps its claimed period implies, it holds even though the MTCProof that carries the tick is itself unsigned and mutable.

# Overview {#overview}

This section is a non-normative walk-through of the mechanism's lifecycle; the normative details follow in {{construction}} through {{distribution}}.
It reuses the small example of {{test-vectors}}: a hash chain of length `hash_chain_length = 5` (a real certificate uses a much longer one, for example 1,128 for a 47-day lifetime with a one-hour period).
{{fig-actors}} shows how the parties interact, and {{fig-hash-chain}} depicts the hash chain lifecycle that the five steps below trace.

~~~aasvg
   +-------------------+
   |        CA         |
   |     (issuer)      |
   +-------------------+
     |                 |
     | (1) issuance:   | (2) each period: reveal one hash chain
     |     commit      |     value as a tick and publish it
     |     anchor in   |     over HTTP  (to revoke, withhold)
     |     log entry   |               |
     v                 |               |
   +---------------+   |               v
   |    MTC log    |   |   +-------------------------+
   |  Merkle Tree, |   |   |  Authenticating party   |
   |  cosigners    |   +-->|      (TLS server)       |
   +---------------+ GET   | writes tick into the    |
     |                     | certificate's MTCProof  |
     | (3) cert:           +-------------------------+
     |     inclusion proof,            |
     |     cosignatures,               | (4) TLS handshake:
     |     committed anchor            v     cert + MTCProof(tick)
     +------------------------>+-------------------------+
                               |    Relying party        |
                               |      (client)           |
                               | verifies OFFLINE:       |
                               | proof, cosignatures,    |
                               | tick --> anchor         |
                               +-------------------------+
~~~
{: #fig-actors title="MTCRS actors and their interactions: the CA commits an anchor at issuance and publishes a tick each period, the authenticating party writes the current tick into the MTCProof, and the relying party verifies everything offline"}

~~~aasvg
   Issuance: the CA hashes a secret seed forward to the anchor,
   then commits the anchor in the certificate.

    +------+   +------+   +------+   +------+   +------+   +------+
    | h[0] |-->| h[1] |-->| h[2] |-->| h[3] |-->| h[4] |-->| h[5] |
    +------+   +------+   +------+   +------+   +------+   +------+
     seed     \___ each arrow is one hash operation ___/   anchor
    (secret)                                             (committed
                                                          in cert)

   Each period, the CA reveals one value, walking the hash chain
   backward; the revealed value is that period's public "tick".

     period:   0        1        2        3        4
     tick:    h[5]     h[4]     h[3]     h[2]     h[1]
            (anchor)
     (h[0] is never revealed; to revoke, the CA stops revealing)

   Verify a tick for period t: hash it forward t times and check
   it equals the anchor.  Period 2:  h[3] --> h[4] --> h[5].
~~~
{: #fig-hash-chain title="MTCRS hash chain lifecycle: generated forward at issuance, revealed in reverse each period, and verified forward to the committed anchor"}

1. **Issuance.**
   For each log entry, the CA generates a secret random seed `h[0]` and hashes it forward `hash_chain_length` times to obtain `h[1], h[2], ..., h[5]` ({{construction}}).
   The final value `h[5]` is the *anchor*.
   The CA commits it into the certificate as the id-pe-hashChainAnchor extension ({{assertion-integration}}); because the anchor sits in the log entry, it is covered by the Merkle Tree and the cosignatures.

2. **Per-period reveal.**
   Time after the certificate's `notBefore` is divided into periods of `tick_interval` seconds (one hour by default).
   At the start of period `t`, the CA reveals `h[hash_chain_length - t]` (for period 2, that is `h[3]`), unless it has revoked the certificate, in which case it reveals nothing further ({{revealing-values}}).
   These period boundaries are the certificate's own: because they are counted from its `notBefore`, each certificate advances through its periods on its own schedule ({{construction}}).
   The hash chain is revealed in reverse of the order it was generated, so revealing the current value gives no help in computing any future one.

3. **Server refresh.**
   Once per period, the authenticating party (server) fetches the certificate's current value as a *tick* `{period, value}` with a single plain HTTP GET ({{distribution}}).
   For period 2, that tick is `{2, h[3]}`.
   It writes the tick into the MTCProof it presents in TLS handshakes ({{cert-format}}).
   A server holding several certificates fetches one tick per certificate, each on that certificate's own schedule.
   The MTCProof is not committed to the tree, so refreshing the tick each period does not disturb the inclusion proof or cosignatures.

4. **Relying-party verification.**
   A relying party reads the tick and the committed anchor from the certificate, hashes `tick.value` forward `tick.period` times, and checks that the result equals the anchor ({{verification}}); hashing `h[3]` twice yields `h[5]`.
   It also checks that `tick.period` agrees with its own clock to within one period.
   Verification is entirely offline: the relying party fetches nothing ({{rp-no-fetch}}).

5. **Revocation = withholding.**
   To revoke a certificate, the CA simply stops revealing its hash chain values ({{revealing-values}}).
   Once the last revealed tick's period ends, no party can produce a valid tick, because doing so would require inverting the hash.
   The certificate therefore becomes unusable within at most two periods.

# Hash Chain Construction {#construction}

## Parameters

The hash chain mechanism introduces the following additional parameter:

`tick_interval`:
: A duration, in seconds: the length of one period, and so the cadence at which the CA reveals a value and the authenticating party refreshes its tick ({{distribution}}).
  It sets the granularity of revocation but not the latency, which is about two intervals under the default acceptance window ({{clock-skew}}).
  This MUST be greater than zero.
  The RECOMMENDED and default value is 3600 (one hour); {{assertion-integration}} specifies how this default is encoded so that a certificate using it carries no `tick_interval` bytes.
  The number of periods in a certificate's lifetime is `hash_chain_length = ceil(lifetime / tick_interval)`.

Because a tick carries its period in a 32-bit field ({{cert-format}}), `hash_chain_length` MUST be less than 2<sup>32</sup>, so that every period number (0 through `hash_chain_length` - 1) and the verifier's one-period acceptance allowance ({{verification}}) are representable.
This is not a practical constraint: reaching it would require, for example, a one-second period sustained over more than a century.

`tick_interval` need not evenly divide the lifetime; if it does not, the final period is shorter than `tick_interval`, ending when the certificate expires.
This is harmless.
The verifier computes the period from `not_before` ({{construction}}) and the base MTC validity check bounds the certificate at `notAfter`, so the truncated final period needs no special handling, and its shorter span only means revocation during it takes effect faster.

The certificate's validity period MUST be longer than `tick_interval`.
A certificate whose validity period is not longer than `tick_interval` would have `hash_chain_length = 1`: its only tick is the public period-0 anchor, which enforces nothing (revocation is only enforceable from period 1 onwards; see {{period-zero-rationale}}).
A CA MUST NOT include the id-pe-hashChainAnchor extension, and MUST NOT use this mechanism, for such a certificate.
Because the period-0 grace defers enforcement of a just-issued certificate to the start of period 2 ({{period-zero-rationale}}), deployments SHOULD choose a validity period substantially longer than twice `tick_interval` so that revocation is effective for most of the certificate's life.

`tick_interval` is a per-certificate value: it is carried in the certificate itself, in the HashChainAnchorInfo committed to the Merkle Tree ({{assertion-integration}}), rather than being a CA-wide configuration constant.
This is deliberate.
Because a relying party verifies offline and has no provisioning relationship with the CA, the only way it can obtain `tick_interval` without a new authenticated distribution channel is to read it from the certificate.
Carrying it in the tree-committed extension makes it both discoverable by the relying party and self-authenticating.
It also lets a CA change `tick_interval` for newly issued certificates without redistributing anything or invalidating existing certificates, each of which keeps the value it was issued with.
A CA MAY of course use the same `tick_interval` for every certificate it issues; the point is only that the value each verifier uses comes from the certificate, not from CA-wide configuration that verifiers cannot see.

## Chain Generation

At certificate issuance time, for each log entry, the CA generates a hash chain as follows:

1. Generate a seed of HASH_SIZE bytes (32 bytes for SHA-256) using a cryptographically secure random number generator ({{?RFC4086}}) or an approved deterministic random bit generator.
   The seed MUST be unpredictable: an adversary who can guess or recover it can compute the whole hash chain and forge ticks for a revoked certificate, so it carries the same unpredictability and confidentiality requirement as a secret key ({{seed-confidentiality}}).

2. Compute the `hash_chain_length` + 1 values of the hash chain:

       h[0] = seed
       h[i] = Hash(HashChainInput(h[i-1]))  for i = 1, ..., hash_chain_length

   Where HashChainInput is defined in {{encoding}}.

3. The anchor is `h[hash_chain_length]`, the final value in the hash chain.

The anchor is included in the certificate as an X.509 extension (see {{assertion-integration}}).

## Period Numbering

Periods are numbered starting from 0.
Period 0 begins at the certificate's `notBefore` time and each subsequent period begins `tick_interval` seconds later.
The period number at any given time t is:

~~~pseudocode
period = floor((t - not_before) / tick_interval)
~~~

`not_before` is the `notBefore` time of the certificate's validity period, expressed in the same units as t (seconds since the Unix epoch).
It anchors the period schedule to a value that both the CA and every verifier read from the certificate, so they compute identical period boundaries regardless of their wall-clock differences; it is not necessarily the exact instant of issuance.
The CA MUST number periods from `notBefore` and MUST NOT begin revealing ticks before period 0 starts at `notBefore`.

Period numbering depends only on `notBefore`.
It is independent of the MTCProof's `start` and `end` fields, which describe the chosen subtree interval used for the inclusion proof and play no part in the period schedule.
The standalone and landmark-relative certificates for an entry can therefore carry different `start` and `end` yet number periods identically, because they share the same `notBefore` ({{cert-profiles}}).
Backdating `notBefore`, as CAs commonly do to accommodate relying-party clock skew, shifts the certificate forward in its own schedule.
Backdating by less than one `tick_interval` is harmless: it merely places the certificate a little way into period 0 when it is first presented.
Backdating by one `tick_interval` or more places the certificate in period 1 or later at the moment of issuance, which forfeits the period 0 grace ({{period-zero-rationale}}) in both its parts.
The CA no longer has until the start of period 1 before it must serve a secret tick, and the authenticating party can no longer present the committed anchor as a period 0 tick while it installs.
A CA that backdates by one `tick_interval` or more MUST therefore be serving that entry's ticks from the moment it issues the certificate, since the authenticating party cannot present the certificate at all until it has fetched one.
Deployments that want the grace preserved keep backdating below one `tick_interval`.
Setting `notBefore` later than issuance (forward-dating) is different: there is no period earlier than 0, and for any time t earlier than `notBefore` the quantity (t - `not_before`) is negative.
Such a certificate is simply not yet valid.
A verifier MUST reject it through the base MTC validity check before computing any period, and MUST NOT evaluate the period expression with unsigned arithmetic, which would underflow for such times and could yield a spuriously large period.

## Revealing Values {#revealing-values}

For each non-revoked certificate, at the start of period t, the CA reveals the hash chain value `h[hash_chain_length - t]`.
This value can be verified by hashing it t times and comparing with the anchor.

Periods run from 0 to `hash_chain_length` - 1, so the last value the CA ever reveals is `h[1]`, one step from the seed, in the certificate's final period.
The CA MUST NOT reveal a value for any period at or beyond `hash_chain_length`, and MUST NOT reveal the seed `h[0]` under any circumstances.
`h[0]` is the whole hash chain, and disclosing it would let any party forge ticks for every remaining period ({{seed-confidentiality}}).
A CA that derives the period to serve from a clock MUST therefore bound that period at `hash_chain_length` - 1 rather than evaluating `h[hash_chain_length - t]` for an arbitrary t; tick publication for a certificate stops when the certificate expires.

For period 0, `hash_chain_length - t` equals `hash_chain_length`, so the value revealed is the anchor `h[hash_chain_length]` itself, which is already public (it is committed in the certificate; see {{assertion-integration}}).
The period 0 tick therefore provides no cryptographic assurance of non-revocation.
Any party holding the certificate can construct it by pairing that anchor with period 0, which takes no hashing at all, and a verifier hashes forward zero times and compares the anchor with itself.
This is an intentional design choice; see {{period-zero-rationale}} for the rationale.

## Revoking a Certificate {#revoking}

To revoke a certificate, the CA stops revealing new values.
Once the previous value expires (at the start of the next period), the certificate is effectively revoked: no party can produce a valid value without knowledge of unrevealed hash chain elements, which requires inverting the hash function.
Because period 0's value is the public anchor, the earliest period for which the CA can withhold a secret value is period 1.
A certificate therefore cannot be revoked during period 0, and one the CA wishes to revoke from the moment of issuance becomes unusable at the start of period 2 ({{period-zero-rationale}}).

Withholding is the entirety of the revocation action, but a CA must discharge it across every channel through which it publishes ticks, and pair it with the base MTC mechanism where this one does not reach.
On deciding to revoke an entry, a CA:

1. MUST stop revealing that entry's hash chain values from the start of the next period, and MUST NOT serve them from its own tick distribution service ({{distribution}}) thereafter.

2. MUST omit the entry from every subsequent bundle published to delegated distributors ({{delegated-distribution}}).
   A distributor pre-provisioned with a buffer of future values cannot be revoked through that channel until the buffer is exhausted, which is why the buffer SHOULD be short.

3. MUST, when revoking because of key compromise, also revoke the serial ranges of that key's certificates that carry no anchor, since withholding ticks reaches only the certificates that carry one ({{downgrade}}).

4. MUST fall back to the base MTC revoked-ranges mechanism if the seed or its derivation secret is compromised, because an attacker holding those can forge ticks whatever the CA withholds ({{seed-confidentiality}}).

No cache purge is required or useful: a tick cached at an HTTP intermediary is bounded by the same acceptance window as a freshly fetched one ({{clock-skew}}), so the certificate becomes unusable on the same schedule either way.
A deployment that needs the revocation to be publicly auditable must record it through a mechanism that produces such an artifact, since neither withholding a tick nor the base revoked ranges does ({{revocation-transparency}}).

## Security of the Hash Chain

The non-revocation proof relies only on the preimage resistance of the hash function, not on collision resistance.
Given `h[i]`, it is computationally infeasible to compute `h[i-1]` (which would be needed to forge a future validity proof).
The hash chain is revealed in reverse order precisely for this reason: knowledge of the current value does not help compute future values.

The label in HashChainInput ({{encoding}}) domain-separates hash chain values from other uses of the hash function in MTC, and the per-entry `issuer_id` and `serial_number` salt each certificate's hash chain into its own hash domain ({{encoding}}).

The one hash whose distinctness matters for a different reason is `tbs_cert_entry_hash`, which addresses the tick URL rather than forming part of the proof ({{distribution}}).
A collision there would merely cause two entries to share a URL and misroute a fetch.
The authenticating party's pre-installation check catches such a misrouted or unexpected tick before it is presented ({{distribution}}), so it does not affect the non-revocation guarantee.

# Hash Chain Input Encoding {#encoding}

The HashChainInput structure provides domain separation for hash chain computations:

~~~tls-presentation
struct {
    uint8 label[7] = "MTCRS\n\0";
    TrustAnchorID issuer_id<1..2^8-1>;
    uint64 serial_number;
    HashValue preimage;
} HashChainInput;
~~~

label:
: A fixed ASCII string providing domain separation from other uses of the hash function in MTC, so that a hash chain value cannot be reinterpreted as, or collide with, another MTC hash computation (for example, a Merkle Tree leaf or node hash).
  The trailing "\n\0" follows the convention of the base MTC specification's label (`"subtree/v1\n\0"`).
  The NUL terminator keeps the MTC label space prefix-free, so no label can be a prefix of another.
  The label's length is not otherwise security-relevant, and this short value keeps a typical HashChainInput within a single hash compression block.

`issuer_id`:
: The CA's trust anchor ID.

`serial_number`:
: The certificate's serial number, which the base specification defines as `(log_number << 48) | index` and which therefore identifies both the issuance log and the entry within it ({{Section 6.2 of !I-D.ietf-plants-merkle-tree-certs}}).

preimage:
: The previous hash chain value being hashed.

All fields are encoded with the TLS presentation language ({{!RFC9846}}).
`serial_number` is in network byte order (big-endian), and `issuer_id` is the binary TrustAnchorID carried with its one-byte length prefix as the `<1..2^8-1>` vector; for TrustAnchorID 32473.1, that is the five bytes 04 81fd5901 ({{test-vectors}}).

Carrying the serial number whole, rather than its `log_number` and index components as separate fields, encodes the identical eight bytes, since those components are exactly its high 16 and low 48 bits.
It matches what both parties hold and removes a split-and-rejoin step in which the field widths could be mistaken.

Both parties read `serial_number` directly from the certificate: the relying party when verifying ({{verification}}), and the authenticating party for its pre-installation check ({{distribution}}).
It cannot be taken from the TBSCertificateLogEntry, which omits `serialNumber` ({{Section 12.6 of !I-D.ietf-plants-merkle-tree-certs}}); an authenticating party therefore needs its certificate to compute HashChainInput, not only the log entry from which it derives `tbs_cert_entry_hash` and its fetch offset ({{distribution}}, {{load-distribution}}).

The `issuer_id` and `serial_number` fields together identify the log entry and act as a per-entry salt, placing each certificate's hash chain in a distinct hash domain.
This salting is not load-bearing for the core guarantee: each hash chain already starts from an independent, cryptographically random seed, and the anchor committed in the certificate ({{assertion-integration}}) binds each revealed value to that specific hash chain.
Its contribution is defense in depth.
It keeps hash chains distinct even if a seed-generation fault were to repeat a seed across entries, and it frustrates any amortized precomputation that would otherwise target the whole population of hash chains at once (the same rationale as salting).

Two constraints rule out deriving the salt from the certificate or the log entry instead, as a hash of the TBSCertificate or of `tbs_cert_entry_data` would.
The first is circularity.
The anchor is committed inside the TBSCertificateLogEntry, and so inside the TBSCertificate ({{assertion-integration}}), whereas the salt must be fixed before the hash chain that produces that anchor can be computed.
A hash of either structure is therefore unavailable when the hash chain is generated.
The second is cost.
HashChainInput is hashed once per forward step, up to `hash_chain_length` - 1 times per verification ({{verification}}).
Substituting a 32-byte hash for the 8-byte serial number would push a typical structure past the 55 bytes that SHA-256 accommodates in a single compression block, roughly doubling that work.
The serial number avoids both, and its uniqueness across a CA's entries follows from its construction rather than from any collision property.

The Hash function is the same hash function used by the Merkle Tree CA (SHA-256 for CAs using SHA-256).

# Integration with MTC Log Entries {#assertion-integration}

## Hash Chain Anchor Extension

This document defines a new X.509 certificate extension for carrying the hash chain anchor.
This extension is included in the TBSCertificateLogEntry's extensions field ({{Section 5.2.1 of !I-D.ietf-plants-merkle-tree-certs}}), and thus appears in the TBSCertificate of the resulting Merkle Tree Certificate and in the entry's `tbs_cert_entry_data` that the base specification commits to the Merkle Tree.

~~~asn.1
id-pe-hashChainAnchor OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) pe(1) TBD }
~~~

The extension value contains the DER encoding of the following ASN.1 structure:

~~~asn.1
HashChainAnchorInfo ::= SEQUENCE {
    tickInterval      INTEGER (1..MAX) DEFAULT 3600,
    anchor            OCTET STRING
}
~~~

`tickInterval`:
: The tick interval in seconds for this certificate ({{construction}}), with a default of 3600 (one hour).
  Under DER, a certificate using the default value MUST omit this field (Section 11.5 of {{X.690}}), so the common one-hour case adds no per-entry bytes; a relying party that finds the field absent MUST use the default of 3600.
  The relying party reads this value (or the default) from here; it is used to number periods and to compute the expected period during verification ({{verification}}).

anchor:
: The hash chain anchor value `h[hash_chain_length]`.
  This OCTET STRING MUST be exactly HASH_SIZE bytes long; a relying party MUST reject the certificate if it is not ({{verification}}).

The extension MUST appear at most once in a certificate.
The extension MUST NOT be present in a certificate whose validity period is not longer than `tick_interval` ({{construction}}); such a certificate cannot advance beyond period 0, so the mechanism would enforce nothing.

Because the anchor is committed to the Merkle Tree, this extension enlarges every log entry that carries it.
With the default `tick_interval`, the committed data is a HashChainAnchorInfo carrying only the anchor (HASH_SIZE bytes, 32 for SHA-256) plus its DER and extension framing.
That is about 50 bytes per entry for SHA-256, of which 36 are the HashChainAnchorInfo itself ({{test-vectors}}) and the rest the X.509 extension's OBJECT IDENTIFIER and wrapper.
A TBSCertificateLogEntry is typically a few hundred bytes (a subject name, validity, a hashed SubjectPublicKeyInfo, and any other extensions), so this is a modest increase.
Being a fixed-size hash, it does not grow with post-quantum key or signature sizes, unlike much of what MTC was designed to keep out of the log.
The cost lands in two bounded places.
The first is monitor bandwidth.
Monitors download every entry, so the ecosystem-wide cost is those bytes times the number of participating entries: on the order of tens of gigabytes at 10<sup>9</sup> entries.
It is incurred once per entry rather than per period, and is far below the per-certificate signatures ({{per-cert-signatures}}) this mechanism avoids.
The second is the certificate presentation, where the same anchor bytes travel in each handshake as ordinary TBSCertificate content.
The inclusion proof is unaffected: its size depends on tree depth, not entry size, so the anchor adds no hashes to the proof path.
This committed cost is the unavoidable price of self-authentication.
Unlike the tick base URL, which is deliberately kept out of the certificate ({{discovery}}), the anchor is the value every tick is verified against and therefore cannot be delivered out of band.
The DEFAULT encoding of `tickInterval` keeps that field off the wire whenever the default period is used, holding the committed cost to the anchor itself; the more compact entry-extension encoding ({{anchor-entry-extension}}) trims the framing further.

This document carries the anchor as an X.509 extension of the TBSCertificateLogEntry rather than as a committed MTCLogEntryExtension, so that the anchor rides as ordinary certificate bytes and the generic MTC log and cosigner infrastructure need not be MTCRS-aware.
The entry-extension alternative is described in {{anchor-entry-extension}}.
It is more compact and symmetric with the tick's encoding, but requires MTCRS-aware cosigner software and lacks a criticality lever.
The anchor's home is the one design choice this document explicitly refers to the working group.
This document's preference is the X.509 extension, because it lets the mechanism layer onto an unmodified MTC log and cosigner deployment ({{base-spec-amendments}}).
A base specification willing to make its entry-extension registry and cosigners MTCRS-aware MAY instead adopt the entry-extension encoding, gaining the compactness and committed/uncommitted symmetry noted above.
The two are mutually exclusive: whichever the base specification selects becomes the single anchor home for the ecosystem, and the verification procedure ({{verification}}) is identical either way.

## Criticality and Incremental Deployment {#extension-criticality}

The id-pe-hashChainAnchor extension SHOULD be marked non-critical, so that relying parties that do not implement this mechanism can still process the certificate.
However, relying parties that do implement this mechanism MUST enforce hash chain verification as described in {{verification}} when the extension is present.
An MTC ecosystem in which all relying parties are expected to support hash chain revocation MAY mark the extension critical, causing implementations that do not recognize it to reject the certificate.
Marking the extension critical is the transition lever that forces relying parties unaware of this mechanism to hard-fail rather than silently ignore it; the entry-extension encoding ({{anchor-entry-extension}}) lacks this lever.
During a transition in which not all relying parties yet implement this mechanism, the base MTC revoked-ranges mechanism and external revocation systems continue to provide coverage, and a root program MAY mandate critical marking once adoption is deemed sufficient.

# Certificate Presentation {#cert-format}

## Hash Chain Tick

When a hash chain anchor extension is present in the certificate, the authenticating party MUST include a hash chain tick in the MTCProof structure (carried in the certificate's `signatureValue`).
The tick is the certificate's non-revocation proof: where the inclusion proof and cosignatures attest that the certificate is authentic, the tick attests that it has not been revoked as of the current period.
The tick is a HashChainTick:

~~~tls-presentation
struct {
    uint32 period;
    HashValue value;
} HashChainTick;
~~~

period:
: The period number for which this tick is valid.
  It tells the relying party two things.
  The first is the freshness the tick asserts: that the certificate was not revoked as of this period, checked against the relying party's clock ({{verification}}).
  The second is how many times to hash value forward to reach the committed anchor.
  That count cannot be taken from the relying party's own expected period, because clock skew and caching allow the presented tick to be for an adjacent period.
  The field is 32 bits so that fine `tick_interval` values remain usable across the full certificate lifetime: a 16-bit field would overflow at 65,535 periods, which a minute-granularity period already exceeds within a 47-day lifetime.

value:
: The hash chain value `h[hash_chain_length - period]`.

The MTCProof is not committed to the Merkle Tree (only the TBSCertificateLogEntry is hashed into the tree), so the tick can be updated each period without affecting the inclusion proof or cosignatures.
The authenticating party reconstructs or replaces the `signatureValue` with a fresh tick while reusing the same inclusion proof and signatures.

The authenticating party MUST include a HashChainTick whose period falls within the acceptance window the relying party applies (step 4 of {{verification}}); in practice this is the most recent tick it has fetched and verified ({{distribution}}).
It SHOULD present the current period's tick once it holds one, but is not required to switch at the period boundary.
The deterministic fetch offset means the preceding period's tick is normally presented for the first part of each period ({{load-distribution}}), and an authenticating party that cannot obtain a fresh tick continues to present its most recent still-valid one ({{availability-considerations}}).
The relying party checks `tick.period` against its own clock using the acceptance window, which allows for clock skew and caching and is specified in step 4 of {{verification}}.

This document describes two possible ways to carry the HashChainTick inside the MTCProof, but exactly one is used: the encoding is fixed by the base MTC specification, not chosen per deployment or per certificate.
Both are amendments to the base MTCProof structure and differ in generality.
The trailing-field encoding ({{tick-trailing-field}}) is RECOMMENDED: it appends the fixed-size tick directly to the MTCProof, which is the minimal change and confines the added, unauthenticated bytes to exactly one value that a conforming relying party fully verifies.
The proof-extension encoding ({{tick-proof-extension}}) is an alternative for a base specification that additionally wants a general, reusable proof-level extensibility point ({{mtcproof-extensibility}}).
As a general "ignore if unknown" channel it carries the abuse surface discussed in {{proof-extensions-considerations}}, which for a single tick is not otherwise justified.
Whichever encoding the base specification selects becomes the single encoding used throughout the ecosystem; the other is discarded.

### Preferred Encoding: Trailing status_tick Field {#tick-trailing-field}

In the RECOMMENDED encoding, the base MTC specification is amended to append the HashChainTick to the MTCProof as a trailing `status_tick` field.
The field is not a bare optional field, since the base MTCProof has no discriminant for one.
It is instead a variant selected by whether the entry carries a hash chain anchor ({{assertion-integration}}), occupying zero bytes when it does not:

~~~tls-presentation
struct {
    MTCLogEntryExtension extensions<0..2^16-1>;
    uint48 start;
    uint48 end;
    HashValue inclusion_proof<0..2^16-1>;
    SubtreeSignature signatures<0..2^16-1>;
    select (certificate_has_anchor) {
        case false: Empty;
        case true:  HashChainTick;
    } status_tick;
} MTCProof;
~~~

certificate_has_anchor is the contextual boolean "the entry carries a hash chain anchor", read from whichever home the deployment uses: the id-pe-hashChainAnchor X.509 extension of the primary design ({{assertion-integration}}), or the `hash_chain_anchor` entry extension of the alternative ({{anchor-entry-extension}}).
This discriminant is not a field of the MTCProof, unlike the base specification's in-structure selects (for example the `select (type)` in {{Section 5.2.1 of !I-D.ietf-plants-merkle-tree-certs}}, whose discriminant is a preceding field of the same structure).
It is instead a property of the enclosing certificate, and it is well-defined for the same reason the base verifier can already read it: an MTCProof is never decoded standalone.
It is only ever parsed as the `signatureValue` of a specific certificate, and {{Section 7.2 of !I-D.ietf-plants-merkle-tree-certs}} already parses it strictly in that certificate context, reconstructing the entry and its extensions from the certificate to check the inclusion proof.
Whether the anchor is present is therefore known before `status_tick` is read, from exactly the data the base procedure already has in hand.
No new parsing capability is introduced; this is the same context-dependent decoding TLS itself relies on, where a structure's contents depend on the context in which it appears ({{!RFC9846}}).
The false case uses the Empty type, the empty structure `struct {} Empty;` of {{!RFC9846}}, so a certificate that does not use this mechanism carries no additional bytes and is byte-identical to a base MTCProof.

This resolves precisely the "extra data after the MTCProof" check in {{Section 7.2 of !I-D.ietf-plants-merkle-tree-certs}}, which that section is amended to interpret as follows:

- If the entry carries a hash chain anchor (the true case), exactly one HashChainTick (4 + HASH_SIZE bytes; 36 bytes for SHA-256) MUST immediately follow the signatures vector, and the `signatureValue` MUST end there. A relying party MUST reject the certificate if any bytes remain after this HashChainTick, or if the `signatureValue` ends before a complete HashChainTick has been read.
- If the entry does not carry a hash chain anchor (the false case), `status_tick` is Empty and the original rule is unchanged: the `signatureValue` MUST end immediately after the signatures vector, with no trailing bytes.

A relying party predating the amendment would reject the certificate at the MTCProof parsing stage; such a relying party could not verify hash chain revocation in any case.

This is the minimal change to the base MTCProof structure.
Because the appended field is fixed-size and, for a conforming relying party, fully verified against the committed anchor ({{verification}}), it adds no variable-length "ignore if unknown" region and hence no general stuffing or covert-channel surface (contrast {{tick-proof-extension}} and {{proof-extensions-considerations}}).
Its only cost is that carrying a second proof-level mechanism in future would require a further base-specification change.

## Use in TLS {#tls-use}

No new TLS extension type is required.
When the authenticating party presents a Merkle Tree Certificate, the hash chain tick is carried within the certificate's `signatureValue` as part of the MTCProof, which is already transmitted in the CertificateEntry.

The presence of the hash chain anchor signals to the relying party that the MTCProof carries a HashChainTick ({{cert-format}}).
That is the id-pe-hashChainAnchor extension in the primary design, or the `hash_chain_anchor` entry extension in the alternative ({{anchor-entry-extension}}).
If the tick is absent, malformed, or fails verification, the relying party MUST reject the certificate.

## Standalone and Landmark-Relative Certificates {#cert-profiles}

A Merkle Tree CA can issue two certificate profiles for the same log entry: a standalone certificate and a landmark-relative certificate (Sections 6.3 and 6.4 of {{!I-D.ietf-plants-merkle-tree-certs}}).
The two differ only in the subtree and signatures carried in their MTCProof; they certify the same TBSCertificateLogEntry.

Hash chain revocation is keyed by the log entry, not by the certificate profile:

- Both profiles commit to the same id-pe-hashChainAnchor extension (part of the TBSCertificateLogEntry, or of the entry's extensions; see {{anchor-entry-extension}}), so a single anchor and hash chain per entry serves both.
- `tbs_cert_entry_hash` ({{distribution}}) is computed over the entry's `tbs_cert_entry_data`, which is identical for both profiles, so both resolve to the same tick URL and the same tick.
- The HashChainTick for a given period is therefore identical in both certificates.

An authenticating party may hold both a standalone and a landmark-relative certificate for the same entry, for example during the renewal overlap described in {{Section 10.4 of !I-D.ietf-plants-merkle-tree-certs}}.
It fetches the entry's tick once per period and writes that same value into the MTCProof of whichever certificate it presents.
Refreshing the tick is independent of profile selection: the authenticating party selects between the two certificates using the base MTC mechanism ({{Section 8 of !I-D.ietf-plants-merkle-tree-certs}}), and updates the HashChainTick in whichever MTCProof it sends.

# Verification {#verification}

When a relying party receives a Merkle Tree Certificate with the id-pe-hashChainAnchor extension, it performs hash chain verification in addition to the base MTC verification procedure.
The steps below name the id-pe-hashChainAnchor X.509 extension of the primary design; under the entry-extension alternative ({{anchor-entry-extension}}) the relying party instead reads the same HashChainAnchorInfo from the entry's extensions, and the procedure is otherwise identical.

The verifier first assembles the inputs to HashChainInput ({{encoding}}) and to the period computation ({{construction}}).
All of them are obtained from the certificate and the trust anchor being validated against; no data from the CA's tick distribution service ({{distribution}}) is needed, and the verifier MUST NOT fetch anything ({{rp-no-fetch}}):

- **`issuer_id`:** the TrustAnchorID of the trust anchor against which the certificate is being validated ({{Section 5.1 of !I-D.ietf-plants-merkle-tree-certs}}).
- **`serial_number`:** the certificate's serial number, read directly from the certificate ({{Section 6.2 of !I-D.ietf-plants-merkle-tree-certs}}).
- **`tick_interval` and anchor:** read from the HashChainAnchorInfo carried in the id-pe-hashChainAnchor extension; if `tickInterval` is absent, use its default of 3600 ({{assertion-integration}}).
- **`not_before`:** the `notBefore` time of the certificate's validity period ({{construction}}), which is the same value the CA used to number periods.

Using these inputs, the verifier performs the following steps:

1. Extract the HashChainAnchorInfo from the certificate's id-pe-hashChainAnchor extension.
   If not present, skip hash chain verification (the certificate does not use this mechanism).
   If the extension value does not DER-decode as a well-formed HashChainAnchorInfo, reject the certificate with a bad_certificate error.
   Examples are a malformed SEQUENCE, a `tickInterval` outside INTEGER (1..MAX), or trailing data after the structure.
   If the anchor OCTET STRING is not exactly HASH_SIZE bytes, reject the certificate with a bad_certificate error.

2. Extract the HashChainTick from the MTCProof (in the certificate's `signatureValue`), according to the encoding fixed by the base MTC specification: the trailing `status_tick` field ({{tick-trailing-field}}) or, if the general `proof_extensions` amendment was adopted instead, the `hash_chain_tick` proof extension ({{tick-proof-extension}}).
   If the id-pe-hashChainAnchor extension is present but the MTCProof does not carry a HashChainTick, reject the certificate with a bad_certificate error.

3. Compute the expected period from the current time:

       expected_period = floor((current_time - not_before) / tick_interval)

4. Check that `tick.period` lies within the *acceptance window*.
   The default acceptance window is `expected_period` - 1, `expected_period`, and `expected_period` + 1; a relying party MAY widen it in either direction as a matter of policy, with the consequences described in {{clock-skew}} and collected in {{rp-policy}}.
   A relying party MUST reject a certificate whose `tick.period` falls outside the acceptance window it applies, with a certificate_expired error.
   That alert covers both directions, because {{!RFC9846}} defines it as "a certificate has expired or is not currently valid".
   A tick too far in the future, which a verifier whose clock is well behind the authenticating party's would see, is not currently valid either.
   There is no period below 0, so when `expected_period` is 0 the lower neighbor is simply absent and the default accepted set is {0, 1}.
   A verifier MUST NOT compute `expected_period` - 1 in unsigned arithmetic, which would underflow (the same hazard as the negative period expression of {{construction}}).

5. Starting from `tick.value`, iteratively hash `tick.period` times:

       v = tick.value
       for i = 1 to tick.period:
           v = Hash(HashChainInput(v))

   The count is `tick.period`, not `hash_chain_length` - `tick.period`: the subtraction is applied when the CA chooses which value to reveal, since period t reveals `h[hash_chain_length - t]`, which lies exactly t hashes below the anchor ({{revealing-values}}).
   A relying party therefore never needs `hash_chain_length`, which is not carried in the certificate ({{assertion-integration}}); as the period counts up, the hash chain index counts down, and the number of forward hashes to the anchor is the period itself.

   Because step 4 has already constrained `tick.period` to the acceptance window, the iteration count is bounded by the certificate's own lifetime and cannot be inflated by a forged tick to mount a denial-of-service attack.
   The largest legitimate `tick.period` is `hash_chain_length - 1`, the certificate's final period, which requires `hash_chain_length - 1` forward hashes (1,127 for the 1,128-period hash chain of a 47-day, one-hour-period certificate; {{why-one-hour}}).
   Under the default acceptance window, the `expected_period` + 1 allowance ({{clock-skew}}) raises the defensive upper bound the verifier must tolerate by one, to `hash_chain_length`; a relying party that widens the window raises that bound correspondingly.

6. Compare the result with anchor from the HashChainAnchorInfo.
   If they do not match, reject the certificate with a bad_certificate error.

If all steps succeed, the hash chain verification passes, confirming that the CA has not revoked this certificate as of the indicated period.

The MTCProof is not committed to the Merkle Tree and can be modified in transit, but the tick is nonetheless self-authenticating.
Steps 5 and 6 bind both `tick.value` and `tick.period` to the committed anchor, because a given value reaches the anchor only after the exact number of forward hashes that its true period implies.
Tampering with either field therefore fails verification, and producing a tick for a period the CA has not yet revealed requires inverting the hash function ({{hash-function-requirements}}).
The only tick an attacker can present that still verifies is a genuine, already-revealed one, and step 4 bounds how stale that may be.

# Tick Distribution {#distribution}

The CA MUST provide a mechanism for authenticating parties to obtain current hash chain ticks.
This document defines an HTTP interface for this purpose.

## HTTP Interface

The CA (or a mirror) serves ticks over HTTP.
Given a tick base URL for the CA (see {{discovery}}), the tick for a particular certificate is fetched from:

~~~http-message
GET {tick_base_url}/.well-known/mtcrs/v1/tick/{tbs_cert_entry_hash}
~~~

where `tbs_cert_entry_hash` is the SHA-256 hash of the entry's `tbs_cert_entry_data` byte string: the contents octets of the DER-encoded TBSCertificateLogEntry, with no enclosing tag or length prefix, as defined in {{Section 5.2.1 of !I-D.ietf-plants-merkle-tree-certs}}.
The final path segment is its lowercase hexadecimal encoding (64 characters for SHA-256), so that the CA and the authenticating party derive an identical URL.
Throughout this document `tbs_cert_entry_hash` denotes that binary hash value (32 bytes for SHA-256); only the URL path segment carries it hex-encoded.
The authenticating party computes it from the TBSCertificateLogEntry it already possesses; no additional per-request metadata from the CA is required.

**Note:** `tbs_cert_entry_hash` is a distribution-layer addressing value: the SHA-256 of the entry's `tbs_cert_entry_data`, fixed to SHA-256 independent of the CA's tree HASH.
It is distinct from the base specification's own `entry_hash`, the Merkle leaf hash `MTH({entry})` used for inclusion proofs ({{Section 7.2 of !I-D.ietf-plants-merkle-tree-certs}}), which is computed with the tree HASH over the entire log entry.
By contrast, `tbs_cert_entry_hash` hashes only `tbs_cert_entry_data` and is never verified as a proof.
It carries no security weight.
The sole property it needs is collision resistance so that two entries do not share a URL, and even that is non-load-bearing, because a URL collision only misroutes a fetch that the authenticating party's pre-installation check catches ({{verification}}).
Fixing it to SHA-256 keeps tick distribution and caching independent of the CA's tree hash.
Algorithm agility lives where it matters, in the security-relevant hashing that follows the agile tree HASH ({{post-quantum}}), and the `v1` path segment is the migration lever should the addressing hash ever need to change.

The tick URL is keyed by `tbs_cert_entry_hash` rather than by the certificate's serial number, even though the serial (`(log_number << 48) | index`; {{Section 6.2 of !I-D.ietf-plants-merkle-tree-certs}}) also uniquely identifies the entry, is shorter, and needs no hashing.
The serial's index component is assigned sequentially, so a serial-keyed URL would let anyone enumerate a CA's whole certificate population and probe each certificate's revocation status simply by counting indices, with no certificate and no log data in hand.
`tbs_cert_entry_hash` raises that bar, because computing it requires the entry's contents (from the certificate or the public log) rather than a running counter.
Being a derived value that need not appear in the certificate, it can also be replaced by the unguessable per-certificate capability token of {{unguessable-urls}} when a CA wants to remove URL derivability entirely.
A serial carried in the certificate offers no such option.
Keying on `tbs_cert_entry_hash` therefore aligns with the design's preference that the tick endpoint not be treated as an enumerable status oracle ({{rp-no-fetch}}).
Its one cost is a reliance on the addressing hash's collision resistance to keep entries' URLs distinct, which is amply met and non-load-bearing (the Note above).
Distinct URLs also require the hashed data itself to differ between entries, which `serialNumber` cannot supply, being omitted from the TBSCertificateLogEntry ({{Section 12.6 of !I-D.ietf-plants-merkle-tree-certs}}).
In this design the anchor supplies it, since it is part of `tbs_cert_entry_data` and is an independent random value per entry ({{assertion-integration}}).
An encoding that moves the anchor out of `tbs_cert_entry_data` must therefore key ticks on something else ({{anchor-entry-extension}}).
Where positive, monitorable revocation transparency is wanted, it is provided deliberately and separately ({{revocation-transparency}}), not as a side effect of an enumerable endpoint.

The tick base URL is not derived from the CA's identifier.
A Merkle Tree CA is identified by a TrustAnchorID, which is a relative object identifier ({{Section 5.1 of !I-D.ietf-plants-merkle-tree-certs}}) rather than a hostname, so it cannot be turned into an origin.
The base URL is instead conveyed to the authenticating party out of band, as described in {{discovery}}.

The scheme (`http://` or `https://`) is whatever the CA specifies as part of the base URL.
Because each tick is self-authenticating, the tick fetch does not require transport-layer integrity, and because the tick value is public, it does not require transport-layer confidentiality of the response body.
CAs MAY therefore publish an `http://` base URL, which eliminates TLS handshake overhead and permits caching by any HTTP intermediary.
The one property plain HTTP does not provide is confidentiality of the request itself: an on-path observer can see which {tbs_cert_entry_hash} is being requested.
CAs whose deployments consider this metadata sensitive SHOULD publish an `https://` base URL instead.

For example, if a CA's tick base URL is `http://mtcrs.ca.example`, ticks are served at:

~~~
http://mtcrs.ca.example/.well-known/mtcrs/v1/tick/a1b2c3...f0
~~~

The base URL is an origin (scheme, host, and optional port); the `.well-known/mtcrs/v1/tick/{tbs_cert_entry_hash}` path is rooted at that origin.
A CA MAY point that origin's hostname at a CDN or mirror through ordinary DNS or HTTP routing, so no path prefix is needed.

The `v1` segment versions the MTCRS HTTP interface as a whole: the SHA-256 addressing of {tbs_cert_entry_hash} and the response format ({{response-format}}).
It is a migration lever, not a per-request parameter.
A future revision needing a different addressing hash or wire format would define a `v2` namespace, which a CA MAY serve alongside `v1` during a transition, without affecting the Merkle Tree, the non-revocation proof, or already-issued certificates.

## Discovering the Tick Base URL {#discovery}

Because the CA's TrustAnchorID is an identifier and not a locator, the tick base URL MUST be conveyed to the authenticating party out of band.
This is not a gap.
The authenticating party already obtains its certificate through a provisioning channel that involves a real CA endpoint, for example an ACME directory.
That channel is therefore the natural carrier for the base URL, and no locator need be derived from the certificate.

A CA MUST make the tick base URL available through at least one of the following mechanisms, and an authenticating party MUST support at least the provisioning-channel mechanism appropriate to how it obtains certificates:

- **Provisioning channel (primary).**
  The base URL is delivered when the certificate is provisioned.
  {{acme-integration}} defines this binding for ACME.
  Each other issuance protocol needs an analogous binding, which this document does not define.
  A CA issuing over such a protocol MUST either specify one (for example, in a short companion document registering the equivalent of the ACME order field of {{acme-integration}}) or publish the base URL through the CA certificate SIA below.
  A provisioning binding is moreover required for unguessable tick URLs ({{unguessable-urls}}), which the SIA cannot carry; a protocol with no provisioning binding can therefore support only the derivable-URL scheme, and only via the SIA.

- **CA certificate SIA (optional).**
  The base URL MAY additionally be published in the CA's certificate representation ({{Section 5.5 of !I-D.ietf-plants-merkle-tree-certs}}) using the id-ad-mtcrsTicks Subject Information Access access method defined in {{iana-considerations}}, whose accessLocation is a uniformResourceIdentifier giving the tick base URL.
  This carries a single per-CA URL on a single object, adds no per-log-entry bytes, and provides a protocol-independent, published record that an authenticating party, its tooling, or an auditor can read once without access to any provisioning transcript.
  Because it is per-CA and distributed out of band rather than presented in the TLS handshake, it avoids the costs that led this document to reject a per-certificate tick URL in Authority Information Access ({{aia-discovery}}).
  Its value is therefore as a published fallback and tooling record.
  Where a provisioning binding exists (for example ACME; {{acme-integration}}) it is redundant with that channel, which takes precedence when the two disagree; where none exists, it is the only interoperable carrier of the base URL.
  It carries only the base URL, so it does not apply when unguessable tick URLs ({{unguessable-urls}}) are used; in that case the full per-certificate URL is delivered through the provisioning channel and the SIA SHOULD NOT be published.
  A deployment that uses unguessable tick URLs therefore has a single discovery channel, the provisioning channel, with no SIA fallback.
  The CA MUST ensure that channel reliably delivers the complete per-certificate URL.

Keeping the base URL out of the certificate is not a secrecy measure, since the URL is derivable by anyone holding the certificate ({{rp-no-fetch}}).
It is instead a way to avoid standardizing a per-certificate fetch affordance in a field relying parties routinely parse.
Only the authenticating party is given the base URL through provisioning, because only it needs to refresh the value it presents; relying parties verify the embedded tick offline ({{verification}}) and MUST NOT fetch ticks ({{rp-no-fetch}}).
The base URL (or, for unguessable tick URLs, the full per-certificate URL) is delivered once at provisioning.
The authenticating party MUST retain it for as long as it presents the certificate and reuse it to refresh the tick each period ({{distribution}}), rather than rediscovering it per fetch.

MTC certificates are renewed frequently ({{Section 10.4 of !I-D.ietf-plants-merkle-tree-certs}} recommends renewal at about 75% of lifetime).
A CA that migrates its tick infrastructure can therefore update the base URL it hands out and rely on renewals to propagate the change, optionally serving HTTP redirects from the old origin in the meantime.

## ACME Integration {#acme-integration}

When the CA issues certificates via ACME, it SHOULD convey the tick base URL in the ACME order object as a new field:

~~~json
"tickBaseURL": "https://mtcrs.cdn.ca.example"
~~~

The `tickBaseURL` field contains the base URL (an origin) from which the authenticating party derives its tick fetch URL, by appending `/.well-known/mtcrs/v1/tick/{tbs_cert_entry_hash}` ({{distribution}}).
A single value covers all of the CA's certificates and lets the CA direct authenticating parties to a CDN, regional mirror, or any origin, without adding bytes to the certificate or log entry.

If the `tickBaseURL` field is absent from the ACME order, the authenticating party obtains the base URL through another mechanism in {{discovery}} (for example, the CA certificate SIA).

A CA using the unguessable-URL scheme ({{unguessable-urls}}) instead carries the complete per-certificate URL in a `tickURL` field in place of `tickBaseURL`.
The two fields are mutually exclusive for a given order: an order carries `tickBaseURL` (derivable scheme) or `tickURL` (unguessable scheme), never both.

CAs using issuance protocols other than ACME SHOULD provide an equivalent mechanism for communicating the tick base URL during certificate provisioning.

## Unguessable Tick URLs {#unguessable-urls}

The tick fetch path described above is `.well-known/mtcrs/v1/tick/{tbs_cert_entry_hash}`, and {tbs_cert_entry_hash} is derivable from the certificate by anyone who holds it, including a relying party ({{rp-no-fetch}}).
Keeping the base URL out of the certificate therefore does not make the tick URL unguessable.
A CA that wishes to make relying-party fetching infeasible by construction, rather than only forbidding it normatively, MAY replace the derivable path component with an unguessable per-certificate capability token:

~~~
{tick_base_url}/.well-known/mtcrs/v1/tick/{tick_token}
~~~

`tick_token`:
: A high-entropy (at least 128-bit) value that does not appear anywhere in the certificate.
  Because the token is absent from the certificate, a relying party cannot construct the URL, while the authenticating party is given it at provisioning time (see below).

The CA MAY generate the token by either of the following methods:

- **Random, with server-side state.**
  The CA generates a random token per certificate and maps it to the corresponding hash chain.
  This adds one indexed lookup to the CA's existing per-certificate state.

- **Deterministic, stateless (RECOMMENDED).**
  The CA derives the token by applying a deterministic authenticated encryption scheme (for example, AES-SIV {{?RFC5297}}) keyed by a CA-held secret to the entry identifier:

      tick_token = key_id || DAE(K_ca, tbs_cert_entry_hash)

  The CA recovers `tbs_cert_entry_hash` by decrypting the token, so no additional per-certificate state is required.
  The token is unguessable without K_ca and is stable for the certificate's lifetime, which preserves caching.
  The key_id prefix identifies K_ca so that it can be rotated; the CA retains superseded keys for decryption during an overlap window, and because MTC certificates are renewed frequently, rotated tokens propagate through renewal, as for base-URL migration ({{discovery}}).

When this hardening is used, discovery is necessarily per-certificate: the CA delivers the complete tick URL (base URL and token together) to the authenticating party through the provisioning channel.
For ACME, the order object carries the full URL in a `tickURL` field in place of `tickBaseURL` ({{acme-integration}}).
The CA-certificate SIA ({{discovery}}) conveys only the per-CA base URL, which cannot locate a token-addressed tick, and only the provisioning channel carries the token.
The SIA therefore provides no operational value when unguessable tick URLs are used, and a CA that uses them SHOULD NOT publish the id-ad-mtcrsTicks access method.

This hardening preserves the properties of the base HTTP interface: each token addresses a value that is immutable within a period, so per-period caching and CDN distribution ({{load-distribution}}) are unchanged.

The token is an addressing capability, not a confidentiality secret, and this hardening is defense in depth rather than a hard security boundary.
The tick it locates is public and self-authenticating, so the fetch still requires no transport-layer integrity or confidentiality and MAY be served over plain HTTP.
The token is correspondingly a bearer capability: an authenticating party could disclose it, and an on-path observer of a plain-HTTP fetch can see it.
Possession of it grants only the ability to fetch that public value, or to observe its absence.
It does not permit forging ticks, which requires the secret hash chain values ({{seed-confidentiality}}), nor using the certificate, which requires the corresponding private key.
Its benefit is that a relying party, or a third party holding a captured certificate, can no longer derive the tick URL from the certificate and probe the CA for its status ({{rp-no-fetch}}).

## Response Format {#response-format}

The response body is the serialized HashChainTick structure: a 4-byte big-endian period followed by HASH_SIZE bytes of value (36 bytes total for SHA-256).
The response Content-Type MUST be `application/octet-stream`.

The CA uses HTTP status codes ({{!RFC9110}}) as follows:

- **200 (OK):** the response body is the current HashChainTick for the entry. During period 0 the current tick is the public anchor paired with period 0 ({{revealing-values}}), so a CA whose distribution service is already provisioned for the entry MAY serve it. This is permitted but not required. The period 0 grace exists precisely so that provisioning need not be complete at the instant of issuance ({{period-zero-rationale}}), and an authenticating party can construct that tick from the anchor committed in its own certificate in any case.
- **404 (Not Found):** the CA is not serving a current tick for this entry. This covers both a revoked certificate, for which the CA has stopped revealing values ({{revoking}}), and a tick that is merely not yet available, as during the period 0 grace ({{period-zero-rationale}}). The status code does not distinguish these cases, so an authenticating party MUST NOT treat a 404 as definitive proof of revocation; it means only that no fresh tick was obtained on this attempt. The authenticating party continues to serve its most recent still-valid tick and MAY retry (see the Operational Model below).
- **410 (Gone), optional:** the server knows that no further tick will ever be published for this entry, because the certificate has been revoked ({{revoking}}), or because it has expired and tick publication has stopped ({{revealing-values}}). A CA MAY return 410 in place of 404 where it holds that knowledge, but is never required to. A delegated distributor generally cannot produce it at all: the CA revokes by dropping the entry from subsequent bundles, so a distributor cannot distinguish a revoked entry from one it was never given ({{delegated-distribution}}). A 410 is a diagnostic hint and nothing more. It is unsigned and MAY be carried over plain HTTP ({{distribution}}), so an on-path observer or a faulty distributor can forge one. An authenticating party MUST NOT let it curtail a tick that is still within the acceptance window (see the Operational Model below). Nor may its absence be read the other way: a plain 404 says nothing about whether the certificate is revoked, so an authenticating party or monitor MUST NOT infer non-revocation from the lack of a 410.
- **429 (Too Many Requests) or 503 (Service Unavailable):** transient overload; the authenticating party retries according to the Retry-After header ({{load-distribution}}).

Any other status code carries its ordinary HTTP semantics ({{!RFC9110}}); an authenticating party treats any non-200 response as "no fresh tick obtained on this attempt" and falls back to its most recent still-valid tick.

Requiring the period 0 tick to be served, rather than permitting it, would not make a 404 mean "revoked".
Revocation is only one of several causes of a missing tick.
An origin outage, a cache or edge miss, and a delegated distributor that has not yet received the current bundle ({{delegated-distribution}}) all yield the same status code, in every period.
During period 0 a 404 cannot mean revoked at all, because the earliest period for which the CA can withhold a secret value is period 1 ({{revoking}}).
The ambiguity is therefore neither introduced nor removed by the period 0 case, and enforcement rests throughout on the presence of a fresh tick rather than on the absence of one ({{revocation-transparency}}).

The CA SHOULD set HTTP cache headers with a max-age no longer than `tick_interval` seconds.
For example:

~~~http-message
Cache-Control: public, max-age=3600
~~~

## Operational Model

For each certificate it serves, the authenticating party periodically fetches that certificate's current tick from the CA:

1. At least once per `tick_interval`, the authenticating party fetches an updated HashChainTick for the certificate.

2. Before installing a fetched tick, the authenticating party MUST verify it against the anchor committed in its own certificate: that hashing `tick.value` forward `tick.period` times yields the anchor ({{verification}}).
   A tick that fails this check MUST NOT be installed or presented; the authenticating party discards it and continues to serve its most recent still-valid tick, retrying as under {{response-format}}.
   This catches a corrupted, truncated, or misrouted (wrong-entry) response before it is ever presented in a handshake, where it would otherwise cause relying parties to reject the certificate.
   The authenticating party SHOULD additionally check that `tick.period` is the period it currently expects, so that an unexpectedly stale or future-dated response is also rejected; because a stale-but-genuine tick still hashes to the anchor, only this freshness check detects it.
   This part is a SHOULD rather than a MUST because clock skew between the authenticating party and the CA can legitimately shift the served period by one ({{clock-skew}}).
   A deployment MAY narrow it to strict equality where both clocks are trusted.

3. The authenticating party updates the HashChainTick carried in its certificate's MTCProof (`signatureValue`) with the newly fetched value.
   The inclusion proof and cosignatures remain unchanged.

4. During TLS handshakes, the authenticating party presents the certificate with the current tick.

During period 0 the authenticating party need not fetch at all: the period 0 tick is the public anchor committed in its own certificate ({{revealing-values}}), which it can construct and present directly.
A 404 during period 0 is therefore expected and harmless, because the CA has until the start of period 1 to begin serving the entry's ticks ({{period-zero-rationale}}).
A CA already provisioned for the entry may equally return that tick with a 200 ({{response-format}}), which the authenticating party has no need of either way.
This does not apply to a certificate whose `notBefore` was backdated by one `tick_interval` or more, which is already past period 0 when it is issued: its first fetch must succeed before it can be served ({{construction}}).

Repeated failure to obtain a fresh tick after period 0 is different.
It is the observable signature of either revocation ({{revoking}}) or a distribution failure, and a 404 does not tell the authenticating party which ({{response-format}}).
An authenticating party SHOULD therefore raise an operational alarm once it has failed to obtain a fresh tick for a full `tick_interval`, rather than waiting until the certificate stops working.
By then it has at most one period of runway left.
Where the server offers the optional 410 ({{response-format}}), the authenticating party learns that no further tick is coming.
It can then attribute that alarm correctly, stop retrying an entry that will never be served again, and begin provisioning a replacement certificate.
Because the signal is unauthenticated, it MUST NOT cause the authenticating party to stop presenting a tick that is still within the acceptance window.
Treating a forged 410 as grounds to withdraw a healthy certificate would hand anyone able to inject a response a remote kill switch, which is a worse position than simply continuing to serve the valid tick it already holds.
An authenticating party that holds a certificate from another CA SHOULD fail over to it before its newest tick leaves the acceptance window ({{availability-considerations}}), which restores service whichever of the two causes applies.
Continuing to present a certificate whose newest tick has already fallen outside that window achieves nothing: every relying party implementing this mechanism rejects it (step 4 of {{verification}}).

The authenticating party may be unable to obtain a fresh tick, for example because the CA is unavailable.
It then continues to serve the most recent tick it holds for as long as that tick remains within the acceptance window (step 4 of {{verification}}).
Because a relying party also accepts the immediately preceding period's tick, a tick fetched for period t stays acceptable until the end of period t+1.
That is close to two periods of runway from a single successful fetch, not one ({{availability-considerations}}).
Once that runway is exhausted, the certificate becomes unusable until a fresh tick is obtained or a new certificate is provisioned.
{{availability-considerations}} discusses this dependency and its mitigations, including widening the acceptance window ({{clock-skew}}) and holding certificates from multiple CAs.

At large deployment scale, tick distribution is dominated by aggregate request volume rather than per-request cost.
A CA serving 10<sup>9</sup> active certificates with a one-hour period sees on the order of 10<sup>5</sup> to 10<sup>6</sup> tick requests per second, and this load tends to concentrate at period boundaries if authenticating parties refresh in lockstep.
At this scale, edge caching (each tick is immutable within its period and cacheable for up to `tick_interval` seconds) and spreading of client refresh timing are required, not merely recommended, to avoid a thundering-herd load on the origin.
{{load-distribution}} describes recommended techniques.

## Distributing Tick Requests {#load-distribution}

Because a relying party also accepts a tick for the immediately preceding period ({{verification}}), an authenticating party has up to one full `tick_interval` of slack in which to fetch each new tick and need not fetch at the period boundary.
Two complementary mechanisms exploit this slack to prevent a period-boundary thundering herd.

### Client-Side: Deterministic Per-Entry Offset

Rather than fetching at the start of each period, an authenticating party SHOULD fetch at a fixed offset into the first half of the period, derived deterministically from its own `tbs_cert_entry_hash`:

~~~pseudocode
offset = UINT32(tbs_cert_entry_hash[0..3])
         mod max(1, tick_interval / 2)
~~~

where `tbs_cert_entry_hash` is the binary hash defined in {{distribution}}, UINT32 interprets its first four bytes as a big-endian unsigned integer, and the division is integer division.
The authenticating party computes this from its own entry, so the offset is available even when the tick URL is addressed by an unguessable token ({{unguessable-urls}}) rather than by `tbs_cert_entry_hash`.
The authenticating party fetches the current period's tick at (period_start + offset), where period_start is the start time of that period.
During the first offset seconds of the period it continues to serve the preceding period's tick.
The serving delay and a verifier whose clock runs ahead both draw on the same one-period preceding-tick grace ({{clock-skew}}).
A verifier whose clock is ahead by more than (`tick_interval` - offset) already expects the following period and rejects a tick two periods behind its expectation.
Bounding the offset to half of `tick_interval` leaves at least half a period of that grace available to absorb verifier clock skew, while still spreading fetches across a wide window.

Because entry hashes are uniformly distributed, deriving the offset this way spreads fetches uniformly across the period with no coordination, shared state, or central scheduler, and the offset is stable from period to period, which aids caching and diagnosis.
This is preferable to independent random jitter, which can still cluster and which varies each period.

### Server-Side: Cache Freshness and Retry-After

The CA (or an edge cache) SHOULD serve each tick with a Cache-Control max-age no longer than `tick_interval` seconds ({{response-format}}), so that a caching layer collapses many client requests for the same entry into a single origin fetch per period.
A CA MAY additionally apply a small per-response jitter to max-age so that cache entries for different entries do not all expire simultaneously.

Under transient overload, the CA or edge MAY respond with HTTP status code 429 (Too Many Requests) or 503 (Service Unavailable) together with a Retry-After header indicating when the authenticating party should retry.
To avoid a synchronized second wave, the CA SHOULD randomize Retry-After values across clients rather than returning a single fixed value.
Because the authenticating party retains its previously fetched tick, which remains valid until the end of the current period, backing off in response to Retry-After does not interrupt service, provided a fresh tick is obtained before the previous one expires.

The deterministic per-entry offset above and edge caching together flatten period-boundary load: the offset spreads fetches uniformly across the period, and caching collapses the fetches for each entry into a single origin request per period regardless of client timing.
At large scale these are required rather than merely recommended, as the Operational Model ({{distribution}}) notes.
This document nonetheless specifies them as SHOULD rather than MUST, because fetch timing is not observable to relying parties and affects neither interoperability nor the security of verification.
A specific load-shaping or availability target is left to root-program or CA operational policy.

## Bulk Retrieval for Large Deployments {#bulk-retrieval}

The HTTP interface ({{distribution}}) addresses one tick per request, so an operator fronting many certificates, such as a large hosting provider or CDN, issues on the order of N fetches per period for N certificates.
The per-entry offset ({{load-distribution}}) spreads them across the period but does not reduce their number.
This stays inexpensive.
Each tick is a 36-byte value that is immutable within its period and cacheable ({{response-format}}), and HTTP/2 and HTTP/3 multiplex many such small requests over a few persistent connections, so N fetches is not N connections or N round-trip stalls.
An operator that prefers fewer requests can front its certificates with its own cache, or act as a delegated distributor ({{delegated-distribution}}).
The CA-to-distributor bundle is exactly a bulk transfer of the currently-revealed ticks, so taking that feed obtains all of them in one exchange.

A CA MAY additionally offer a batch endpoint keyed by a list of `tbs_cert_entry_hash` values (or tokens; {{unguessable-urls}}).
The trade-off is cacheability: a batch response is specific to the set requested, and so is far less cacheable by generic HTTP intermediaries than the per-entry GETs.
It therefore suits an operator fetching from the CA or a mirror it controls rather than from a shared edge cache.
This document does not standardize a batch wire format.
Like the choice of distribution channel generally ({{distribution}}), any such mechanism is an agreement between a CA and its authenticating parties layered on the single-tick interface, which remains the interoperable baseline.
It does not affect relying parties, who never fetch ({{rp-no-fetch}}).

## Delegated Tick Distribution {#delegated-distribution}

Because a tick is self-authenticating ({{verification}}), the party that serves ticks need not be trusted for integrity or authenticity.
A distributor cannot forge a tick for a period the CA has not revealed (preimage resistance; {{hash-function-requirements}}), and cannot serve a tampered value that verifies.
Tick distribution is therefore safe to delegate to third parties, which serve only public, self-authenticating values and hold no seed and no signing key.

The CA publishes to its authorized distributors the value currently revealed for each entry, as a bundle keyed by `tbs_cert_entry_hash`, refreshing it as certificates advance through their own periods ({{construction}}).
Each distributor serves those values through the HTTP interface of {{distribution}}.
To revoke a certificate, the CA drops its entry from subsequent refreshes: absence is revocation, so no revocation list is exchanged.
Because a distributor only ever receives already-revealed values, compromising it exposes nothing that is not already public and does not let it defeat revocation.

MTC mirrors are a natural home for this role.
They already replicate and serve MTC log data at high availability, and extending a mirror to also serve the currently-revealed ticks reuses that infrastructure without adding any trust, since the ticks it serves are self-authenticating.
Content delivery networks and relying-party-side operators can serve as distributors on the same terms, including browser providers, which already run large-scale revocation-distribution infrastructure.
Because none of them is trusted for integrity, a CA MAY spread distribution across anycast, several independent CDNs, or several delegated distributors concurrently with no added trust, removing the CA origin as a single point of failure.
The level of redundancy a CA must provide is a matter for root-program or CA policy rather than an interoperability requirement of this document.
Operating such a service is distinct from the prohibition in {{rp-no-fetch}}, which forbids a relying party from using the endpoint as its own online responder during validation.
It does not prevent a relying-party-side organization from running a distribution service that authenticating parties fetch from.
The only trust placed in any distributor is for availability, addressed by operating several and by the multi-CA strategy of {{availability-considerations}}.

What is delegated is distribution, not revocation authority.
The CA retains the seed and the unrevealed hash chain values ({{seed-confidentiality}}), so it alone decides what to reveal each period.
A distributor can at most withhold or delay the values it was given ({{dos-withholding}}), which is an availability fault mitigated by redundancy, not a way to un-revoke a certificate.

A CA MAY publish only values that are already revealed, in which case each distributor depends on the CA for every refresh and the CA retains tight, sole control of revocation.

Alternatively, as part of disaster-recovery planning, a CA MAY pre-provision a distributor with a small buffer of future periods' values, so that the distributor can keep certificates usable through a CA-side outage.
This is continuity (liveness) delegation, not delegation of revocation.
Sharing future ticks lets the holder keep certificates alive.
It correspondingly removes the CA's ability to revoke them through that distributor for the buffered window, because a certificate cannot be revoked from a distributor that already holds its future values.
The buffer length therefore caps how quickly those certificates can be revoked through the hash chain; during the window the only remaining lever is the base MTC revoked-ranges fallback ({{interaction-with-base-mtc-revocation}}), which the CA controls independently.
Future values held by a distributor are as sensitive as the CA's own unrevealed hash chain values ({{seed-confidentiality}}): compromising the distributor lets an attacker keep a revoked certificate alive for the remainder of the buffer.
A CA SHOULD therefore keep the buffer short, sized to its outage-tolerance versus revocation-latency budget, the same trade-off as the period-0 grace ({{period-zero-rationale}}).
It SHOULD pre-provision only distributors trusted to stop serving on the CA's instruction.

Such a buffer is compact and inherently bounded.
For a buffer of N periods the CA need send each distributor only a single value per certificate: the value that will be revealed N periods ahead.
From that the distributor derives every intervening period's value by hashing forward ({{revealing-values}}).
One value per certificate thus covers the whole buffer, and it confers no power beyond period t+N, since serving any later period would require inverting the hash.
A CA MUST NOT instead share the seed-derivation secret ({{derived-seeds}}) with a distributor: unlike a bounded buffer of already-revealed values, that secret would grant the unbounded ability to forge non-revocation for the entire certificate population.

This prohibition holds even in disaster recovery: a CA facing an unrecoverable failure MUST NOT hand its seed-derivation secret or per-certificate seeds to a successor operator as a continuity measure.
That secret is as sensitive as the issuance signing key ({{derived-seeds}}), so transferring it is a root-key-custody event that destroys forward security and hands over unbounded forging power.
It is also unnecessary.
The bounded buffer above keeps already-issued certificates usable through the outage, and because MTC certificates are short-lived ({{Section 10.4 of !I-D.ietf-plants-merkle-tree-certs}}) the failing CA's population ages out while subscribers migrate to a successor issuing under its own key and seed.
If the disaster is itself a seed or key compromise, the response is the revoked-ranges fallback ({{interaction-with-base-mtc-revocation}}), not wider custody of a possibly-tainted secret.

The feed from CA to distributor SHOULD be authenticated and integrity-protected.
This is not required for relying-party security, which rests on self-authentication and the authenticating party's own pre-installation check ({{verification}}), but it prevents a distributor from being fed corrupt bundles that would cause authenticating parties to reject ticks and refetch.

# Privacy Considerations

The Privacy Considerations of the base MTC specification ({{Section 11 of !I-D.ietf-plants-merkle-tree-certs}}) apply to Merkle Tree Certificates that use this mechanism.
This mechanism adds one network interaction, the authenticating party's periodic tick fetch ({{distribution}}), and deliberately adds none on the relying-party side.

No relying-party activity is exposed.
The current tick is embedded in the certificate presentation and verified offline against the committed anchor, and relying parties MUST NOT fetch ticks ({{rp-no-fetch}}).
Consequently the CA learns nothing about which certificates a relying party validates or which sites it visits.
This is the central privacy difference from client-driven OCSP {{?RFC6960}}, whose status fetches revealed relying-party browsing to the CA; that failure mode is avoided here by construction rather than by policy.

The authenticating party's tick fetch, by contrast, exposes request metadata.
An on-path observer of a tick fetch, or the CA (or CDN) serving it, sees which `tbs_cert_entry_hash` is being requested, or with unguessable tick URLs which `tick_token` ({{unguessable-urls}}).
It can thereby learn which certificate the authenticating party holds.
For a public-facing server this reveals little, since the certificate it serves is itself public; the request identifies the authenticating party's own certificate, not any relying party.
Two points nonetheless bear noting:

- Because a tick is self-authenticating and public, the fetch does not require transport-layer confidentiality for correctness, so a CA MAY serve ticks over plain HTTP ({{distribution}}). Plain HTTP leaves the requested `tbs_cert_entry_hash` or `tick_token` visible to on-path observers. A deployment that considers this metadata sensitive, for example one serving certificates that are not otherwise publicly enumerable, SHOULD publish an https base URL instead.
- Unguessable tick URLs ({{unguessable-urls}}) are an addressing and access-control measure, not a confidentiality one: the `tick_token` appears in the request URL, so it offers no confidentiality against an observer of the authenticating party's own fetch. Its privacy benefit is solely that a relying party, or a third party holding only the certificate, cannot derive the URL and probe the CA for the certificate's status ({{rp-no-fetch}}).

Pushed revocation lists such as {{CRLite}} and {{CRLSets}} are checked by the client entirely offline.
This mechanism preserves the same relying-party privacy, since the client fetches nothing either way, and does so universally, for any TLS client rather than only browsers that ship the list.
Its one difference is the authenticating party's own fetch, and that metadata concerns the server's own public certificate (whose liveness a public server already exposes by answering connections), not any relying party.
It also need not reach the CA at all.
Because ticks are self-authenticating, distribution can be delegated to CDNs, mirrors, or other distributors ({{delegated-distribution}}), so the server fetches from a distributor rather than the CA and the CA observes no per-server fetch pattern.
Caching leaves the origin seeing aggregated cache-miss traffic rather than every server's every-period fetch.

# Security Considerations

## Hash Function Requirements {#hash-function-requirements}

The security of this mechanism depends on the preimage resistance of the hash function used.
SHA-256 {{!SHS=DOI.10.6028/NIST.FIPS.180-4}} provides 256 bits of preimage resistance, which is sufficient for all foreseeable certificate lifetimes.
With a one-hour `tick_interval` and a 47-day lifetime, the hash chain length is 1,128, which does not meaningfully degrade the security margin.

## Post-Quantum Considerations {#post-quantum}

This mechanism is post-quantum robust as specified and needs no migration to a new primitive.
Its security rests solely on the preimage resistance of the hash function, for which the best known quantum attack is Grover's algorithm, a quadratic speed-up.
Against SHA-256 that leaves work on the order of 2<sup>128</sup>, an ample margin for all foreseeable certificate lifetimes.
The non-revocation proof relies on no collision resistance, because a revealed value is bound to a specific hash chain by the committed anchor and the per-entry domain separation of {{encoding}}, not by any collision property.
The weaker quantum bounds on collision finding therefore do not apply (`tbs_cert_entry_hash`, the sole hash used for uniqueness rather than as part of the proof, is discussed under {{distribution}}).
It also inherits whatever hash the CA's issuance log uses ({{construction}}), so a CA that moves to a larger or post-quantum-oriented hash carries this mechanism along with no change here.

Just as importantly, this mechanism keeps post-quantum signatures off the per-period revocation path.
A signed-status approach, using OCSP-like per-certificate signatures ({{per-cert-signatures}}), would require a post-quantum signature per certificate per period (for example an ML-DSA-65 signature of roughly 3,309 bytes), whereas a tick is 36 bytes of hash output and is never signed.
Adopting hash-chain revocation is therefore aligned with a post-quantum transition rather than a distraction from it: it removes post-quantum signing from the revocation path instead of adding it.

## Seed Confidentiality {#seed-confidentiality}

The CA MUST keep the hash chain seed (h\[0\]) and all not-yet-revealed hash chain values confidential.
Compromise of these values would allow an attacker to produce future ticks, defeating revocation.

A CA that derives per-certificate seeds from a single long-term secret ({{derived-seeds}}) concentrates this requirement into that secret.
It MUST then be protected at least as strongly as the issuance signing key, and per-log or per-epoch sub-seed derivation SHOULD be used to bound the impact of a compromise.
Such derivation MUST use a keyed KDF or PRF (for example HKDF or HMAC); a raw `Hash(ca_seed || ...)` construction MUST NOT be used, as it invites length-extension and MAC-misuse and can make derived seeds distinguishable from independent random seeds ({{derived-seeds}}).

If the CA's seed storage is compromised, the CA MUST revoke all affected certificates via the base MTC revocation mechanism (revoked ranges of serial numbers) as a fallback; see {{interaction-with-base-mtc-revocation}}.

## Denial of Service via Tick Withholding {#dos-withholding}

A compromised or malicious CA could withhold ticks from a legitimate authenticating party, either broadly or targeted at a specific subscriber.
In the targeted case it revokes that certificate with no auditable signal.
This is analogous to a CA refusing to issue OCSP responses, or refusing to issue or renew certificates at all.
It is inherent in the CA trust model rather than novel to this mechanism, and it is mitigated by the same forces that discipline CA behaviour today:

- **Detectability.** The authenticating party knows it did not receive a tick, and can raise an alarm, switch to another CA, or fall back to a traditionally-signed certificate.
- **Third-party observability.** The tick distribution endpoint can be monitored externally (Certificate Transparency-style auditing {{?RFC9162}}), making selective withholding observable.
- **Market pressure.** An authenticating party that cannot reliably obtain ticks will switch CAs.

Because ticks are small and cacheable, they are readily distributed via CDN, which further reduces the attack surface for withholding.

The converse exposure is load rather than withholding.
The endpoint is public and unauthenticated, and in the derivable-URL scheme its addresses can be computed by anyone holding a certificate or reading the log ({{rp-no-fetch}}).
A third party can therefore fetch any entry's tick, and can do so in volume.
This is the ordinary position of a public static HTTP endpoint, and it is met by the ordinary means: caching, rate limiting, and CDN or anycast capacity ({{load-distribution}}).
These are effective here because every response is an immutable, precomputed per-period value that costs the origin nothing to produce ({{operational-resilience}}).
Unguessable tick URLs ({{unguessable-urls}}) additionally deny an attacker the ability to address entries it has not seen.
What such flooding cannot do is defeat revocation: it neither forges a tick nor suppresses one that an authenticating party has already fetched and installed.

## Relying Parties Do Not Fetch Ticks {#rp-no-fetch}

The current tick is embedded in the MTCProof presented during the handshake and is verified offline against the anchor committed in the Merkle Tree ({{verification}}).
A relying party therefore has no need to contact the CA, and MUST NOT fetch ticks or otherwise use the tick distribution endpoint as an online revocation responder.

This is a privacy and availability protection, not a secrecy one.
The tick distribution URL is not secret: the fetch path is `.well-known/mtcrs/v1/tick/{tbs_cert_entry_hash}` with {tbs_cert_entry_hash} computable by anyone holding the certificate, and the origin is low-entropy and, when the CA certificate SIA ({{discovery}}) is used, available to relying parties as well.
By default the design does not, and cannot, technically prevent a relying party from constructing the URL and fetching; it declines to standardize or advertise such a fetch as an affordance to relying parties.
A CA that wishes to remove this derivability entirely MAY use the optional per-certificate capability-token hardening in {{unguessable-urls}}, which makes the tick URL unguessable to a party holding only the certificate.
A relying-party fetch would gain nothing over the embedded tick, since the authenticating party already presents the current value.
It would meanwhile reintroduce the CA-visibility of relying-party activity (the CA learning which sites a relying party visits), the added latency, and the soft-fail behaviour that made client-driven OCSP {{?RFC6960}} problematic.

The CA certificate SIA access method ({{discovery}}) exists to convey the base URL to authenticating-party tooling.
Relying parties possess the CA certificate but MUST NOT use its tick base URL to fetch tick status.

## Unauthenticated Proof Extensions

The RECOMMENDED trailing `status_tick` encoding ({{tick-trailing-field}}) appends a fixed-size, fully verified value and so adds no general "ignore if unknown" region.
If the base specification instead adopts the alternative `proof_extensions` encoding ({{mtcproof-extensibility}}), note that this field is not committed to the Merkle Tree and is covered by no signature: it is mutable and can carry data that relying parties ignore.
Hash chain revocation does not rely on its authenticity, because the tick is self-authenticating and its presence is mandated by the committed id-pe-hashChainAnchor extension.
{{proof-extensions-considerations}} discusses the general risks of this field (bloat, covert channels, and a strippable soft-fail for other mechanisms) and the constraints recommended for the base specification.

## Interaction with Base MTC Revocation {#interaction-with-base-mtc-revocation}

The hash chain mechanism complements rather than replaces the base MTC revoked ranges mechanism.
Revoked ranges are relying-party configuration: each relying party maintains, per CA, a list of revoked serial-number ranges, seeded from the CA certificate's minSerial and maxSerial and extended from out-of-band sources ({{Section 7.5 of !I-D.ietf-plants-merkle-tree-certs}}).
They are therefore closer in kind to CRLite {{CRLite}} or CRLSets {{CRLSets}} than to a logged or signed artifact: pushed state, distributed out of band, effective only for relying parties that receive it.
Nothing about a revoked range is committed to the Merkle Tree.
Revoked ranges provide a fallback for scenarios where the hash chain mechanism is insufficient:

- Compromise of the CA's hash chain seed storage
- Bulk revocation of many certificates simultaneously
- Relying parties that have not yet implemented hash chain verification

Relying parties that support both mechanisms SHOULD check both: a certificate is considered revoked if either mechanism indicates revocation.
Whether to check the base MTC revoked ranges in addition to the hash chain is a relying-party policy choice ({{rp-policy}}).

This composition is one-directional.
Other revocation signals may only add grounds for revocation: the base MTC revoked ranges, or external systems such as CRLite {{CRLite}} or CRLSets {{CRLSets}}.
A relying party MAY consult them and MUST reject if any reports the certificate revoked.
A relying party MUST NOT, however, treat a "not revoked" result from any such mechanism as licence to accept a certificate whose tick is absent, stale, or fails verification.
Doing so would reduce this mechanism's hard-fail to the strippable soft-fail it is designed to prevent ({{ocsp-stapling-comparison}}).
A missing tick is thus a rejection in its own right.
Consulting another mechanism can nonetheless serve two diagnostic purposes when a tick is absent.
The first is distinguishing an actual revocation from a mere distribution outage, which a 404 does not ({{revocation-transparency}}).
The second is recovering the revocation reason (keyCompromise, cessationOfOperation, and so on) from a mechanism that does convey one, since a tick's absence carries no reason code ({{revocation-transparency}}).
Neither changes the safe action for an unproven tick, which remains rejection, subject only to the availability levers of {{availability-considerations}}.

## Revocation Transparency and Auditability {#revocation-transparency}

Revocation in this mechanism is the *absence* of a tick: the CA stops revealing hash chain values ({{revealing-values}}) and the certificate becomes unusable within two periods.
There is deliberately no positive, signed, non-repudiable artifact asserting "the CA revoked entry X as of period T."
This is a genuine difference from CRLs and OCSP, whose signed responses are such artifacts.
The base MTC revoked-ranges mechanism does not supply one either: it is relying-party configuration distributed out of band, not anything committed to the log ({{interaction-with-base-mtc-revocation}}).
The transparency here is asymmetric.
Opting a certificate *into* the mechanism is transparent, because the anchor is an extension committed to the Merkle Tree and so visible to monitors ({{assertion-integration}}).
The per-period revocation *state*, by contrast, is neither signed nor committed, so a monitor cannot observe it in the log.

Four consequences follow, each bounded:

- **Revocation is observable but not provable.**
  A monitor watching a certificate's tick endpoint can detect that ticks have stopped, but cannot by that alone prove the CA revoked it rather than suffered a distribution outage: a 404 does not distinguish the two ({{response-format}}).
  The mechanism therefore provides detection of withheld ticks ({{dos-withholding}}), not a non-repudiable revocation record.
  That is enough to discipline selective or covert withholding, which is externally observable and bounded by the same forces that discipline any CA, but it is not an audit trail of revocation decisions.

- **No revocation-event transparency in the log.**
  Because revealed ticks are not committed to the tree, the fact and time of a revocation are not recorded there.
  Nor do base MTC revoked ranges supply such a record, being relying-party configuration rather than log content ({{interaction-with-base-mtc-revocation}}), so no in-band, logged revocation record exists anywhere in MTC.
  A deployment that requires one uses an external system that provides it, either CRLs or OCSP, which apply to Merkle Tree Certificates unchanged ({{Section 12.7 of !I-D.ietf-plants-merkle-tree-certs}}), or a signed revocation feed published by the CA (see below).

- **No revocation reason codes.**
  A tick's absence carries no reason (keyCompromise, cessationOfOperation, and so on).
  Conveying a reason is out of scope here; a deployment that needs machine-readable reasons uses the base MTC revoked-ranges mechanism or an external revocation system that carries them.

- **No status after expiry.**
  Tick publication stops when the certificate expires ({{revealing-values}}), so no status can be obtained for an expired certificate, and because revocation is absence, nothing then distinguishes one that was revoked from one that was not.
  CRLs and OCSP can in principle answer past `notAfter`, which profiles for long-term signature validation depend on.
  This is out of scope for the TLS use case that motivates this mechanism, where an expired certificate is rejected on validity grounds before any tick is examined.
  A tick retained while the certificate was valid does remain verifiable indefinitely, since verification is offline hashing against the anchor in the certificate ({{verification}}).
  It is therefore durable, self-authenticating evidence of non-revocation as of its own period, in 36 bytes rather than an archived signed response.
  Only the negative cannot be reconstructed later.

None of this weakens enforcement, which is what the mechanism exists to provide.
A revoked certificate stops verifying at every relying party within the two-period bound ({{clock-skew}}) whether or not any auditable artifact exists, because enforcement depends on the *presence* of a fresh tick, not on a monitor observing its absence.
Auditability, where a deployment needs it, therefore comes from outside both this mechanism and the base revoked-ranges mechanism: from CRLs or OCSP, which apply unchanged ({{Section 12.7 of !I-D.ietf-plants-merkle-tree-certs}}), or from a signed revocation feed the CA publishes.
This document neither defines nor requires such a feed.

## Downgrade to a Non-MTCRS Certificate {#downgrade}

Hash chain revocation applies per certificate, not per key; more precisely, it applies per log entry carrying the id-pe-hashChainAnchor extension.
An attacker who holds a private key (the only party who can use any certificate for that key) could therefore present a different, still-valid certificate for the same key that does not carry the anchor extension, escaping tick enforcement.
Such certificates are outside this mechanism's scope and are handled exactly as in base MTC: by the per-serial revoked-ranges mechanism, which is independent of hash chain revocation, and bounded by the short lifetimes and trusted-validity windows of the base model.
A CA revoking a compromised key MUST therefore revoke all of that key's certificates, withholding ticks for those that use this mechanism ({{revealing-values}}) and revoking the serial ranges of the rest ({{interaction-with-base-mtc-revocation}}).
Withholding ticks alone would revoke only the certificates that carry an anchor.
This is the general property that revocation targets certificates rather than keys; it is not specific to this mechanism.

## Clock Skew {#clock-skew}

The default acceptance window of verification step 4 accepts a tick whose period is the verifier's `expected_period`, the immediately preceding period (`expected_period` - 1), or the immediately following period (`expected_period` + 1).
This tolerates a verifier clock that is behind or ahead of the authenticating party's by up to one full `tick_interval` in either direction.
It also tolerates an authenticating party that is still serving the previous period's tick for caching or staggered refresh ({{load-distribution}}).

The two directions are not equivalent in cost.
Accepting the immediately following period, which is what a verifier whose clock is behind will see, costs nothing in revocation terms.
That tick is a fresher non-revocation proof than the verifier expected, and a tick for a period the CA has not yet reached cannot be forged (preimage resistance; {{hash-function-requirements}}).
Accepting the immediately preceding period, which arises from a verifier clock that is ahead or from a deliberately stale tick, accepts a non-revocation proof up to one `tick_interval` old.
That is the intended one-period grace.

Deployments with known clock-skew or availability concerns MAY widen the window, as step 4 permits.
Accepting further preceding periods tolerates a tick-distribution outage ({{availability-considerations}}) at the cost of correspondingly delayed revocation enforcement, while accepting further following periods tolerates a verifier clock that runs further behind and carries no revocation cost.

Widening the preceding side relaxes the revocation bound one-for-one.
A relying party that accepts the k immediately preceding periods keeps a withheld certificate usable for up to k + 1 periods after the CA stops revealing values, in place of the two periods the default window gives ({{revealing-values}}).
The worst-case revocation latency stated elsewhere in this document, at most two periods, therefore assumes the default window.
How quickly revocation takes effect at a given relying party is a property of that relying party's policy, not of the hash chain; this is why widening is a deliberate, ecosystem-wide trade-off rather than a per-server option ({{rp-policy}}).

The acceptance window is anchored to the relying party's own clock, so revocation timeliness depends on that clock's integrity.
A clock running behind true time shifts the window toward the past, so a genuine but stale tick, one the CA revealed before it stopped revealing, can fall inside the window and be accepted.
An attacker who moves a relying party's clock backward can thereby keep a revoked certificate acceptable for roughly the induced offset, bounded by the window width and ultimately by `notAfter`, checked against the same clock.
The forward direction adds no forgery avenue.
A tick for a period the CA has not yet reached cannot be produced without inverting the hash ({{hash-function-requirements}}), so the exposure comes entirely from the clock being wrong, not from accepting a fresher-than-expected proof.
This is not something specific to this mechanism.
It is the trusted-time dependency shared by every time-based validity and revocation check: `notAfter`, OCSP thisUpdate/nextUpdate, CRL validity, and the base MTC short-lived-certificate model itself.
Two consequences follow.
First, the acceptance window SHOULD be kept as narrow as clock quality allows, since widening it for outage tolerance enlarges this exposure.
Second, a deployment whose relying parties cannot trust their clocks gains little revocation timeliness from a short `tick_interval`, because the clock error, not the period, then bounds how long a revoked certificate remains acceptable.
A relying party that requires tight revocation SHOULD therefore source time from a trusted, integrity-protected clock.
Both this and the window width are relying-party policy choices ({{rp-policy}}).

## Relying-Party Policy Levers {#rp-policy}

Several behaviours of this mechanism are configurable by relying-party (client) policy, which a root program may also set.
This section collects them for convenience; each is specified in full in the section cited, and nothing here is a new requirement.

Acceptance window:
: The default accepts a tick for the current, immediately preceding, or immediately following period.
  A relying party MAY widen the preceding side to tolerate a tick-distribution outage, at the cost of correspondingly delayed revocation, or the following side to tolerate a clock that runs behind, at no revocation cost.
  Widening applies to every certificate the relying party validates ({{clock-skew}}, {{availability-considerations}}).

Trusted time:
: The acceptance window is anchored to the relying party's clock, so revocation timeliness is bounded by clock integrity.
  A relying party that requires tight revocation SHOULD source time from a trusted, integrity-protected clock and keep its window narrow ({{clock-skew}}).

Cross-checking base MTC revocation:
: A relying party that also supports the base MTC revoked-ranges mechanism SHOULD check both; a certificate is revoked if either indicates so ({{interaction-with-base-mtc-revocation}}).

Resumption and long-lived connections:
: The tick is checked only at full-handshake certificate validation.
  A relying party that wants revocation to take effect within about one `tick_interval` SHOULD cap session-ticket reuse and force periodic full handshakes, so that a fresh tick is re-checked ({{enforcement-latency}}).

Enforcement and criticality:
: A relying party that implements this mechanism MUST enforce hash chain verification whenever the id-pe-hashChainAnchor extension is present; an ecosystem MAY additionally mark the extension critical for hard enforcement ({{extension-criticality}}).

Fixed, not a lever:
: Relying parties MUST NOT fetch ticks or use the distribution endpoint as an online responder ({{rp-no-fetch}}); this is a constraint, not a configurable choice.

If the base specification adopts the general `proof_extensions` field ({{mtcproof-extensibility}}), further relying-party handling applies: size-budget enforcement, committed admissibility, and unknown-type handling ({{proof-extensions-considerations}}).

The resilience levers that involve holding certificates from multiple CAs, operating redundant tick distribution, and choosing `tick_interval` are authenticating-party or CA decisions, not relying-party policy ({{availability-considerations}}, {{construction}}).

# Operational and Availability Considerations {#operational-considerations}

This section covers the operational characteristics of the mechanism that are not security properties in themselves: the availability dependency introduced by periodic tick refresh, and the client-side latency of handshake-time revocation checks.

## Availability Considerations {#availability-considerations}

Because an authenticating party must fetch a fresh tick at least once per `tick_interval` ({{distribution}}), a tick-distribution outage lasting longer than one period renders the affected certificate unusable until a fresh tick is obtained.
This is an availability dependency that the base MTC short-lived-certificate model does not have, and deployments SHOULD plan for it.
It is intrinsic to enforceable revocation rather than a defect.
A mechanism that let a server keep presenting a usable certificate regardless of CA state would, by construction, fail open, which is the soft-fail behaviour this design rejects ({{ocsp-stapling-comparison}}).
The goal is therefore to bound the dependency, not to eliminate it; several factors and mitigations limit its impact:

- **The tick interval is the outage-tolerance budget.**
  A one-hour period gives on the order of one period of tolerance for tick-distribution unavailability before a certificate becomes unusable, and up to about two periods from a single successful fetch (see below).
  A one-day period scales that to the order of a day, at the cost of proportionally delayed revocation enforcement.
  Deployments choose `tick_interval` to balance revocation latency against their realistic availability expectations for tick distribution.

- **The dependency is on a lightweight service.**
  Fetching a tick is a single lightweight HTTP GET with no per-request cryptography.
  It is far less fragile than ACME issuance or an OCSP responder, and simpler to operate and more resilient than the latter ({{operational-resilience}}).
  Because the authenticating party retains a full period of buffer, brief outages are invisible to relying parties.

- **The acceptance window can be widened, deliberately.**
  A relying party MAY accept ticks from further preceding periods, converting a tick-distribution outage longer than one period into bounded additional revocation latency rather than a hard failure ({{clock-skew}}).
  This is a relying-party (or root-program) policy, not something a server can switch on, and it applies to every certificate that relying party validates, so it loosens revocation freshness ecosystem-wide.
  It is therefore a conscious fallback for known-poor availability, not a default.
  It remains hard-fail once the widened window elapses: a bounded extension of acceptable staleness, not a fail-open.
  The multi-CA approach below is preferable wherever it is available, because it restores availability without accepting any additional staleness.

- **Multiple independent CAs remove the single point of failure.**
  Authenticating parties SHOULD obtain Merkle Tree Certificates from multiple independent CAs, so that if one CA's tick distribution becomes unavailable they can immediately present a certificate from another whose ticks remain current.
  This is the preferred resilience mechanism, because unlike widening the acceptance window it restores availability at no cost to revocation freshness.
  Failover needs no new protocol.
  The tick is embedded in the MTCProof rather than negotiated as a separate stapled response.
  A server holding certificates from several CAs therefore simply presents, in each handshake, one for which it currently holds a fresh tick and whose trust anchor the relying party supports, using the base MTC certificate-selection mechanism ({{Section 8 of !I-D.ietf-plants-merkle-tree-certs}}).
  This is ordinary certificate selection driven by a background tick refresh, not a handshake-time refetch or a new failover exchange; its one precondition is that the relying party support the alternate CA's trust anchor.
  Because MTC certificates are lightweight to obtain and maintain, the incremental cost of holding certificates from two or three CAs is modest relative to the resilience gained.

Compared with relying on short lifetimes alone, this is a shift in the availability dependency rather than a new one, and the shift is smaller than it first appears.
A single successful fetch gives more than one period of runway.
Because a relying party also accepts the immediately preceding period's tick ({{clock-skew}}), a tick fetched for one period stays acceptable through the end of the next.
A distribution outage therefore breaks a certificate only after it outlasts that runway of up to about two periods, not the instant it passes one.
Short-lived certificates do not remove the dependency on CA availability; they relocate it.
Such a certificate depends on the CA's issuance pipeline being reachable each time it must renew, and one due to renew during an issuance outage expires just as an MTCRS certificate does when a tick outage outlasts its runway.
The difference is cadence and weight.
MTCRS moves the dependency onto a static, cacheable, CDN- and anycast-friendly GET with no cryptography ({{operational-resilience}}).
That is far easier to keep at very high availability than the ACME issuance, validation, signing, logging, and CT path a short-lived certificate depends on.
Multi-CA operation removes even that as a single point of failure, so a single CA's tick outage need not break any certificate globally.
A longer `tick_interval` trades the runway back toward a short-lived certificate's issuance cadence while still permitting the in-life revocation that passive expiry cannot.

The alternative, no in-band revocation at all, instead makes the ecosystem depend entirely on external revocation systems whose availability the CA does not control.

## Client-Side Enforcement Latency and Session Resumption {#enforcement-latency}

A relying party checks the non-revocation proof ({{verification}}) only when it validates the certificate, which happens during a full TLS handshake.
Two common TLS behaviours mean this check does not recur for the life of a connection or a resumed session.
The effective client-side revocation latency is therefore bounded not by `tick_interval` alone but by how long a client keeps or resumes a connection:

- **Established connections.** Once a full handshake completes, the certificate, and hence the tick, is not re-evaluated for the lifetime of that connection. A long-lived connection (HTTP keep-alive, HTTP/2, or HTTP/3) may continue to use a certificate that has since been revoked until the connection closes.

- **Session resumption.** A resumed TLS session carries no Certificate message: the server's authentication is derived from the original full handshake and is not re-validated, so no tick is presented and none is checked. A client may therefore resume without re-checking revocation for as long as its session tickets remain usable. TLS 1.3 caps a ticket's lifetime at seven days ({{Section 4.7.1 of !RFC9846}}), and implementations commonly use shorter, configurable limits, but within that window resumption bypasses tick verification.

- **Renegotiation.** TLS 1.3 removed renegotiation, and browsers have disabled or restricted TLS 1.2 renegotiation, so renegotiation cannot be relied upon to re-present a fresh tick. There is likewise no mechanism for a server to push an updated certificate or tick mid-connection.

The effective latency before a revocation takes effect at a given client is therefore approximately the maximum of `tick_interval`, the remaining lifetime of any established connection, and the client's session-resumption window.
A deployment that wants revocation to take effect within about one `tick_interval` SHOULD bound the session-ticket lifetime, and where practical the lifetime of long-lived connections, to a value near `tick_interval`.
That forces a fresh full handshake, and thus a fresh tick, within that period.
On the relying-party side this is a policy choice ({{rp-policy}}): a client MAY cap how long it reuses session tickets and force a periodic full handshake so that the tick is re-checked, independently of the server's ticket-lifetime setting.

This limitation is not specific to this mechanism.
Every handshake-time revocation mechanism (OCSP {{?RFC6960}}, CRLite {{CRLite}}, CRLSets {{CRLSets}}) is likewise consulted only when the certificate is validated, and the base MTC short-lived-certificate model has the same property: a revoked-but-unexpired certificate is equally accepted on a resumed session.
Relative to passive expiry, this mechanism still improves matters, because every full handshake re-checks a per-period non-revocation proof rather than trusting a static `notAfter`.

# Implementation Status

This section records the status of known implementations of the mechanism defined by this specification at the time of posting of this Internet-Draft, following {{?RFC7942}}.
It is requested that the RFC Editor remove this section before publication.

There are no known implementations at the time of writing.
The author intends to produce a reference implementation covering hash chain generation ({{construction}}), tick distribution ({{distribution}}), and relying-party verification ({{verification}}), and to report interoperability results to the working group.
The test vectors of {{test-vectors}} are given so that independent implementations can check their HashChainInput encoding and hashing order against a fixed example before any interoperable deployment exists.

# IANA Considerations {#iana-considerations}

## Module Identifier

IANA is requested to register the following entry in the "SMI Security for PKIX Module Identifier" registry:

| Decimal | Description       | Reference     |
|---------|-------------------|---------------|
| TBD     | id-mod-mtcrs-2026 | This document |

## Certificate Extension

IANA is requested to register the following entry in the "SMI Security for PKIX Certificate Extension" registry:

| Decimal | Description          | Reference     |
|---------|----------------------|---------------|
| TBD     | id-pe-hashChainAnchor | This document |

## Access Descriptor

IANA is requested to register the following entry in the "SMI Security for PKIX Access Descriptor" registry:

| Decimal | Description      | Reference     |
|---------|------------------|---------------|
| TBD     | id-ad-mtcrsTicks | This document |

The id-ad-mtcrsTicks access method is used as a Subject Information Access access method ({{!RFC5280}}) in a Merkle Tree CA certificate ({{Section 5.5 of !I-D.ietf-plants-merkle-tree-certs}}).
Its accessLocation is a uniformResourceIdentifier giving the CA's tick base URL ({{discovery}}).

~~~asn.1
id-ad-mtcrsTicks OBJECT IDENTIFIER ::= { id-ad TBD }
~~~

## Well-Known URI

IANA is requested to register the following entry in the "Well-Known URIs" registry ({{!RFC8615}}):

| Field | Value |
|-------|-------|
| URI Suffix | mtcrs |
| Change Controller | IETF |
| Reference | This document |
| Status | permanent |
| Related Information | Path prefix for the MTCRS tick distribution HTTP interface: `/.well-known/mtcrs/v1/tick/{tbs_cert_entry_hash}` ({{distribution}}) |

## ACME Order Object Fields

IANA is requested to register the following entries in the "ACME Order Object Fields" registry ({{!RFC8555}}):

| Field Name  | Field Type | Configurable | Reference     |
|-------------|------------|--------------|---------------|
| `tickBaseURL` | string     | false        | This document |
| `tickURL`     | string     | false        | This document |

Both fields are set by the server in the order object; neither is configurable by the client in a newOrder request.
A CA uses `tickBaseURL` for the derivable tick URL scheme ({{acme-integration}}) and `tickURL` for the unguessable per-certificate URL scheme ({{unguessable-urls}}); the two are mutually exclusive for a given order.

## MTCProof Extension Type

The proof-extension encoding of the tick ({{tick-proof-extension}}) relies on an MTCProofExtensionType code point, `hash_chain_tick`(0), within a `proof_extensions` field that the base MTC specification does not currently define ({{mtcproof-extensibility}}).
This document does not create an MTCProofExtensionType registry.
If the base MTC specification {{!I-D.ietf-plants-merkle-tree-certs}} adopts the `proof_extensions` mechanism, it, and not this document, is expected to establish the corresponding IANA registry, following the allocation policy recommended in {{proof-extensions-considerations}}.
This document requests that, in that event, the value `hash_chain_tick` be allocated in that registry with a reference to this document.
When the RECOMMENDED trailing `status_tick` encoding ({{tick-trailing-field}}) is used instead, no such registry or code point is required.

--- back

# ASN.1 Module {#asn1-module}

This appendix provides an ASN.1 module for the structures this document defines, following the conventions of {{!RFC5912}}.

~~~asn.1
MTCRS-2026
  { iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) id-mod(0)
    id-mod-mtcrs-2026(TBD) }

DEFINITIONS IMPLICIT TAGS ::= BEGIN

IMPORTS
  EXTENSION
  FROM PKIX-CommonTypes-2009 -- in [RFC5912]
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-pkixCommon-02(57) } ;

-- PKIX arcs

id-pkix OBJECT IDENTIFIER ::=
  { iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) }

id-pe OBJECT IDENTIFIER ::= { id-pkix 1 }
id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }

-- Hash chain anchor certificate extension

ext-hashChainAnchor EXTENSION ::= {
  SYNTAX HashChainAnchorInfo
  IDENTIFIED BY id-pe-hashChainAnchor
  CRITICALITY { TRUE | FALSE } }

id-pe-hashChainAnchor OBJECT IDENTIFIER ::= { id-pe TBD }

HashChainAnchorInfo ::= SEQUENCE {
  tickInterval      INTEGER (1..MAX) DEFAULT 3600,
  anchor            OCTET STRING }

-- Tick distribution Subject Information Access method

id-ad-mtcrsTicks OBJECT IDENTIFIER ::= { id-ad TBD }

END
~~~

The id-mod-mtcrs-2026, id-pe-hashChainAnchor, and id-ad-mtcrsTicks arcs contain TBD values to be replaced with the OIDs assigned by IANA ({{iana-considerations}}).

# Test Vectors {#test-vectors}

This appendix gives a worked example that pins down the exact HashChainInput byte layout ({{encoding}}) and hashing order.
All values are hexadecimal, and the hash function is SHA-256 (HASH_SIZE = 32).

The example uses:

- `issuer_id`: TrustAnchorID 32473.1, whose binary representation is 81fd5901; as a `<1..2^8-1>` vector it encodes with its length prefix as 04 81fd5901.
- `serial_number` = 281474976710698, which is `(log_number << 48) | index` for log number 1 and entry index 42
- `hash_chain_length` = 5
- seed h\[0\] = the 32 bytes 00 01 ... 1f (a fixed value for this example; a real CA uses a cryptographically random, secret seed)

The fixed fields of HashChainInput therefore encode as:

~~~
label          4d544352530a00        ("MTCRS\n\0")
issuer_id      0481fd5901
serial_number  000100000000002a
~~~

Each step computes h\[i\] = SHA-256(HashChainInput(h\[i-1\])), where HashChainInput(preimage) is the concatenation label || `issuer_id` || `serial_number` || preimage.
For example, HashChainInput(h\[0\]) is the following 52 bytes:

~~~
4d544352530a000481fd5901000100000000002a000102030405060708090a0b
0c0d0e0f101112131415161718191a1b1c1d1e1f
~~~

The resulting hash chain is:

~~~
h[0]  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
h[1]  a99c801b389eed84c31eb04c970d2fbe63608bbd8911d54e63eb7f18adcf286a
h[2]  8721e95cbd26d1f2789c859d89858ca1c37193f0772aa171da6f02b71acb51cd
h[3]  4dab657fef30e247ed04565cbfc0ba1f7c977df06544563e9dc5a697c9d21ec4
h[4]  b8c0f6b6aac2f65177c9c2481e50b1070cfd31a348f27f94d5318ecfea385aca
h[5]  f855b7134602eee167305c1a0314ffbf435c8d1b2e49ee3e7b18cd445bdeb234
~~~

The anchor committed in the certificate is h\[`hash_chain_length`\] = h\[5\].

For period t = 2, the CA reveals h\[`hash_chain_length` - t\] = h\[3\].
The HashChainTick is { period = 2, value = h\[3\] }, which serializes (a 4-byte big-endian period followed by the 32-byte value; {{response-format}}) as the following 36 bytes:

~~~
000000024dab657fef30e247ed04565cbfc0ba1f7c977df06544563e9dc5a697
c9d21ec4
~~~

To verify, a relying party hashes `tick.value` forward `tick.period` (2) times ({{verification}}):

~~~
v0 = h[3] = 4dab657f...c9d21ec4
v1 = SHA-256(HashChainInput(v0)) = b8c0f6b6...ea385aca  (= h[4])
v2 = SHA-256(HashChainInput(v1)) = f855b713...5bdeb234  (= h[5])
~~~

v2 equals the anchor h\[5\], so verification succeeds.

The certificate's id-pe-hashChainAnchor extension carries the DER encoding of a HashChainAnchorInfo ({{assertion-integration}}) whose anchor is h\[5\].
The two encodings below pin the DEFAULT handling of `tickInterval`.

With the default `tick_interval` of 3600, DER omits the field (Section 11.5 of {{X.690}}), so the HashChainAnchorInfo is a SEQUENCE carrying only the anchor OCTET STRING (36 bytes):

~~~
30220420
f855b7134602eee167305c1a0314ffbf435c8d1b2e49ee3e7b18cd445bdeb234
~~~

With a non-default `tick_interval`, for example 86400 (one day), the field is present as an INTEGER preceding the anchor (41 bytes):

~~~
302702030151800420
f855b7134602eee167305c1a0314ffbf435c8d1b2e49ee3e7b18cd445bdeb234
~~~

Here `30` is SEQUENCE, `04 20` the 32-byte anchor OCTET STRING, and `02 03 015180` the INTEGER 86400.
A relying party that finds `tickInterval` absent MUST use the default of 3600 ({{assertion-integration}}).

# Amendments Requested of the Base Specification {#base-spec-amendments}

For convenience, this section collects the amendments this document asks of the base specification; each is specified in full in the section cited.

Exactly one change to the base specification is required:

- **Amend the Section 7.2 "extra data" check** so that, when a certificate carries the hash chain anchor, the MTCProof in its `signatureValue` may carry the HashChainTick, and otherwise remains byte-identical to a base MTCProof.
  The RECOMMENDED realization appends a trailing `status_tick` field ({{tick-trailing-field}}); a base specification that instead adopts the general `proof_extensions` field ({{mtcproof-extensibility}}) carries the tick as a proof extension ({{tick-proof-extension}}) and amends Section 7.2 accordingly.

The following item is optional; a base specification MAY adopt it but need not:

- **Register a `hash_chain_anchor` entry-extension type** in the MTCLogEntryExtensionType registry, as an alternative home for the anchor, if the base specification is willing to make its entry-extension registry and cosigner software aware of this mechanism ({{anchor-entry-extension}}).

Everything else this document defines layers on top of an otherwise unmodified base MTC log and cosigner deployment and needs no base-specification change.
That covers the id-pe-hashChainAnchor X.509 extension ({{iana-considerations}}), the hash chain construction ({{construction}}), verification ({{verification}}), and tick distribution ({{distribution}}).

The MTCProof changes themselves are edits to a structure that the base specification owns: the trailing `status_tick` field ({{tick-trailing-field}}) and, should the working group prefer the general mechanism, the `proof_extensions` field ({{mtcproof-extensibility}}).
This document specifies them in full so that the required change is concrete and reviewable.
The intent, however, is to hand them to the base MTC specification {{!I-D.ietf-plants-merkle-tree-certs}} to incorporate and maintain, rather than to keep a competing definition of MTCProof here.
If the base specification adopts the change, the corresponding text in this document becomes a description of base-specification behaviour and can be reduced to a reference.

# Open Questions for the Working Group {#open-questions}

{{base-spec-amendments}} states what this document asks of the base specification as concrete proposals, so that they are reviewable.
This section collects the choices behind those proposals that the author considers genuinely open, each with the alternatives, this document's current preference, and a pointer to the full analysis.
A working group that adopts this document should expect to settle them; nothing in this section is itself a normative requirement.

1. **Where does the anchor live?**
   The anchor can be an X.509 extension of the TBSCertificateLogEntry ({{assertion-integration}}) or a committed entry extension ({{anchor-entry-extension}}).
   Both are committed to the Merkle Tree, so the verification procedure is identical either way; the trade is compactness and committed/uncommitted symmetry against a criticality lever and MTCRS-agnostic log and cosigner software.
   The entry extension additionally forces a change to tick addressing, because the anchor then no longer separates entries that are otherwise identical ({{anchor-entry-extension}}).
   *Preference:* the X.509 extension, because it lets the mechanism layer onto an unmodified MTC log and cosigner deployment.
   Whichever is chosen becomes the single anchor home for the ecosystem.

2. **How is the tick carried in the MTCProof?**
   Either as a trailing `status_tick` field ({{tick-trailing-field}}) or as a `hash_chain_tick` proof extension ({{tick-proof-extension}}).
   *Preference:* the trailing field, as the minimal change to a base-specification-owned structure, adding no variable-length "ignore if unknown" region.

3. **Does the base specification want general proof-level extensibility at all?**
   This is separable from question 2.
   The `proof_extensions` field ({{mtcproof-extensibility}}) is worth adopting only if the working group wants a reusable extension point for future proof-level mechanisms; if it is adopted, the tick should use it rather than a bare trailing field.
   *Preference:* not needed for hash chain revocation alone, and it carries the abuse surface discussed in {{proof-extensions-considerations}}.

4. **What should the default `tick_interval` and acceptance window be?**
   The two jointly set revocation latency: a withheld tick stops verifying within (k + 1) `tick_interval`s, where k is the number of preceding periods a relying party accepts ({{clock-skew}}).
   This document uses one hour ({{why-one-hour}}) with k = 1, which is where the two-period bound quoted throughout comes from.
   They are worth settling separately because they have different owners.
   `tick_interval` is per-certificate and set by the CA, carried in the certificate for every verifier to read ({{construction}}), whereas the acceptance window is relying-party or root-program policy applying uniformly to every certificate that party validates ({{rp-policy}}).
   A one-day interval is also viable and materially shifts the balance between revocation latency and outage tolerance ({{availability-considerations}}); widening k buys outage tolerance at a one-for-one cost in latency ({{clock-skew}}).
   *Preference:* one hour with k = 1.
   Neither is a protocol question: both concern recommended defaults and what root programs should require.

5. **Should period 0 enforce revocation?**
   The period 0 tick is the public anchor, which gives the CA a one-period grace before it must serve a new certificate's first secret tick but defers enforcement of a just-issued certificate to the start of period 2 ({{period-zero-rationale}}).
   Computing the hash chain one element longer removes the grace and enforces from period 1; that construction is given in {{period-zero-rationale}}.
   *Preference:* keep the grace, as the operational headroom is generally worth more than sub-two-period revocation of a brand-new certificate.

6. **Is "tick" the right name for the revealed value?**
   The name appears throughout this document and in the field and parameter names it proposes (`status_tick`, `tick_interval`, `tickInterval`), so it is cheap to change now and expensive later.
   "Tick" was chosen for its clock connotation: one per period, on a fixed cadence.
   It is also unclaimed in TLS and PKI, unlike "token" (time-stamp tokens, bearer tokens, Privacy Pass), "witness" and "checkpoint" (already used in transparency systems, and this document has cosigners), and "heartbeat" (a TLS extension).
   "Token" is doubly unavailable here.
   This document already uses it for the optional per-certificate capability that addresses a tick URL ({{unguessable-urls}}).
   Its bearer-credential connotation is also the opposite of what a tick is, since a tick is public, unsigned, and useless to a party that does not also hold the certificate.
   Its weakness is that "tick" ordinarily names a time event rather than a value, so a reader may expect it to be a period number; this document therefore always presents the tick as the pair `{period, value}`.
   *Preference:* keep "tick"; a descriptive alternative such as "non-revocation proof" is accurate but too long to carry as the primary name, and is used here as the gloss at first mention instead.

# Proposed MTCProof Extensibility {#mtcproof-extensibility}

The RECOMMENDED way to carry the tick is the fixed trailing `status_tick` field ({{tick-trailing-field}}), which needs no general extensibility mechanism.
This section describes an alternative: a general, reusable proof-level extensions field that the base MTC specification {{!I-D.ietf-plants-merkle-tree-certs}} MAY adopt.
It is worth adopting only if the base specification wants future mechanisms, beyond hash chain revocation, to attach data to the certificate presentation without a further structural change each time.
It is not required for hash chain revocation alone, and it carries the abuse surface discussed in {{proof-extensions-considerations}}.
Like the trailing-field amendment ({{tick-trailing-field}}), this is an edit to a base-specification-owned structure ({{base-spec-amendments}}).
It is written out here for concreteness but is intended to be handed to the base MTC specification to adopt and maintain, not kept as a separate definition.
This appendix defines the field and how the tick would be encoded within it.
The case for and against selecting this encoding over the trailing field is made in {{tick-proof-extension}}, and the constraints a base specification adopting it should impose are collected in {{proof-extensions-considerations}}.

## Motivation

The current MTCProof is a fixed sequence of fields with no extensibility point, and {{Section 7.2 of !I-D.ietf-plants-merkle-tree-certs}} requires relying parties to reject any data trailing it, so no field can be appended without amending the base specification ({{tick-trailing-field}}):

~~~tls-presentation
struct {
    MTCLogEntryExtension extensions<0..2^16-1>;
    uint48 start;
    uint48 end;
    HashValue inclusion_proof<0..2^16-1>;
    SubtreeSignature signatures<0..2^16-1>;
} MTCProof;
~~~

The existing `extensions` field carries the log entry's MTCLogEntryExtension values, which are committed to the Merkle Tree and so cannot carry dynamic, per-period data like hash chain ticks: the inclusion proof would fail.

A proof-level extensions field, not committed to the tree and freely updatable by the authenticating party, would let the MTCProof carry revocation ticks and other future self-authenticating proof-level values without a new version of the base specification for each.

## Proposed Amendment

This document proposes updating {{!I-D.ietf-plants-merkle-tree-certs}} with the following extended MTCProof structure:

~~~tls-presentation
enum { hash_chain_tick(0), (2^16-1) } MTCProofExtensionType;

struct {
    MTCProofExtensionType extension_type;
    opaque extension_data<0..2^16-1>;
} MTCProofExtension;

struct {
    MTCLogEntryExtension entry_extensions<0..2^16-1>;
    uint48 start;
    uint48 end;
    HashValue inclusion_proof<0..2^16-1>;
    SubtreeSignature signatures<0..2^16-1>;
    MTCProofExtension proof_extensions<0..2^16-1>;
} MTCProof;
~~~

The `proof_extensions` field is a variable-length list with a 2-byte length prefix.
When empty, it encodes as two zero bytes (0x0000), adding minimal overhead to certificates that do not use any proof extensions.

The existing `extensions` field is renamed to `entry_extensions` to distinguish it from the new `proof_extensions` field.
Both are variable-length lists of tag-length-value structures, but they serve different roles: `entry_extensions` carries the log entry's MTCLogEntryExtension values (committed to the Merkle Tree), while `proof_extensions` carries proof-level data that can be freely updated without affecting the inclusion proof.

Relying parties MUST ignore unrecognized proof extension types.

The "extra data" check in {{Section 7.2 of !I-D.ietf-plants-merkle-tree-certs}} would be amended to account for the trailing `proof_extensions` field.

## Hash Chain Tick as a Proof Extension

With this extensibility mechanism, the HashChainTick ({{cert-format}}) is carried as a proof extension rather than as a bare trailing field: as an MTCProofExtension with `extension_type` set to `hash_chain_tick(0)` and `extension_data` containing the serialized tick (4 + HASH_SIZE bytes).

## Backward Compatibility

Because the `proof_extensions` field uses a length-prefixed encoding, an implementation that supports the extended structure but does not recognize a particular extension type can skip over it by consuming the declared length.
Implementations that predate the amendment will reject the certificate at the MTCProof parsing stage (due to trailing bytes), which is acceptable: such implementations would also not recognize the id-pe-hashChainAnchor extension's semantics, so they cannot verify hash chain revocation regardless.

For the transition period, ecosystems have two options:

- **Mark the extension critical:** Unaware implementations reject at the X.509 extension stage, producing a clear error rather than an opaque parse failure.

- **Deploy the base spec amendment first:** Once the `proof_extensions` field is adopted into the base MTC specification, all conforming implementations will parse it (ignoring unknown types), enabling incremental deployment of hash chain revocation with a non-critical X.509 extension.

## Considerations for the proof_extensions Field {#proof-extensions-considerations}

The `proof_extensions` field is, by design, unauthenticated and freely mutable: it is not committed to the Merkle Tree, no cosignature covers the MTCProof, and relying parties ignore unrecognized types.
These properties are what let the tick be updated each period.
As a general-purpose extension point, however, they also let an authenticating party, or any relaying intermediary, add, alter, or strip proof extensions undetectably and insert data that relying parties silently ignore ("stuffing").
This does not affect hash chain revocation itself, because the tick is self-authenticating and its presence is mandated by the committed id-pe-hashChainAnchor extension, so stuffed or stripped data can neither forge nor suppress a tick.
If the base MTC specification adopts `proof_extensions` as a general mechanism, three controls matter most; a relying party can enforce the first two without understanding any extension's contents:

Bounded size and count:
: `proof_extensions` is transmitted in every handshake, so an unbounded ignored field undercuts MTC's compactness and creates a bloat and denial-of-service surface.
  The base specification MUST set a small maximum total size and extension count, well below the 2<sup>16</sup>-1 the length prefix permits, and relying parties MUST reject certificates that exceed it.

Committed admissibility:
: The strongest control on stuffing is to make the permissible extensions a function of committed data.
  The base specification SHOULD commit, per entry, an allow-list of permitted (extension_type, length) pairs in the tree-committed entry data ({{assertion-integration}}).
  Relying parties should then be required to reject any proof extension absent from that list or disagreeing with it on length.
  This is enforceable by a relying party that does not implement the specific mechanism, and, being committed and therefore logged, it also makes the presence of each proof-level mechanism transparent to monitors (though not its per-period value).

Security-relevant extensions must be anchored:
: Unrecognized or absent proof extensions are ignored.
  Any future proof extension carrying security-relevant data MUST therefore make its presence mandatory and self-authenticating through an element committed to the Merkle Tree, as hash chain revocation does with the id-pe-hashChainAnchor extension ({{assertion-integration}}).
  Otherwise "ignore if unknown" becomes a strippable soft-fail ({{ocsp-stapling-comparison}}).

A base specification SHOULD also consider several further controls.
One is a canonical encoding: ascending `extension_type`, no duplicate types, exact-length consumption.
Another is an IANA registry for `MTCProofExtensionType` with a private-use range.
A third is fail-closed rejection of unknown types, optionally softened by a per-extension criticality bit; this closes the ignore channel but trades incremental deployability for hard enforcement, the same trade-off as marking the anchor extension critical ({{extension-criticality}}).
A fourth is a deterministic fixed-length region, where each type's value length is implied, leaving no unauthenticated free space for a self-authenticating value such as the tick.
Two properties are inherent and MUST be respected.
Proof-extension values are neither logged nor committed, so a mechanism needing transparency of its contents MUST use `entry_extensions` instead ({{assertion-integration}}).
And because `proof_extensions` widen `signatureValue` malleability ({{Section 12.6 of !I-D.ietf-plants-merkle-tree-certs}}), applications MUST derive any certificate identifier from the TBSCertificate, never from the MTCProof.

Taken together, committed admissibility, fixed-length determinism, and fail-closed handling progressively convert `proof_extensions` from an open, "ignore if unknown" channel into a closed, committed, verifiable set of slots.
That is much of why this document RECOMMENDS the fixed trailing `status_tick` field ({{tick-trailing-field}}) for the single use it needs.

# Design Rationale {#rationale}

This section provides rationale for the choices made in this document.

## Why Functional Revocation Is Superior to Passive Expiry {#revocation-vs-expiry}

A common argument holds that sufficiently short certificate lifetimes eliminate the need for revocation: if a certificate expires in one day, the window of exposure after key compromise or misissuance is bounded by that day.
This reasoning is incomplete.
Three independent time intervals govern the security of a certificate:

1. **Certificate lifetime:** The maximum duration for which a certificate can be presented.
   Without revocation, this is the upper bound on exposure after any problem.

2. **Revocation latency:** Once the CA decides to revoke, how quickly can the certificate become unusable?
   Without a revocation mechanism, this equals the remaining certificate lifetime.
   With hash chain revocation, this is at most two periods (e.g., two hours).

3. **CA validation frequency:** How often the CA re-verifies that the subscriber remains authorized (domain control, organization identity, etc.).
   This determines how quickly the CA *learns* of problems that are not self-reported by the subscriber.

These three intervals interact as follows.
The worst-case exposure time after a problem occurs is:

~~~pseudocode
exposure = min(remaining_lifetime,
               detection_time + revocation_latency)
~~~

Without revocation, detection_time is irrelevant: the certificate remains valid until it expires regardless of what the CA knows.
With revocation, the CA can act as soon as it detects the problem, and the certificate becomes unusable within the revocation latency.

This has a counterintuitive consequence: a certificate with a long lifetime but active revocation can provide *shorter* exposure than a certificate with a short lifetime but no revocation.
For example:

- A 1-day certificate without revocation: worst-case exposure is ~24 hours (compromise occurs immediately after issuance).

- A 47-day certificate with 1-hour hash chain revocation: if the CA learns of the compromise within minutes (subscriber report, domain validation re-check, or external notification), worst-case exposure is ~2 hours.

By substituting expensive asymmetric signatures with incredibly cheap symmetric hashing, this mechanism allows CAs to achieve the security benefit of an hourly expiration window without any of the architectural cost that comes with hourly re-issuance {{SHORTLIVED}}.
Rather than re-signing and re-logging every certificate each hour, the CA reveals a single precomputed hash value per period, and the relying party verifies it with a single hash computation.

The critical difference is that passive expiry provides no mechanism for the CA to act on new information.
A hash chain tick is a *continuous assertion of non-revocation*: each tick is an active statement by the CA that, as of this period, it has not revoked the certificate.
Absence of the tick is immediately detectable and enforced by the relying party.

### The Role of CA Validation Frequency

Even with functional revocation, the CA cannot revoke a certificate for a problem it does not know about.
The frequency of CA re-validation therefore determines the effective security bound for non-self-reported problems (e.g., loss of domain control that the subscriber does not notice or report).

Without revocation, validation frequency is largely irrelevant: even if the CA discovers a problem mid-lifetime, it cannot shorten the certificate's validity.
The only recourse is to publish the revocation via an external mechanism (CRLite, CRLSets) that may or may not reach all relying parties.

With hash chain revocation, frequent CA validation translates directly into security improvement.
The CA can act on a detected problem at the very next period boundary, by withholding that certificate's tick, and the certificate stops verifying within at most two periods of the decision ({{revealing-values}}, {{clock-skew}}).
This creates an incentive structure where CAs that validate more frequently provide measurably better security, an incentive that does not exist in a pure short-lived-certificate model without revocation.

Root program policies can leverage this by requiring both short tick intervals and minimum re-validation frequencies, achieving a defence-in-depth posture that neither mechanism provides alone.

This reframes where certificate lifetime sits in the security argument.
Much of the pressure to shorten certificate lifetimes is a substitute for revocation: with no reliable in-band revocation, expiry is the only enforceable bound on exposure after key compromise or misissuance.
Fine-grained hash chain revocation supplies that bound directly, within about two periods rather than a lifetime.
It therefore removes revocation latency as a rationale for reducing lifetimes further.
Once revocation is measured in hours, shrinking a lifetime from weeks to days barely changes the worst-case exposure to a *detected* problem, while still incurring the issuance, logging, and relying-party trusted-subtree costs that shorter lifetimes carry ({{short-lifetimes}}).
This document does not argue that certificates should therefore be longer.
The residual reasons to bound lifetime are real and are not addressed by revocation.
The first is exposure to problems the CA never detects, which revocation cannot act on, and which re-validation frequency, above, bounds instead.
The second is the agility and hygiene benefits of forced rotation: rapid algorithm migration, retirement of stale certificates, and keeping certificates aligned with current domain control.
The narrower point is that, with enforceable revocation in place, lifetime and revocation become independent levers.
A root program can then set each on its own merits, rather than using lifetime as a proxy for a revocation mechanism it did not have.

## Why Hash Chains (Micali) Instead of Other Revocation Mechanisms

Several alternative revocation mechanisms were considered and rejected; {{alternatives}} analyses each.
Hash chains {{MICALI}} were selected because they are the only known mechanism that provides *all* of the properties listed in the Introduction at once.
Those are timely revocation, zero per-period CA signing, self-authentication against the committed anchor, mandatory hard-fail enforcement, and a 36-byte per-handshake cost.
They achieve this using nothing but a hash function and basic arithmetic, with no new cryptographic primitive.
Each alternative in {{alternatives}} secures some of these but sacrifices at least one.
Signed per-certificate status reintroduces per-period signing ({{operational-resilience}}); a separate TLS or stapled channel reintroduces the strippable soft-fail ({{ocsp-stapling-comparison}}); and pushed external lists give up universal, CA-anchored enforcement ({{browser-revocation-history}}).
It is this simultaneity, not any single property, that distinguishes hash chains.

## Why This Succeeds Where Micali's CRS Did Not {#why-crs-succeeds}

Micali's certificate revocation system {{MICALI}} introduced the hash chain primitive this document builds on, yet it never saw wide deployment in the Web PKI.
The reason was not the cryptography, which is sound, but delivery.
The scheme made proving non-revocation cheap to *verify*, but it did not change how the per-period token *reached* the relying party.
A verifier still had to obtain a fresh per-certificate value each period, and classic X.509 offered no low-cost, enforceable place to carry it.
A relying party therefore had to fetch it, which reintroduced the distribution, latency, privacy, and soft-fail problems of OCSP {{?RFC6960}}.
Cheap verification did not translate into cheap, enforceable delivery, so the ecosystem standardized on OCSP and CRLs and later moved to pushed revocation lists ({{browser-revocation-history}}).

Merkle Tree Certificates remove that barrier, which is what lets the same primitive become deployable here:

- **Delivery is free.**
  The tick rides inside the MTCProof the authenticating party already presents in the handshake ({{cert-format}}), so the relying party receives it with the certificate and fetches nothing ({{rp-no-fetch}}).
  The only fetch is the server's own once-per-period refresh, a static cacheable GET that can be delegated to CDNs and mirrors ({{delegated-distribution}}).

- **The commitment is free.**
  MTC already commits the anchor in the Merkle Tree and covers it with cosignatures ({{assertion-integration}}), so the tick is self-authenticating with no new signature, responder, or trust relationship.
  Classic CRS, by contrast, needed the CA to sign the hash chain's endpoint (its anchor) into each certificate.

- **Enforcement is hard-fail by construction.**
  Because the committed anchor mandates the tick's presence, a relying party rejects a certificate whose tick is missing or stale ({{ocsp-stapling-comparison}}); it cannot silently soft-fail, which is what undermined both online OCSP and a client-fetched CRS token.

- **The remaining costs are tractable at scale.**
  Zero per-period signing keeps post-quantum signatures off the revocation path ({{post-quantum}}), precomputation is bounded by fractal traversal ({{hash-chain-traversal}}), and distribution is delegable ({{delegated-distribution}}), addressing the generation-and-distribution load that also burdened CRS.
  MTC is moreover greenfield, so enforcement can be mandatory from the outset rather than accommodating a soft-fail install base.

In short, CRS's limitation was delivery and enforcement, not the hash chain.
MTC supplies the missing delivery channel, the certificate presentation itself, committed in a Merkle Tree.
That turns the same primitive into a fetch-free, hard-fail mechanism.

## Why One Hour (or One Day) Periods {#why-one-hour}

A one-hour `tick_interval` provides a good balance:

- **Revocation latency:** A compromised key is unusable within at most two hours (current period + grace period).

- **Operational feasibility:** Authenticating parties must fetch a new tick once per hour.
  This is a trivial HTTP request for a small response.

- **Hash chain length:** For 47-day certificates, the hash chain length is 1,128.
  Verification requires at most 1,127 hash computations, which takes microseconds on modern hardware.

- **CA storage:** A CA MAY store one seed per active certificate (32 bytes each; 32 GB for 1 billion), but need not.
  Deriving seeds from a single long-term CA secret ({{derived-seeds}}) reduces per-certificate secret storage to nothing, since any hash chain is recomputed on demand from that one secret and the public entry identity.
  Traversal or checkpoint schemes ({{hash-chain-traversal}}) bound the recomputation cost, so "store millions of secret seeds" is a choice, not a requirement.

A one-day period is also viable, reducing operational frequency at the cost of up to 48-hour revocation latency.
At day-scale periods the hash chain is short enough that a CA can store each hash chain in full and skip the fractal traversal of {{hash-chain-traversal}} entirely; `hash_chain_length` is then on the order of the lifetime in days, e.g. 47 for a 47-day certificate.
The once-per-day fetch cadence also gives a far more forgiving outage-tolerance budget ({{availability-considerations}}); the price is coarser revocation.
A day-scale period should be compared against a same-lifetime certificate with no in-band revocation, whose worst-case exposure is the full remaining lifetime, rather than against a one-day short-lived certificate.
Its worst-case revocation latency is about two periods (up to ~48 hours), which is longer than a one-day certificate's 24-hour exposure but far shorter than the tens of days a long-lived certificate without revocation would allow.
The fine-grained-revocation advantage over short lifetimes ({{revocation-vs-expiry}}) is precisely what a short period buys, so deployments SHOULD choose the shortest period operationally feasible.

## Rationale for Using the Anchor as the Period 0 Tick {#period-zero-rationale}

The period 0 tick is the public anchor, so the mechanism does not enforce revocation during period 0.
The earliest period for which the CA can withhold a secret value is period 1.
Because the acceptance window keeps the anchor acceptable throughout period 1 ({{verification}}), a certificate the CA wishes to revoke from issuance becomes unusable only at the start of period 2.
That is the same worst-case bound of at most two periods that applies to any revocation decision ({{revocation-vs-expiry}}).
The only capability given up is revoking a certificate faster than that bound in the first moments after issuance, and this trade-off is deliberate and has two advantages.

Operational grace period at issuance:
: The CA's tick distribution service ({{distribution}}) does not need to have computed and begun serving a certificate's first secret tick at the exact instant of issuance.
  It has until the start of period 1, one full `tick_interval`, to begin doing so.
  This assumes `notBefore` is not backdated by a full `tick_interval` or more, which would place the certificate past period 0 at issuance and remove the grace ({{construction}}).
  This mirrors established practice for OCSP {{?RFC6960}}, where a newly issued certificate's first status response is permitted to be briefly unavailable after issuance (the CA/Browser Forum Baseline Requirements, for example, allow up to 15 minutes).
  Revocation infrastructure need not be instantaneously ready for brand-new certificates.

Narrow, low-value window:
: The only capability lost is revoking a certificate within the first `tick_interval` after it was issued.
  A certificate that must be revoked within, for example, one hour of issuance is an unusual case, and the CA directly controls the relevant decision.
  If it already knows at issuance time that a certificate should not be trusted, it simply does not issue it.
  That an arbitrary party can present the public anchor as a period 0 tick confers no additional capability on an attacker, because presenting the certificate in a TLS handshake still requires possession of the corresponding private key.
  It means only that the CA's revocation signal does not take effect until period 1.

A deployment that instead requires revocation enforcement from the moment of issuance, with no period 0 grace, can obtain it by treating the anchor as an ordinary secret hash chain element.
It computes the hash chain one element longer, uses `h[hash_chain_length + 1]` as the anchor, and hashes the revealed value `period + 1` times (rather than `period` times) during verification.
The period 0 tick is then the secret value `h[hash_chain_length]`, which the CA can withhold.
This document uses the shorter construction because the operational grace period is generally more valuable than sub-two-period revocation of a just-issued certificate.

## CA-Side Storage and Computation Trade-off {#storage-tradeoff}

A CA has two largely independent implementation choices for each certificate's hash chain of length `hash_chain_length` (denoted L below): how to produce each period's revealed value, and where the per-certificate seed comes from.
Both are CA-side only; the on-the-wire tick and the relying party's verification procedure ({{verification}}) are unchanged.

### Storing Versus Recomputing Hash Chain Values {#hash-chain-traversal}

Within a single hash chain, a CA does not have to choose between the two naive extremes:

- **Store the entire hash chain:** O(L) storage per certificate, but each revealed value is a free lookup.
  For L = 1128 (a 47-day lifetime with a one-hour period), this is roughly 35 KiB per certificate, or about 36 TB across 1 billion certificates.

- **Store only the seed:** O(1) storage per certificate, but recomputing the value revealed in period t costs up to L hash evaluations (L/2 on average).
  Over a certificate's lifetime this is O(L<sup>2</sup>) hashing.

A CA MAY instead use **fractal hash-chain traversal** {{FRACTAL}} {{ALMOST-OPTIMAL}} to obtain a logarithmic middle ground.
The hash chain is revealed in reverse of the order in which it is computed (the CA computes `h[1..L]` forward from the secret seed `h[0]`, but reveals `h[L-1], h[L-2], ..., h[1]` over time), which is exactly the setting these algorithms address.
Instead of the whole hash chain or just the seed, the CA maintains a small set of precomputed helper values ("pebbles") parked at self-similar positions along the hash chain.
When the value for the current period is needed, a pebble is already there; between periods the CA spends a small fixed budget of hash evaluations advancing the more distant pebbles toward the positions where they will next be needed.
The scheduling guarantees:

~~~
storage  ~ log2(L)      hash values per certificate
work     ~ (1/2) log2(L) hash evaluations per revealed value
~~~

For L = 1128, this is approximately 10 to 11 stored values (~320 to 350 bytes) per certificate and about 5 hash evaluations per period.
Across 1 billion certificates that is roughly 340 GB of state.
If the traversal is advanced once per period and the resulting value served to all requests in that period, the aggregate is on the order of 10<sup>6</sup> hash evaluations per second.
This dominates a simple square-root checkpoint scheme (which would need ~1.1 TB and up to ~34 hashes per value) on both axes, and turns the seed-only extreme's O(L<sup>2</sup>) lifetime cost into O(L log L).

The pebbles are unrevealed hash chain values and therefore carry the same confidentiality requirement as the seed ({{seed-confidentiality}}).

### Deriving Seeds from a Long-Term CA Secret {#derived-seeds}

The per-certificate seed itself can also be eliminated from storage.
Instead of generating and storing an independent random seed per certificate, a CA MAY derive each seed from a single long-term CA secret with a keyed key-derivation function, for example `h[0] = HMAC-SHA256(ca_seed, label || issuer_id || serial_number)`, or the equivalent with HKDF.
A raw `Hash(ca_seed || ...)` construction MUST NOT be used, as it invites length-extension and MAC-misuse; a proper PRF/KDF is required so that derived seeds are computationally indistinguishable from the independent random seeds of {{construction}}.
Any hash chain is then recomputable on demand from `ca_seed` and the (public) entry identity, giving O(1) secret storage for the entire CA and stateless, reconstructible issuance, with no change visible to verifiers.
The cost is concentration.
Compromise of `ca_seed` exposes every certificate's hash chain, past, present, and future, so it MUST be protected at least as strongly as the CA's issuance signing key ({{seed-confidentiality}}).
Being a single small key, it is nonetheless better suited to HSM custody than a bulk per-certificate seed store.
To bound the blast radius, a CA SHOULD derive per-log or per-epoch sub-seeds (`log_seed = KDF(ca_seed, log_number)`, then `h[0] = KDF(log_seed, label || index)`), which can be retired as their logs expire.
As with any seed compromise, rotation protects only certificates issued afterward, and already-committed anchors still require the revoked-ranges fallback ({{seed-confidentiality}}).
Rotation is by issuance epoch, not by tick period: a certificate's entire hash chain derives from the seed fixed at issuance, so per-log or per-epoch sub-seeds are the finest granularity at which a compromise can be bounded.

## Why Embed the Tick in the MTCProof {#why-embed}

The MTCProof is the bundle of evidence a relying party checks to accept a certificate.
The inclusion proof and cosignatures establish authenticity, and the tick completes it with non-revocation, so embedding the tick extends the certificate's proof of validity rather than attaching unrelated data.
It is embedded directly in the MTCProof (the certificate's `signatureValue`) rather than delivered via a separate channel because:

1. **Inseparable from acceptance:** The tick is part of the certificate presentation, not a separate signal.
   When the committed id-pe-hashChainAnchor extension is present, the amended Section 7.2 parse ({{tick-trailing-field}}) requires the MTCProof to carry the tick, so a relying party that implements this mechanism rejects the certificate if the tick is absent.
   The tick is not itself covered by a CA signature.
   Like the rest of the MTCProof it is mutable, which is precisely what lets it be refreshed each period, so an active attacker can remove the bytes.
   What it cannot do is remove them and leave a certificate that still verifies.
   Stripping the tick therefore forces a hard failure rather than the silent soft-fail that let a stripped OCSP staple pass ({{ocsp-stapling-comparison}}): the guarantee is that revocation status cannot be dropped undetectably, not that the bytes are physically immovable.

2. **No new protocol machinery:** No TLS CertificateEntry extension or other signaling mechanism is needed.
   The tick travels inside the existing certificate structure, requiring no changes to TLS implementations beyond MTC support.

3. **Safe to update dynamically:** The MTCProof is not committed to the Merkle Tree; only the TBSCertificateLogEntry is.
   The authenticating party can freely replace the `signatureValue` each period without invalidating the inclusion proof or cosignatures.

4. **No additional round-trips:** The tick travels with the certificate in the same TLS message.
   No DNS lookups or side-channel fetches are needed by the relying party.

5. **Server must participate:** The authenticating party is already responsible for maintaining its MTC certificate and refreshing it before expiry.
   Adding a lightweight hourly tick refresh is an incremental burden, not a new class of operational requirement.

## Comparison with OCSP Stapling {#ocsp-stapling-comparison}

OCSP stapling delivers a CA-signed status response inside the TLS handshake, and is the closest existing analogue to this mechanism.
It has nonetheless failed to become an enforceable revocation channel, for reasons this mechanism is specifically designed to avoid.
The major browsers' migration away from live OCSP and stapling toward pushed revocation lists was itself a verdict on soft-fail.

### Why OCSP Stapling Is Not Enforceable

OCSP stapling ({{?RFC6960}}, carried via the TLS status_request extension) is optional and strippable: the client requests it, and the server, or a network attacker, can omit the stapled response with no signal that one was expected.
A relying party therefore cannot distinguish a deliberately stripped response from a temporarily unavailable responder, so it must soft-fail (treat missing status as "not revoked") to avoid breaking legitimate connections.
Soft-fail, in turn, provides almost no protection against an active attacker, who can simply suppress the response.
This is a self-reinforcing loop: because enforcement is impossible, stapling yields little security benefit; because it yields little benefit, servers have weak incentive to deploy it; and because deployment is incomplete, relying parties can never move from soft-fail to hard-fail.

OCSP Must-Staple ({{?RFC7633}}) was introduced to break this loop by letting a certificate commit to requiring a stapled response.
It saw little adoption: enabling it risks self-inflicted outages if the responder or the server's stapling path fails, and the ecosystem never reached the coverage that would let relying parties depend on it.
The stapled response remains a separate TLS signal with its own failure modes, layered on a CA-operated responder that must sign every response.

### Why This Mechanism Is Enforceable

The hash chain tick is not a separate, optional signal: it is carried inside the MTCProof, which is part of the certificate presentation itself ({{cert-format}}).
A relying party that parses the certificate necessarily encounters the tick; there is no request step to omit, and nothing a middlebox or misconfigured server can strip while leaving a valid certificate.
A relying party can therefore hard-fail on a missing or invalid tick from the outset, precisely what stapling could never achieve.
In effect this mechanism provides the property Must-Staple aimed at, a certificate that cannot be presented without current status, but makes it un-strippable by construction rather than by a policy flag.

### Why It Is More Readily Deployable

Several differences lower the deployment barrier relative to stapling:

- **No responder infrastructure and no per-response signatures.**
  The CA reveals a precomputed hash value per period; there is no OCSP responder fleet, responder certificate, or per-check signing operation.
  Ticks are static within a period, self-authenticating, and cacheable by any HTTP intermediary, so distribution is far more robust than a signing responder, the very fragility that made Must-Staple risky to enable.

- **No TLS-stack changes.**
  The tick travels inside the existing certificate structure, so no status_request negotiation or CertificateStatus handling is required in TLS implementations beyond MTC support itself.
  Stapling requires status_request support on both ends.

- **A small, cacheable refresh instead of stapling machinery.**
  A server refreshes a small value once per period ({{distribution}}), with no cryptographic operations, rather than fetching, validating, and stapling CA-signed OCSP responses with their own validity windows.

- **Greenfield enforcement.**
  MTC is new, so there is no legacy soft-fail install base to accommodate.
  Within an MTC ecosystem, enforcement can be mandatory from day one (or made so by marking the anchor extension critical; see {{extension-criticality}}), avoiding the transition that stapling never completed.

The counterweight is that a tick, unlike a soft-failed OCSP response, is a hard dependency: a server that cannot refresh its tick within a period becomes unusable until it does.
This is the failure mode OCSP Must-Staple has, but MTCRS carries a smaller version of it and, unlike Must-Staple, an escape from it.
The refresh is a static unsigned fetch rather than a time-bounded signed response with a responder certificate and validity window.
And where Must-Staple binds one certificate to one responder with no fallback, a server can hold certificates from several CAs and present one whose tick is current ({{availability-considerations}}).
{{availability-considerations}} discusses this availability dependency and its mitigations.

### Operational Simplicity and Resilience {#operational-resilience}

Beyond the deployment barrier, tick distribution is simpler to operate and more resilient than an OCSP responder.
The serving path holds no online signing key and no responder certificate.
It returns precomputed values that are immutable within a period, so it is a static, cacheable, CDN-offloadable, plain-HTTP key-value service ({{distribution}}) with no per-request cryptography and nothing security-critical in the request path.
A compromised or overloaded tick service can only serve public precomputed values; it cannot mint a false non-revocation statement, unlike a responder whose signing key is a high-value online target.
Relying parties impose no load at all, because they never fetch ({{rp-no-fetch}}).
That removes the responder-in-the-hot-path that made online OCSP a latency, availability, and privacy problem.

Two qualifications apply.
First, the new cost is on the generation side: the CA must produce the current tick for every non-revoked certificate each period, a precompute workload ({{storage-tradeoff}}) rather than OCSP's sign-on-demand.
Second, the failure mode differs by design.
An OCSP responder outage fails open (relying parties soft-fail and proceed), whereas a tick-distribution outage lasting longer than one period fails closed for the affected certificate, bounded by the one-period buffer and mitigated by caching, multi-CA operation, and window-widening ({{availability-considerations}}).

## Relationship to the Browser Move Away from Online Revocation {#browser-revocation-history}

The major browsers disabled live OCSP checking and never pushed OCSP stapling to ubiquity; instead they moved to client-side pushed revocation (Chrome's CRLSets {{CRLSets}}, Mozilla's OneCRL and CRLite {{CRLite}}, and Apple's on-device revocation data).
A handshake-carried status mechanism might therefore look like a return to an approach the ecosystem already rejected.
It is not: the reasons for that move are specific, and this mechanism is designed around each of them.

- **Soft-fail.**
  Online OCSP had to treat an unreachable responder as "not revoked," so an active attacker could suppress the check.
  Here the proof is part of the certificate presentation and hard-fails by construction ({{ocsp-stapling-comparison}}), which is what OCSP Must-Staple ({{?RFC7633}}) aimed at but never achieved at scale.

- **Relying-party privacy.**
  Client-driven OCSP leaked relying-party browsing to CAs.
  Relying parties here never contact the CA ({{rp-no-fetch}}); the only fetch is server-side.

- **Operator and responder fragility.**
  Must-Staple's stapling-pipeline failures caused self-inflicted outages, so clients could never move to hard-fail ({{ocsp-stapling-comparison}}).
  Here the refresh is a trivial cacheable GET with no signing, buffered for a period and backed by multi-CA fallback ({{dos-withholding}}), and MTC is greenfield, so enforcement can be mandatory from the outset.

The pushed-list systems remain valuable and complementary: comprehensive and fail-closed, but vendor-controlled and effective only for relying parties that ship the feed ({{external-revocation}}).
This mechanism provides a universal, CA-operated baseline enforced by every relying party, including non-browser TLS clients and IoT devices with no external feed.
The browser move in fact validates the design choices adopted here: fail-closed enforcement with no handshake-time relying-party network dependency.

## Incremental Deployment and Transition {#deployment-transition}

Two aspects of this design are shaped by the need to deploy into an ecosystem where not every relying party will support hash chain revocation at once.

Marking id-pe-hashChainAnchor non-critical ({{extension-criticality}}) lets CAs begin issuing certificates with hash chain anchors before every relying party enforces them.
Aware relying parties act on the extension and unaware ones proceed without it, and during the transition the base MTC revoked-ranges mechanism and external revocation systems continue to provide coverage.
This mirrors how many X.509 extensions are specified as non-critical (Authority Information Access, Authority Key Identifier, CRL Distribution Points per {{!RFC5280}}).
Because the marking is SHOULD rather than MUST, it MAY be marked critical for hard enforcement from day one.
That applies to an ecosystem in which all relying parties are known to support the mechanism, or to a root program once adoption is sufficient.

Amending MTCProof needs more care, because the base MTCProof has no extensibility point and {{Section 7.2 of !I-D.ietf-plants-merkle-tree-certs}} rejects any trailing bytes.
Appending the tick therefore causes an unaware relying party to reject the certificate regardless of the anchor extension's criticality: it ignores the non-critical extension, parses the MTCProof, finds unexpected trailing bytes, and fails.
Deploying the mechanism thus requires one of:

1. **Amend the base MTC specification** so conforming parsers accept the tick, using either the RECOMMENDED trailing `status_tick` field ({{tick-trailing-field}}) or the general `proof_extensions` field ({{mtcproof-extensibility}}). This is the approach this document proposes ({{base-spec-amendments}}).
2. **Mark the anchor extension critical**, so unaware implementations reject at the X.509 stage rather than on an opaque parse failure, at the cost of incremental deployment.
3. **Deploy concurrently**, adopting the extended MTCProof from the start while MTC is still greenfield.

The required amendment is narrow and backward-compatible.
The trailing `status_tick` occupies zero bytes when the anchor extension is absent, so a certificate not using this mechanism is byte-identical to a base MTCProof, and base MTC verification, the tree, the cosigner, and the log are unchanged ({{tick-trailing-field}}, {{anchor-entry-extension}}).
Folding it into the base specification now, while MTC is greenfield, avoids any lasting split between aware and unaware parsers; retrofitting it after wide deployment would be far harder.

## Verification Cost {#verification-cost}

A relying party verifies a tick by hashing `tick.value` forward `tick.period` times ({{verification}}), so the cost grows with the certificate's age: near the end of a 47-day certificate with a one-hour period it computes up to 1,127 hashes.
This linear cost is small in every setting that has been raised as a concern.

On modern hardware, 1,127 SHA-256 operations take roughly 10 to 20 microseconds.
That is negligible beside the handshake's asymmetric cryptography (one signature verification is worth hundreds of SHA-256 operations), which is itself dwarfed by the network round-trip.
On constrained IoT devices SHA-256 is usually hardware-accelerated and the computation finishes in under a millisecond.
A shorter certificate lifetime or a longer `tick_interval` both reduce `hash_chain_length` and so bound the cost directly.

Across the many connections a page load opens, three effects keep the total small.
The hashing is a small fraction of what each full handshake already spends on asymmetric cryptography, so summing it across several origins remains a small fraction of that cryptography summed across the same handshakes.
Most connections pay nothing: a resumed session carries no Certificate message and verifies no tick ({{enforcement-latency}}), and connection coalescing (HTTP/2 and HTTP/3) collapses many same-origin assets onto one connection.
And a relying party that revalidates the same (entry, period), for example a recurring third-party CDN origin, MAY cache the verified result and skip the forward hashing on repeat.

The same reasoning covers energy on a battery-powered sensor or wearable.
One verification costs a fraction of a millijoule in software and is near-free with a hardware SHA engine, so it is dominated by the asymmetric key exchange and signature verification the same handshake performs.
The effects above apply equally, and a newly issued certificate is the cheapest of all to verify, since the forward-hash count equals the current period and so is near zero just after issuance.

# Alternatives Considered {#alternatives}

## DNS-Based Tick Distribution

An alternative to the HTTP interface ({{distribution}}) is for the CA to publish current ticks via DNS, for example a TXT record at a name derived from `tbs_cert_entry_hash`, which the authenticating party fetches and embeds in the MTCProof.
Because the tick is embedded regardless of transport, the relying party's verification is unchanged and the choice is purely between the CA and the authenticating party; it does not affect interoperability.
DNS's hierarchical caching suits small, frequently-updated values, letting recursive resolvers serve ticks without CA-operated CDN infrastructure.
Its apparent costs are addressable: large zones with one record per certificate, and TTL-bounded propagation.
A programmable authoritative server can synthesize the response for `{tbs_cert_entry_hash}._tick.<zone>` on demand from the same hash chain state ({{distribution}}), so no per-certificate records are stored.
A TTL no longer than `tick_interval` bounds staleness: a briefly stale record stays acceptable under the one-period grace ({{clock-skew}}), and the authenticating party's pre-installation check ({{verification}}) refetches an unexpectedly stale one.
Because ticks are self-authenticating, the delegated-distribution model ({{delegated-distribution}}) applies unchanged, with edge DNS nodes fed the same bundle.

DNSSEC is not required and SHOULD NOT be used: each tick is self-authenticating ({{verification}}), so an attacker cannot forge one in transit without inverting the hash, and suppressing a tick is only a denial of service against any distribution channel.
DNSSEC would add key management and signing for frequently-changing records, and larger responses, without improving the mechanism's security.

## OCSP-Based Tick Distribution

Another alternative is to distribute ticks over OCSP {{?RFC6960}}.
This would mean defining a new OCSP response type (or response extension) that carries the HashChainTick, so an authenticating party fetches its tick from an OCSP responder instead of the HTTP interface ({{distribution}}).
As with DNS-based distribution, this would be only a transport choice for the authenticating party's fetch: the tick is still embedded in the MTCProof and verified offline, so the relying party's procedure is unchanged.
The surface appeal is that CAs already operate OCSP infrastructure.

This approach was rejected because:

- **The tick is self-authenticating, so an OCSP signature is pointless or harmful.**
  An OCSP response is a responder-signed status.
  Signing each tick reintroduces exactly the per-response signing load this mechanism is designed to avoid (the OCSP-like per-certificate signatures alternative below; {{operational-resilience}}); leaving it unsigned is not really an OCSP response.

- **It is heavier and less cacheable than a plain GET.**
  The HTTP interface is a static, plain-HTTP, CDN-cacheable key-value fetch with no per-request cryptography; OCSP adds DER request construction, a responder, nonce handling, and signature validation, contradicting the operational-simplicity argument ({{operational-resilience}}).

- **Addressing and semantics do not fit.**
  OCSP is a relying-party-to-responder status query located via AIA and keyed by CertID (issuer name and key hashes plus serial).
  Here, by contrast, the authenticating party fetches a value about its own certificate, addressed by `tbs_cert_entry_hash` and the CA's TrustAnchorID ({{distribution}}).
  Mapping this onto OCSP reintroduces the AIA-inflation problem of a per-certificate URL in the certificate ({{aia-discovery}}).

- **It invites relying-party fetching.**
  OCSP is strongly associated with client-side status checking, so an OCSP-shaped interface risks reintroducing the CA-visible relying-party fetch, latency, and soft-fail that {{rp-no-fetch}} forbids and this design avoids.

Because the relying party only ever sees the embedded tick, the CA-to-authenticating-party transport is a bilateral choice.
A CA MAY tunnel ticks over any transport it and its authenticating parties support, including OCSP, but this document neither standardizes nor recommends an OCSP encoding for it.

## AIA-Based Tick URL Discovery {#aia-discovery}

Another alternative is to convey the tick distribution URL via a new Authority Information Access (AIA) access method in the certificate, following the established pattern used for OCSP responder URLs in {{!RFC5280}}.

This approach was rejected because:

- **Inflates log entries:** AIA is part of the TBSCertificate, which is committed to the Merkle Tree.
  A ~50-80 byte URL in every log entry increases tree size and inclusion proof transmission costs, conflicting with MTC's goal of compactness.

- **Immutable once issued:** If the CA migrates its tick distribution infrastructure, all existing certificates still contain the old URL.
  Delivering the URL out of band ({{discovery}}) lets the CA migrate its tick infrastructure without certificate reissuance.

- **Only the authenticating party needs it, and only it should fetch:** Relying parties verify the embedded tick offline against the committed anchor and MUST NOT fetch ticks ({{rp-no-fetch}}).
  Putting a per-certificate URL in the certificate would not make fetching infeasible, since the URL is derivable regardless ({{rp-no-fetch}}).
  Placing it in a field relying parties routinely parse would, however, standardize and encourage client-side tick fetching, reintroducing the OCSP-style privacy leak, latency, and soft-fail problems this mechanism avoids.

- **Redundant given existing CA relationship:** The authenticating party obtained the certificate from the CA (e.g., via ACME) and can receive the tick base URL through that same channel at zero per-certificate cost ({{discovery}}).

Out-of-band delivery of the base URL at provisioning ({{discovery}}) conveys it at zero per-certificate cost.
CAs MAY additionally publish the base URL in the CA certificate SIA ({{discovery}}) for a protocol-independent record.

## Carrying the Anchor as a Merkle Tree Entry Extension {#anchor-entry-extension}

This document carries the anchor in an X.509 certificate extension (id-pe-hashChainAnchor) placed in the extensions field of the TBSCertificateLogEntry, and thus also in the TBSCertificate.
An alternative is to carry it as an MTCLogEntryExtension, the entry-level extension point defined in {{Section 5.2.1 of !I-D.ietf-plants-merkle-tree-certs}}, rather than as an X.509 extension.
Both are committed to the Merkle Tree, so either home makes the anchor self-authenticating; the choice is between two extension mechanisms, not between committed and uncommitted storage.

In this alternative, a new MTCLogEntryExtensionType (for example, `hash_chain_anchor`) is registered with the base specification, and its extension_data carries the HashChainAnchorInfo (DER-encoded, or an equivalent TLS-encoded structure).
The verifier reads the anchor and `tick_interval` from the entry's extensions, which it already reconstructs from the MTCProof's extensions field during base MTC verification ({{Section 7.2 of !I-D.ietf-plants-merkle-tree-certs}}), rather than from an X.509 extension.

Obtaining the anchor costs neither party any meaningful extra work.
Both the anchor and the tick then travel in the MTCProof: the entry extensions in its leading field, the tick in its trailing one.
A relying party therefore finds the anchor by scanning a short type-length-value list it has already parsed to reconstruct the entry, in place of the scan of the certificate's X.509 extensions that the primary design performs.
Each is a lookup in a list the party decodes regardless.
An authenticating party likewise reads it from the certificate it already holds, and preserves the entry extensions verbatim when it rewrites the `signatureValue` to install a fresh tick ({{distribution}}).
Disturbing them would break the inclusion proof, so the error is self-detecting.
One detail is in fact simpler: `certificate_has_anchor`, the discriminant of the trailing `status_tick` field ({{tick-trailing-field}}), becomes a preceding field of the same structure rather than a property of the enclosing certificate, matching the base specification's own in-structure selects.
The costs of this alternative lie elsewhere, as below.

This changes what `tbs_cert_entry_hash` ({{distribution}}) covers, though not its role.
`tbs_cert_entry_hash` is computed over `tbs_cert_entry_data`, which contains the TBSCertificateLogEntry but not the entry-level extensions of the MTCLogEntry.
In this alternative the anchor is therefore committed to the tree through the MTCLogEntry rather than through `tbs_cert_entry_data`, and does not contribute to `tbs_cert_entry_hash`.
In the primary design the anchor, as an X.509 extension of the TBSCertificateLogEntry, is part of `tbs_cert_entry_data` and does contribute.
Either way `tbs_cert_entry_hash` remains well-defined and identical for a given entry's standalone and landmark-relative certificates ({{cert-profiles}}), and continues to serve only as the tick-URL identifier.

Excluding the anchor does, however, remove the uniqueness the tick URL relies on.
`serialNumber` is omitted from the TBSCertificateLogEntry, its value being authenticated instead by the inclusion proof index ({{Section 12.6 of !I-D.ietf-plants-merkle-tree-certs}}).
`tbs_cert_entry_data` therefore carries nothing that distinguishes two entries certifying the same subject, public key, validity, and extensions, which a CA that rounds `notBefore` readily produces for a repeated issuance request.
In the primary design the anchor separates such entries, each carrying an independent random value; in this alternative it does not.
Both would then resolve to a single tick URL while holding different hash chains, and the authenticating party for whichever entry the CA does not serve there would reject every tick it fetched ({{verification}}).
A base specification adopting the entry-extension encoding MUST therefore address ticks by a value that covers the anchor, in place of `tbs_cert_entry_hash`.
One candidate is the base specification's own `entry_hash`, the Merkle leaf hash `MTH({entry})`, which is computed over the entry extensions as well as `tbs_cert_entry_data` ({{distribution}}).

This has a natural symmetry with the tick's encoding: the immutable, committed anchor lives in the committed entry extensions, while the mutable, per-period tick lives in the uncommitted trailing field or `proof_extensions` ({{cert-format}}).
It is also more compact, because an MTCLogEntryExtension uses a short TLS type-and-length framing rather than an X.509 extension's OBJECT IDENTIFIER and DER wrapper.

It has three costs, however:

- **No criticality lever.**
  Entry extensions have no critical marking, and relying parties ignore unrecognized ones ({{Section 12.5 of !I-D.ietf-plants-merkle-tree-certs}}).
  The transition strategy of marking the X.509 extension critical to force unaware relying parties to hard-fail ({{extension-criticality}}) is therefore unavailable; enforcement rests entirely on relying parties that implement this mechanism.

- **Not visible to generic X.509 tooling.**
  The anchor no longer appears in the TBSCertificate, so only MTC-aware software can observe that a certificate uses this mechanism.

- **The log-signing infrastructure must be MTCRS-aware.**
  {{Section 5.4 of !I-D.ietf-plants-merkle-tree-certs}} forbids a CA cosigner from signing a subtree containing an entry with an extension_type it does not recognize.
  A `hash_chain_anchor` entry extension therefore forces the CA's log and cosigner components to recognize it before they can sign any subtree containing an MTCRS certificate.
  With the X.509 extension, the anchor rides inside the entry's `tbs_cert_entry_data` as ordinary certificate bytes, so that recognition gate never fires; the gate concerns the entry type and extension_type, not X.509 extensions.
  The generic log and cosigner infrastructure therefore remain MTCRS-agnostic, and only the issuance front-end and the tick distribution service ({{distribution}}) need be MTCRS-aware.

Because of the last point in particular, this document uses the X.509 extension as the primary design: it lets this mechanism be layered onto an otherwise unmodified MTC log and cosigner deployment.
A base specification that is willing to make its entry-extension registry and cosigner software aware of hash chain revocation MAY instead adopt the entry-extension encoding, gaining the compactness and the committed/uncommitted symmetry described above.

## TLS Extension or status_request Reuse

Another option is to carry the tick in TLS rather than in the MTCProof.
That means either a new TLS or CertificateEntry extension, or the existing `status_request` extension (defined for OCSP stapling), whose `CertificateStatusType` enum is extensible beyond OCSP; in TLS 1.3 it would ride in the `CertificateEntry` extensions.

All such approaches share a disqualifying property: a TLS-carried status is opt-in and strippable.
A separate extension can be omitted by a middlebox or misconfigured server, and `status_request` is requested by the client and may be omitted by the server.
In either case there is no signal that one was expected, forcing relying parties to soft-fail, exactly the failure mode analysed in {{ocsp-stapling-comparison}}.
Embedding the tick in the MTCProof instead makes it inseparable from the certificate's acceptance, so stripping forces a hard failure rather than a silent soft-fail ({{why-embed}}).

Two further points weigh against a TLS encoding.
A new TLS extension type requires IANA registration and TLS-stack changes, whereas embedding in the MTCProof needs no TLS-layer change beyond MTC support itself.
And `status_request` specifically carries `OCSPResponse` semantics (a signed responder assertion); repurposing it for a bare, self-authenticating hash value would be a poor semantic fit.

## Proof-Extension Encoding for the Tick {#tick-proof-extension}

This document carries the tick in the RECOMMENDED trailing `status_tick` field ({{tick-trailing-field}}).
Alternatively, if the base MTC specification wants a general, reusable proof-level extensibility point rather than a single appended field, it can adopt the `proof_extensions` structure and carry the HashChainTick as one of its entries.
{{mtcproof-extensibility}} defines that field and the exact hash_chain_tick encoding; when the id-pe-hashChainAnchor extension is present, the MTCProof MUST contain exactly one hash_chain_tick proof extension.

This encoding can also carry future proof-level mechanisms (for example, other self-authenticating freshness values) without a further structural change, and lets a conforming parser skip a tick it does not recognize.
Those benefits come at a cost: as a general, unauthenticated, "ignore if unknown" channel it introduces the abuse surface discussed in {{proof-extensions-considerations}}, namely bloat, covert channels, and a strippable soft-fail for any misuse.
This document treats that surface as unjustified for a single tick, and therefore recommends the trailing field ({{tick-trailing-field}}) unless a concrete need for general extensibility exists.

## Shorter Certificate Lifetimes {#short-lifetimes}

The simplest revocation strategy is to make certificates short-lived enough that revocation is unnecessary.
The general case for functional revocation over passive expiry is made once, in {{revocation-vs-expiry}}; this section only catalogues the specific operational costs that nonetheless motivate longer lifetimes:

- **Issuance infrastructure load:** Shorter lifetimes require more frequent issuance.
  With millions of subscribers, daily certificate issuance produces proportionally larger logs and more frequent Merkle Tree constructions.

- **Availability risk:** An authenticating party that cannot reach the CA for one day loses its certificate entirely.
  Longer lifetimes provide more buffer against CA outages.

- **Trusted subtree state:** The number of landmark subtrees relying parties must maintain grows with shorter lifetimes and more frequent landmark allocation, at the cost of increased CA operational complexity.

- **Deployment constraints:** Root program policies such as {{CHROME-MTC}} have set maximum lifetimes (e.g., 47 days) based on ecosystem-wide operational feasibility assessments, and permit them alongside a shorter recommended validity precisely because not every deployment can renew on the shorter cadence.
  Not all deployments can support arbitrarily short lifetimes.

Matching a one-hour period's revocation latency with lifetime alone would mean certificates expiring about every two hours.
That attains comparable worst-case exposure but does not remove the cost; it moves it to the heavier places catalogued above.
For the CA that means a roughly hundredfold increase in issuance, tree cosigning, and log growth, and for relying parties the same increase in trusted-subtree sync, discarding the batched compactness MTC exists to provide.
It also imposes a stricter availability dependency, since re-issuance (key generation, CSR, challenge, log inclusion) is far heavier to keep continuously live than a lightweight tick fetch.
Hash chain revocation buys the same fine-grained revocation for a few microseconds of hashing instead, which is why the microseconds are the cheap side of the trade, not over-engineering.

Hash chain revocation provides the revocation latency benefits of short-lived certificates while retaining the operational advantages of longer lifetimes.

## CRLite / CRLSets / External Revocation {#external-revocation}

External revocation systems like {{CRLite}} and {{CRLSets}} compress revocation information into compact data structures pushed to relying parties.
The base MTC specification suggests using these as a complement.

This approach has limitations when used as the sole revocation mechanism for MTC:

- **Push latency:** These systems are updated on the order of hours to days, depending on the deployment.
  They do not provide a guaranteed upper bound on revocation latency.

- **Relying party coverage:** Not all relying parties subscribe to external revocation feeds.
  A mechanism that depends on the relying party having an up-to-date feed cannot provide universal revocation enforcement.

- **Separate trust path:** External revocation requires the relying party to trust the feed provider (e.g., the browser vendor) in addition to the CA.
  Hash chain revocation uses only the existing CA trust relationship.

These mechanisms remain valuable as defense-in-depth and as a fallback for the hash chain mechanism, as discussed in {{interaction-with-base-mtc-revocation}}.

## Per-Certificate Signatures (OCSP-like) {#per-cert-signatures}

A CA could sign per-certificate non-revocation statements each period, analogous to OCSP responses.

This approach was rejected because:

- **Signing load:** A CA with a billion active certificates would need to produce a billion signatures per period.
  With post-quantum signature algorithms, this is computationally expensive.

- **Response size:** OCSP responses include a full signature (e.g., 3,309 bytes for ML-DSA-65).
  Hash chain ticks are 36 bytes.

- **Complexity:** OCSP requires its own responder infrastructure, certificate chain, and protocol.
  Hash chains require only a hash function.

# Acknowledgments
{:numbered="false"}

The hash chain revocation concept is based on Silvio Micali's foundational work on efficient certificate revocation {{MICALI}}.
The name "MTCRS" is a nod to Micali's Certificate Revocation System (CRS); and coincidentally, "RS" also happens to be the initials of the author of this document.

# Change log
{:numbered="false"}

> **RFC Editor's Note:** Please remove this section prior to publication of a
> final version of this document.

<!-- One "## Since draft-strad-plants-mtcrs-NN {:numbered="false"}" subsection per
published revision, most recent first. -->

This is the initial revision, so there are no changes to record yet.

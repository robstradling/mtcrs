---
title: "Merkle Tree Certificate Revocation Status (MTCRS)"
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
  RFC2119:
  RFC5280:
  RFC5912:
  RFC8174:
  RFC8446:
  RFC8555:
  RFC8615:
  RFC9110:
  SHS:
    title: "Secure Hash Standard"
    author:
      org: National Institute of Standards and Technology (U.S.)
    date: 2015
    target: https://doi.org/10.6028/nist.fips.180-4
  I-D.ietf-plants-merkle-tree-certs:
    title: "Merkle Tree Certificates"
    author:
      - name: David Benjamin
      - name: Devon O'Brien
      - name: Bas Westerbaan
      - name: Luke Valenta
      - name: Filippo Valsorda
    date: 2026-07
    target: https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/

informative:
  RFC5297:
  RFC6960:
  RFC6962:
  RFC7633:
  MICALI:
    title: "Efficient Certificate Revocation"
    author:
      - name: Silvio Micali
    date: 1996
    target: https://dl.acm.org/doi/10.5555/889659
  CHROME-MTC:
    title: "Chrome MTC Policy"
    author:
      org: Google Chrome
    date: 2025
    target: https://googlechrome.github.io/CertificateTransparency/mtc_policy.html
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
    date: 2002
    target: https://doi.org/10.1007/3-540-36504-4_8

...

--- abstract

This document defines a hash chain revocation mechanism for Merkle Tree Certificates (MTC) {{I-D.ietf-plants-merkle-tree-certs}}.
A Merkle Tree CA includes a hash chain anchor (the "target") in the certificate at issuance time.
Periodically, the CA reveals hash chain values ("ticks") that serve as proofs of non-revocation.
The authenticating party embeds the current tick in the certificate's MTCProof as the certificate's non-revocation proof -- alongside the inclusion proof that establishes authenticity -- enabling the relying party to cryptographically verify that the certificate has not been revoked, with granularity as fine as one hour, or finer.

This mechanism provides timely revocation without requiring signatures per revocation check, without relying on the relying party to poll for revocation updates, and without introducing new trust relationships beyond the existing CA.


--- middle

# Introduction

Merkle Tree Certificates {{I-D.ietf-plants-merkle-tree-certs}} authenticate TLS connections using compact inclusion proofs into a Merkle Tree maintained by a certification authority (CA).
The base MTC specification uses a short-lived certificates model, where certificate expiration replaces explicit revocation signals.

However, deployments such as Chrome's draft MTC policy {{CHROME-MTC}} permit certificate lifetimes of up to 47 days.
At this timescale, key compromise or certificate misissuance can cause significant harm before natural expiry.
The base MTC specification acknowledges this gap and suggests that relying parties with access to external revocation systems like {{CRLite}} or {{CRLSets}} SHOULD use them, but does not define an in-band revocation mechanism.

This document defines such a mechanism based on hash chains {{MICALI}}.
At issuance, the CA commits a hash chain anchor into the MTC log entry as an X.509 extension.
Each revocation period (e.g., every hour), the CA reveals the next hash chain value for all non-revoked certificates.
To revoke a certificate, the CA simply stops revealing values.
The authenticating party (server) embeds the current hash chain value in the certificate's MTCProof (the signatureValue), and the relying party (client) verifies it against the anchor committed in the log entry.

The MTCProof already carries a proof of inclusion: the evidence that a certificate is authentic, because its entry sits in a cosigned Merkle Tree.
This mechanism adds a proof of non-revocation to the same structure, so that together they let a relying party confirm not merely that the certificate was issued, but that it may be relied upon now.

This approach achieves the following properties:

- **Timely revocation:** Revocation takes effect within one period (e.g., one hour), regardless of when the relying party last updated its trusted subtrees.

- **No per-check signatures:** Unlike OCSP {{RFC6960}}, verification requires only hash computations, not signature verification.
  The CA incurs no signing load for revocation status.

- **Mandatory enforcement:** The hash chain value is a required component of the certificate presentation.
  Unlike OCSP stapling, the mechanism cannot be silently omitted by the authenticating party.

- **Self-authenticating:** The hash chain value is verified against the anchor already committed in the Merkle Tree.
  No new trust relationships or authenticated channels are needed.

- **Minimal overhead:** A single tick (36 bytes for SHA-256: a 4-byte period and a 32-byte hash value) is added per handshake to the certificate's MTCProof; the committed anchor adds roughly 40 to 50 bytes to each log entry ({{assertion-integration}}).

## Rationale for This Approach

Several alternative revocation mechanisms were considered and rejected.
{{alternatives}} provides detailed analysis of each.
The hash chain approach was selected because it uniquely combines mandatory enforcement (the value is structurally required for certificate validity), zero signing overhead, self-authentication against an already-trusted anchor, and minimal bandwidth cost.

## Why Functional Revocation Is Superior to Passive Expiry {#revocation-vs-expiry}

A common argument holds that sufficiently short certificate lifetimes eliminate the need for revocation: if a certificate expires in one day, the window of exposure after key compromise or misissuance is bounded by that day.
This reasoning is incomplete.
Three independent time intervals govern the security of a certificate:

1. **Certificate lifetime:** The maximum duration for which a certificate can be presented.
   Without revocation, this is the upper bound on exposure after any problem.

2. **Revocation latency:** Once the CA decides to revoke, how quickly can the certificate become unusable?
   Without a revocation mechanism, this equals the remaining certificate lifetime.
   With hash chain revocation, this is at most two revocation periods (e.g., two hours).

3. **CA validation frequency:** How often the CA re-verifies that the subscriber remains authorized (domain control, organization identity, etc.).
   This determines how quickly the CA *learns* of problems that are not self-reported by the subscriber.

These three intervals interact as follows.
The worst-case exposure time after a problem occurs is:

    exposure = min(remaining_lifetime, detection_time + revocation_latency)

Without revocation, detection_time is irrelevant — the certificate remains valid until it expires regardless of what the CA knows.
With revocation, the CA can act as soon as it detects the problem, and the certificate becomes unusable within the revocation latency.

This has a counterintuitive consequence: a certificate with a long lifetime but active revocation can provide *shorter* exposure than a certificate with a short lifetime but no revocation.
For example:

- A 1-day certificate without revocation: worst-case exposure is ~24 hours (compromise occurs immediately after issuance).

- A 47-day certificate with 1-hour hash chain revocation: if the CA learns of the compromise within minutes (subscriber report, domain validation re-check, or external notification), worst-case exposure is ~2 hours.

By substituting expensive asymmetric signatures with incredibly cheap symmetric hashing, this mechanism allows CAs to achieve the security benefit of an hourly expiration window without any of the architectural cost that comes with hourly re-issuance {{SHORTLIVED}}.
Rather than re-signing and re-logging every certificate each hour, the CA reveals a single precomputed hash value per period, and the relying party verifies it with a single hash computation.

The critical difference is that passive expiry provides no mechanism for the CA to act on new information.
A hash chain tick is a *continuous assertion of non-revocation* — each tick is an active statement by the CA that, as of this period, it has not revoked the certificate.
Absence of the tick is immediately detectable and enforced by the relying party.

### The Role of CA Validation Frequency

Even with functional revocation, the CA cannot revoke a certificate for a problem it does not know about.
The frequency of CA re-validation therefore determines the effective security bound for non-self-reported problems (e.g., loss of domain control that the subscriber does not notice or report).

Without revocation, validation frequency is largely irrelevant: even if the CA discovers a problem mid-lifetime, it cannot shorten the certificate's validity.
The only recourse is to publish the revocation via an external mechanism (CRLite, CRLSets) that may or may not reach all relying parties.

With hash chain revocation, frequent CA validation translates directly into security improvement: the CA can revoke within one period of detecting any problem.
This creates an incentive structure where CAs that validate more frequently provide measurably better security — an incentive that does not exist in a pure short-lived-certificate model without revocation.

Root program policies can leverage this by requiring both short revocation periods and minimum re-validation frequencies, achieving a defence-in-depth posture that neither mechanism provides alone.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the hash function HASH and its output length in bytes HASH_SIZE that a Merkle Tree CA defines for its issuance logs (Section 5 of {{I-D.ietf-plants-merkle-tree-certs}}); for a CA using SHA-256, HASH is SHA-256 and HASH_SIZE is 32.
Hash chain values, the anchor, and the tick all use this hash.

The HashChainTick that this mechanism embeds in the MTCProof ({{cert-format}}) is the certificate's *non-revocation proof*: the component of the MTCProof attesting that the certificate has not been revoked as of the current period, complementing the inclusion proof and cosignatures that attest authenticity.
The separate entry_hash used only to address ticks ({{distribution}}) is always computed with SHA-256, independent of the CA's tree hash.

# Hash Chain Construction {#construction}

## Parameters

The hash chain mechanism introduces the following additional parameter:

revocation_period:
: A duration, in seconds, that determines the granularity of revocation.
  This MUST be greater than zero.
  The RECOMMENDED and default value is 3600 (one hour); {{assertion-integration}} specifies how this default is encoded so that a certificate using it carries no revocation_period bytes.
  The number of periods in a certificate's lifetime is `chain_length = ceil(lifetime / revocation_period)`.
  revocation_period need not evenly divide the lifetime; if it does not, the final period is shorter than revocation_period, ending when the certificate expires.
  This is harmless: the verifier computes the period from not_before ({{construction}}) and the base MTC validity check bounds the certificate at notAfter, so the truncated final period needs no special handling, and its shorter span only means revocation during it takes effect faster.

The certificate's validity period MUST be longer than revocation_period.
A certificate whose validity period is not longer than revocation_period would have `chain_length = 1`: its only tick is the public period-0 anchor, which enforces nothing (revocation is only enforceable from period 1 onwards; see {{period-zero-rationale}}).
A CA MUST NOT include the id-pe-hashChainAnchor extension, and MUST NOT use this mechanism, for such a certificate.
Because the period-0 grace defers enforcement of a just-issued certificate to the start of period 2 ({{period-zero-rationale}}), deployments SHOULD choose a validity period substantially longer than twice revocation_period so that revocation is effective for most of the certificate's life.

revocation_period is a per-certificate value: it is carried in the certificate itself, in the HashChainAnchorInfo committed to the Merkle Tree ({{assertion-integration}}), rather than being a CA-wide configuration constant.
This is deliberate.
Because a relying party verifies offline and has no provisioning relationship with the CA, the only way it can obtain revocation_period without a new authenticated distribution channel is to read it from the certificate; carrying it in the tree-committed extension makes it both discoverable by the relying party and self-authenticating.
It also lets a CA change revocation_period for newly issued certificates without redistributing anything or invalidating existing certificates, each of which keeps the value it was issued with.
A CA MAY of course use the same revocation_period for every certificate it issues; the point is only that the value each verifier uses comes from the certificate, not from CA-wide configuration that verifiers cannot see.

## Chain Generation

At certificate issuance time, for each log entry, the CA generates a hash chain as follows:

1. Generate a cryptographically random seed of HASH_SIZE bytes (32 bytes for SHA-256).

2. Compute the chain_length + 1 values of the hash chain:

       h[0] = seed
       h[i] = Hash(HashChainInput(h[i-1]))  for i = 1, ..., chain_length

   Where HashChainInput is defined in {{encoding}}.

3. The anchor (target) is `h[chain_length]`, the final value in the chain.

The anchor is included in the certificate as an X.509 extension (see {{assertion-integration}}).

## Period Numbering

Periods are numbered starting from 0.
Period 0 begins at the certificate's notBefore time and each subsequent period begins revocation_period seconds later.
The period number at any given time t is:

    period = floor((t - not_before) / revocation_period)

not_before is the notBefore time of the certificate's validity period, expressed in the same units as t (seconds since the Unix epoch).
It anchors the period schedule to a value that both the CA and every verifier read from the certificate, so they compute identical period boundaries regardless of their wall-clock differences; it is not necessarily the exact instant of issuance.
The CA MUST number periods from notBefore and MUST NOT begin revealing ticks before period 0 starts at notBefore.

A CA commonly sets notBefore slightly earlier than the actual instant of issuance (backdating) to tolerate relying-party clock skew.
This is harmless here: it merely places the certificate a little way into period 0 when it is first presented (or, if notBefore is backdated by more than one revocation_period, into a later period).
Setting notBefore later than issuance (forward-dating) is different: there is no period earlier than 0, and for any time t earlier than notBefore the quantity (t - not_before) is negative.
Such a certificate is simply not yet valid; a verifier MUST reject it through the base MTC validity check before computing any period, and MUST NOT evaluate the period expression with unsigned arithmetic, which would underflow for such times and could yield a spuriously large period.

## Revealing Values {#revealing-values}

For each non-revoked certificate, at the start of period t, the CA reveals the hash chain value `h[chain_length - t]`.
This value can be verified by hashing it t times and comparing with the anchor.

For period 0, `chain_length - t` equals `chain_length`, so the value revealed is the anchor `h[chain_length]` itself, which is already public (it is committed in the certificate; see {{assertion-integration}}).
The period 0 tick therefore provides no cryptographic assurance of non-revocation, and any party can construct it.
This is an intentional design choice; see {{period-zero-rationale}} for the rationale.

To revoke a certificate, the CA stops revealing new values.
Once the previous value expires (at the start of the next period), the certificate is effectively revoked: no party can produce a valid value without knowledge of unrevealed chain elements, which requires inverting the hash function.
Because period 0's value is the public anchor, the earliest period for which the CA can withhold a secret value is period 1; a certificate therefore cannot be revoked during period 0.

## Security of the Hash Chain

The security of this mechanism relies on the preimage resistance of the hash function.
Given `h[i]`, it is computationally infeasible to compute `h[i-1]` (which would be needed to forge a future validity proof).
The chain is revealed in reverse order precisely for this reason: knowledge of the current value does not help compute future values.

The label in HashChainInput ({{encoding}}) domain-separates chain values from other uses of the hash function in MTC, and the per-entry issuer_id, log_number, and index salt each certificate's chain into its own hash domain ({{encoding}}).

## Rationale for Using the Target as the Period 0 Tick {#period-zero-rationale}

Revealing the anchor `h[chain_length]` as the period 0 tick means the mechanism does not enforce revocation during period 0.
The earliest period for which the CA can withhold a secret value is period 1, and, because a relying party accepts the tick for the current or the immediately preceding period (the acceptance window of {{verification}} also allows the immediately following period, but that does not extend acceptance of the period 0 anchor), the public anchor remains acceptable throughout period 1.
A certificate that the CA wishes to revoke from the moment of issuance thus becomes unusable at the start of period 2.
This is the same worst-case bound of at most two revocation periods that applies to any revocation decision ({{revocation-vs-expiry}}); the only capability given up is the ability to revoke a certificate faster than that bound in the first moments after issuance.
This trade-off is deliberate and has two advantages.

Operational grace period at issuance:
: The CA's tick distribution service ({{distribution}}) does not need to have computed and begun serving a certificate's first secret tick at the exact instant of issuance.
  It has until the start of period 1 -- one full revocation_period -- to make the certificate's chain available.
  This mirrors established practice for OCSP {{RFC6960}}, where a newly issued certificate's first status response is permitted to be briefly unavailable after issuance (the CA/Browser Forum Baseline Requirements, for example, allow up to 15 minutes).
  Revocation infrastructure need not be instantaneously ready for brand-new certificates.

Narrow, low-value window:
: The only capability lost is revoking a certificate within the first revocation_period after it was issued.
  A certificate that must be revoked within, for example, one hour of issuance is an unusual case, and the CA directly controls the relevant decision: if it already knows at issuance time that a certificate should not be trusted, it simply does not issue it.
  That an arbitrary party can present the public anchor as a period 0 tick confers no additional capability on an attacker, because presenting the certificate in a TLS handshake still requires possession of the corresponding private key.
  It means only that the CA's revocation signal does not take effect until period 1.

A deployment that instead requires revocation enforcement from the moment of issuance, with no period 0 grace, can obtain it by treating the anchor as an ordinary secret chain element: compute the chain one element longer, use `h[chain_length + 1]` as the anchor, and hash the revealed value `period + 1` times (rather than `period` times) during verification.
The period 0 tick is then the secret value `h[chain_length]`, which the CA can withhold.
This document uses the shorter construction because the operational grace period is generally more valuable than sub-two-period revocation of a just-issued certificate.

# Amendments Requested of the Base Specification {#base-spec-amendments}

This mechanism is designed to layer onto the base MTC specification {{I-D.ietf-plants-merkle-tree-certs}} with as little change to it as possible.
For convenience, this section collects the amendments this document asks of the base specification; each is specified in full in the section cited.

Exactly one change to the base specification is required:

- **Amend the Section 7.2 "extra data" check** so that, when a certificate carries the hash chain anchor, the MTCProof in its signatureValue may carry the HashChainTick, and otherwise remains byte-identical to a base MTCProof.
  The RECOMMENDED realization appends a trailing status_tick field ({{tick-trailing-field}}); a base specification that instead adopts the general proof_extensions field ({{mtcproof-extensibility}}) carries the tick as a proof extension ({{tick-proof-extension}}) and amends Section 7.2 accordingly.

The following item is optional; a base specification MAY adopt it but need not:

- **Register a hash_chain_anchor entry-extension type** in the MerkleTreeCertEntryExtensionType registry, as an alternative home for the anchor, if the base specification is willing to make its entry-extension registry and cosigner software aware of this mechanism ({{anchor-entry-extension}}).

Everything else this document defines -- the id-pe-hashChainAnchor X.509 extension ({{iana-considerations}}), the hash chain construction ({{construction}}), verification ({{verification}}), and tick distribution ({{distribution}}) -- layers on top of an otherwise unmodified base MTC log and cosigner deployment and needs no base-specification change.

# Integration with MTC Log Entries {#assertion-integration}

## Hash Chain Anchor Extension

This document defines a new X.509 certificate extension for carrying the hash chain anchor.
This extension is included in the TBSCertificateLogEntry's extensions field, and thus appears in the TBSCertificate of the resulting Merkle Tree Certificate.

    id-pe-hashChainAnchor OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) dod(6) internet(1)
        security(5) mechanisms(5) pkix(7) pe(1) TBD }

The extension value contains the DER encoding of the following ASN.1 structure:

    HashChainAnchorInfo ::= SEQUENCE {
        revocationPeriod  INTEGER (1..MAX) DEFAULT 3600,
        anchor            OCTET STRING
    }

revocationPeriod:
: The revocation period in seconds for this certificate ({{construction}}), with a default of 3600 (one hour).
  Under DER, a certificate using the default value MUST omit this field (X.690, Section 11.5), so the common one-hour case adds no per-entry bytes; a relying party that finds the field absent MUST use the default of 3600.
  The relying party reads this value (or the default) from here; it is used to number periods and to compute the expected period during verification ({{verification}}).

anchor:
: The hash chain anchor value `h[chain_length]`.
  This OCTET STRING MUST be exactly HASH_SIZE bytes long; a relying party MUST reject the certificate if it is not ({{verification}}).

The id-pe-hashChainAnchor extension SHOULD be marked non-critical, so that relying parties that do not implement this mechanism can still process the certificate.
However, relying parties that do implement this mechanism MUST enforce hash chain verification as described in {{verification}} when the extension is present.
An MTC ecosystem in which all relying parties are expected to support hash chain revocation MAY mark the extension critical, causing implementations that do not recognize it to reject the certificate.

The extension MUST appear at most once in a certificate.
The extension MUST NOT be present in a certificate whose validity period is not longer than revocation_period ({{construction}}); such a certificate cannot advance beyond period 0, so the mechanism would enforce nothing.

Because the anchor is committed to the Merkle Tree, this extension enlarges every log entry that carries it.
With the default revocation_period, the committed data is a HashChainAnchorInfo carrying only the anchor (HASH_SIZE bytes, 32 for SHA-256) plus its DER and extension framing -- on the order of 40 to 50 bytes per entry.
This is the unavoidable price of self-authentication: unlike the tick base URL, which is deliberately kept out of the certificate ({{discovery}}), the anchor is the value every tick is verified against and therefore cannot be delivered out of band.
The DEFAULT encoding of revocationPeriod keeps that field off the wire whenever the default period is used, holding the committed cost to the anchor itself.

## Alternative: Carrying the Anchor as a Merkle Tree Entry Extension {#anchor-entry-extension}

This document carries the anchor in an X.509 certificate extension (id-pe-hashChainAnchor) placed in the extensions field of the TBSCertificateLogEntry, and thus also in the TBSCertificate.
An alternative is to carry it as a MerkleTreeCertEntryExtension -- the entry-level extension point defined in Section 5.2.1 of {{I-D.ietf-plants-merkle-tree-certs}} -- rather than as an X.509 extension.
Both are committed to the Merkle Tree, so either home makes the anchor self-authenticating; the choice is between two extension mechanisms, not between committed and uncommitted storage.

In this alternative, a new MerkleTreeCertEntryExtensionType (for example, hash_chain_anchor) is registered with the base specification, and its extension_data carries the HashChainAnchorInfo (DER-encoded, or an equivalent TLS-encoded structure).
The verifier reads the anchor and revocation_period from the entry's extensions, which it already reconstructs from the MTCProof's extensions field during base MTC verification (Section 7.2 of {{I-D.ietf-plants-merkle-tree-certs}}), rather than from an X.509 extension.

This changes what `entry_hash` ({{distribution}}) covers, though not its role.
entry_hash is computed over tbs_cert_entry_data, which contains the TBSCertificateLogEntry but not the entry-level extensions of the MerkleTreeCertEntry.
In this alternative the anchor is therefore committed to the tree through the MerkleTreeCertEntry rather than through tbs_cert_entry_data, and does not contribute to entry_hash; in the primary design the anchor, as an X.509 extension of the TBSCertificateLogEntry, is part of tbs_cert_entry_data and does contribute.
Either way entry_hash remains well-defined and identical for a given entry's standalone and landmark-relative certificates ({{cert-profiles}}), and continues to serve only as the tick-URL identifier.

This has a natural symmetry with the tick's encoding: the immutable, committed anchor lives in the committed entry extensions, while the mutable, per-period tick lives in the uncommitted trailing field or proof_extensions ({{cert-format}}).
It is also more compact, because a MerkleTreeCertEntryExtension uses a short TLS type-and-length framing rather than an X.509 extension's OBJECT IDENTIFIER and DER wrapper.

It has three costs, however:

- **No criticality lever.**
  Entry extensions have no critical marking, and relying parties ignore unrecognized ones (Section 12.5 of {{I-D.ietf-plants-merkle-tree-certs}}).
  The transition strategy of marking the X.509 extension critical to force unaware relying parties to hard-fail ({{objections}}) is therefore unavailable; enforcement rests entirely on relying parties that implement this mechanism.

- **Not visible to generic X.509 tooling.**
  The anchor no longer appears in the TBSCertificate, so only MTC-aware software can observe that a certificate uses this mechanism.

- **The log-signing infrastructure must be MTCRS-aware.**
  Section 5.4 of {{I-D.ietf-plants-merkle-tree-certs}} forbids a CA cosigner from signing a subtree containing an entry with an extension_type it does not recognize.
  A hash_chain_anchor entry extension therefore forces the CA's log and cosigner components to recognize it before they can sign any subtree containing an MTCRS certificate.
  With the X.509 extension, the anchor rides inside the entry's tbs_cert_entry_data as ordinary certificate bytes, so that recognition gate (which concerns the entry type and extension_type, not X.509 extensions) never fires: the generic log and cosigner infrastructure remain MTCRS-agnostic, and only the issuance front-end and the tick distribution service ({{distribution}}) need be MTCRS-aware.

Because of the last point in particular, this document uses the X.509 extension as the primary design: it lets this mechanism be layered onto an otherwise unmodified MTC log and cosigner deployment.
A base specification that is willing to make its entry-extension registry and cosigner software aware of hash chain revocation MAY instead adopt the entry-extension encoding, gaining the compactness and the committed/uncommitted symmetry described above.

# Certificate Presentation {#cert-format}

## Hash Chain Tick

When a hash chain anchor extension is present in the certificate, the authenticating party MUST include a hash chain tick in the MTCProof structure (carried in the certificate's signatureValue).
The tick is the certificate's non-revocation proof: where the inclusion proof and cosignatures attest that the certificate is authentic, the tick attests that it has not been revoked as of the current period.
The tick is a HashChainTick:

    struct {
        uint32 period;
        HashValue value;
    } HashChainTick;

period:
: The period number for which this tick is valid.
  It tells the relying party both the freshness the tick asserts -- that the certificate was not revoked as of this period, checked against the relying party's clock ({{verification}}) -- and how many times to hash value forward to reach the committed anchor, which cannot be taken from the relying party's own expected period because clock skew and caching allow the presented tick to be for an adjacent period.
  The field is 32 bits so that fine revocation_period values remain usable across the full certificate lifetime: a 16-bit field would overflow at 65,535 periods, which a minute-granularity period already exceeds within a 47-day lifetime.

value:
: The hash chain value `h[chain_length - period]`.

The MTCProof is not committed to the Merkle Tree (only the TBSCertificateLogEntry is hashed into the tree), so the tick can be updated each period without affecting the inclusion proof or cosignatures.
The authenticating party reconstructs or replaces the signatureValue with a fresh tick while reusing the same inclusion proof and signatures.

The authenticating party MUST include a HashChainTick with a period value that is current at the time of the TLS handshake.
A relying party SHOULD accept ticks for the current period, the immediately preceding period, or the immediately following period, to allow for clock skew and caching ({{clock-skew}}).

This document describes two possible ways to carry the HashChainTick inside the MTCProof, but only one is used in practice: the encoding is fixed by the base MTC specification, not chosen per deployment.
Both are amendments to the base MTCProof structure and differ in generality.
The trailing-field encoding ({{tick-trailing-field}}) is RECOMMENDED: it appends the fixed-size tick directly to the MTCProof, which is the minimal change and confines the added, unauthenticated bytes to exactly one value that a conforming relying party fully verifies.
The proof-extension encoding ({{tick-proof-extension}}) is an alternative for a base specification that additionally wants a general, reusable proof-level extensibility point ({{mtcproof-extensibility}}); as a general "ignore if unknown" channel it carries the abuse surface discussed in {{proof-extensions-considerations}}, which for a single 36-byte use is not otherwise justified.
Whichever encoding the base specification selects becomes the single encoding used throughout the ecosystem; the other is discarded (see {{objections}}).

### Preferred Encoding: Trailing status_tick Field {#tick-trailing-field}

In the RECOMMENDED encoding, the base MTC specification is amended to append the HashChainTick to the MTCProof as a trailing status_tick field.
The field is not a bare optional field -- the base MTCProof has no discriminant for one -- but a variant selected by whether the certificate carries the id-pe-hashChainAnchor extension, occupying zero bytes when it does not:

    struct {
        MerkleTreeCertEntryExtension extensions<0..2^16-1>;
        uint48 start;
        uint48 end;
        HashValue inclusion_proof<0..2^16-1>;
        MTCSignature signatures<0..2^16-1>;
        select (certificate_has_hashChainAnchor) {
            case false: Empty;
            case true:  HashChainTick;
        } status_tick;
    } MTCProof;

certificate_has_hashChainAnchor is the contextual boolean "the certificate's TBSCertificate contains the id-pe-hashChainAnchor extension".
Like the base specification's select on the certificate context (for example, Section 5.2.1 of {{I-D.ietf-plants-merkle-tree-certs}}) and the analogous contextual selects in TLS ({{RFC8446}}), the discriminant is not a field of the structure; it is always available where an MTCProof is parsed, because an MTCProof is only ever decoded as the signatureValue of a specific certificate whose extensions are known.
The false case uses the Empty type (an empty structure), so a certificate that does not use this mechanism carries no additional bytes and is byte-identical to a base MTCProof.

This resolves precisely the "extra data after the MTCProof" check in Section 7.2 of {{I-D.ietf-plants-merkle-tree-certs}}, which that section is amended to interpret as follows:

- If the certificate contains the id-pe-hashChainAnchor extension (the true case), exactly one HashChainTick (4 + HASH_SIZE bytes; 36 bytes for SHA-256) MUST immediately follow the signatures vector, and the signatureValue MUST end there. A relying party MUST reject the certificate if any bytes remain after this HashChainTick, or if the signatureValue ends before a complete HashChainTick has been read.
- If the certificate does not contain the id-pe-hashChainAnchor extension (the false case), status_tick is Empty and the original rule is unchanged: the signatureValue MUST end immediately after the signatures vector, with no trailing bytes.

A relying party predating the amendment would reject the certificate at the MTCProof parsing stage; such a relying party could not verify hash chain revocation in any case.

This is the minimal change to the base MTCProof structure.
Because the appended field is fixed-size and, for a conforming relying party, fully verified against the committed anchor ({{verification}}), it adds no variable-length "ignore if unknown" region and hence no general stuffing or covert-channel surface (contrast {{tick-proof-extension}} and {{proof-extensions-considerations}}).
Its only cost is that carrying a second proof-level mechanism in future would require a further base-specification change.

### Alternative Encoding: Proof Extension {#tick-proof-extension}

Alternatively, if the base MTC specification wants a general, reusable proof-level extensibility point rather than a single appended field, it can adopt the `proof_extensions` structure defined in {{mtcproof-extensibility}} and carry the HashChainTick as one of its entries.

The HashChainTick is then encoded as an MTCProofExtension with `extension_type` set to `hash_chain_tick(0)` and `extension_data` containing the serialized HashChainTick (4 + HASH_SIZE bytes), as described in {{mtcproof-extensibility}}.
When the id-pe-hashChainAnchor extension is present, the MTCProof MUST contain exactly one hash_chain_tick proof extension.

This encoding can also carry future proof-level mechanisms (for example, other self-authenticating freshness values) without a further structural change, and lets a conforming parser skip a tick it does not recognize.
Those benefits come at a cost: as a general, unauthenticated, "ignore if unknown" channel it introduces the abuse surface -- bloat, covert channels, and a strippable soft-fail for any misuse -- discussed in {{proof-extensions-considerations}}.
This document treats that surface as unjustified for a single 36-byte use, and therefore recommends the trailing field ({{tick-trailing-field}}) unless a concrete need for general extensibility exists.

## Use in TLS {#tls-use}

No new TLS extension type is required.
When the authenticating party presents a Merkle Tree Certificate, the hash chain tick is carried within the certificate's signatureValue as part of the MTCProof, which is already transmitted in the CertificateEntry.

The presence of the hash chain anchor -- the id-pe-hashChainAnchor extension in the primary design, or the hash_chain_anchor entry extension in the alternative ({{anchor-entry-extension}}) -- signals to the relying party that the MTCProof carries a HashChainTick ({{cert-format}}).
If the tick is absent, malformed, or fails verification, the relying party MUST reject the certificate.

## Standalone and Landmark-Relative Certificates {#cert-profiles}

A Merkle Tree CA can issue two certificate profiles for the same log entry: a standalone certificate and a landmark-relative certificate (Sections 6.3 and 6.4 of {{I-D.ietf-plants-merkle-tree-certs}}).
The two differ only in the subtree and signatures carried in their MTCProof; they certify the same TBSCertificateLogEntry.

Hash chain revocation is keyed by the log entry, not by the certificate profile:

- Both profiles commit to the same id-pe-hashChainAnchor extension (part of the TBSCertificateLogEntry, or of the entry's extensions; see {{anchor-entry-extension}}), so a single anchor and hash chain per entry serves both.
- entry_hash ({{distribution}}) is computed over the entry's tbs_cert_entry_data, which is identical for both profiles, so both resolve to the same tick URL and the same tick.
- The HashChainTick for a given period is therefore identical in both certificates.

An authenticating party that holds both a standalone and a landmark-relative certificate for the same entry -- for example, during the renewal overlap described in Section 10.4 of {{I-D.ietf-plants-merkle-tree-certs}} -- fetches the entry's tick once per period and writes that same value into the MTCProof of whichever certificate it presents.
Refreshing the tick is independent of profile selection: the authenticating party selects between the two certificates using the base MTC mechanism (Section 8 of {{I-D.ietf-plants-merkle-tree-certs}}), and updates the HashChainTick in whichever MTCProof it sends.

# Verification {#verification}

When a relying party receives a Merkle Tree Certificate with the id-pe-hashChainAnchor extension, it performs hash chain verification in addition to the base MTC verification procedure.
The steps below name the id-pe-hashChainAnchor X.509 extension of the primary design; under the entry-extension alternative ({{anchor-entry-extension}}) the relying party instead reads the same HashChainAnchorInfo from the entry's extensions, and the procedure is otherwise identical.

The verifier first assembles the inputs to HashChainInput ({{encoding}}) and to the period computation ({{construction}}).
All of them are obtained from the certificate and the trust anchor being validated against; no data from the CA's tick distribution service ({{distribution}}) is needed, and the verifier MUST NOT fetch anything ({{rp-no-fetch}}):

- **issuer_id:** the TrustAnchorID of the trust anchor against which the certificate is being validated (Section 5.1 of {{I-D.ietf-plants-merkle-tree-certs}}).
- **log_number and index:** recovered from the certificate's serial number, which the base specification defines as `serial = (log_number << 48) | index` (Section 6.2 of {{I-D.ietf-plants-merkle-tree-certs}}); the verifier takes index as the low 48 bits and log_number as the remaining high bits.
- **revocation_period and anchor:** read from the HashChainAnchorInfo carried in the id-pe-hashChainAnchor extension; if revocationPeriod is absent, use its default of 3600 ({{assertion-integration}}).
- **not_before:** the notBefore time of the certificate's validity period ({{construction}}), which is the same value the CA used to number periods.

Using these inputs, the verifier performs the following steps:

1. Extract the HashChainAnchorInfo from the certificate's id-pe-hashChainAnchor extension.
   If not present, skip hash chain verification (the certificate does not use this mechanism).
   If the anchor OCTET STRING is not exactly HASH_SIZE bytes, reject the certificate with a bad_certificate error.

2. Extract the HashChainTick from the MTCProof (in the certificate's signatureValue), according to the encoding fixed by the base MTC specification: the trailing status_tick field ({{tick-trailing-field}}) or, if the general proof_extensions amendment was adopted instead, the hash_chain_tick proof extension ({{tick-proof-extension}}).
   If the id-pe-hashChainAnchor extension is present but the MTCProof does not carry a HashChainTick, reject the certificate with a bad_certificate error.

3. Compute the expected period from the current time:

       expected_period = floor((current_time - not_before) / revocation_period)

4. Check that `tick.period` is equal to expected_period, expected_period - 1, or expected_period + 1 ({{clock-skew}}).
   If not, reject the certificate with a certificate_expired error (this alert also covers a tick too far in the future, which a verifier whose clock is well behind the authenticating party's would see).

5. Starting from `tick.value`, iteratively hash `tick.period` times:

       v = tick.value
       for i = 1 to tick.period:
           v = Hash(HashChainInput(v))

   Because step 4 has already constrained `tick.period` to within one of expected_period (and hence to at most chain_length + 1), the iteration count is bounded by the certificate's own lifetime and cannot be inflated by a forged tick to mount a denial-of-service attack.

6. Compare the result with anchor from the HashChainAnchorInfo.
   If they do not match, reject the certificate with a bad_certificate error.

If all steps succeed, the hash chain verification passes, confirming that the CA has not revoked this certificate as of the indicated period.

Although the MTCProof is not committed to the Merkle Tree and can be modified in transit, the tick is self-authenticating: steps 5 and 6 bind both tick.value and tick.period to the committed anchor, because a given value reaches the anchor only after the exact number of forward hashes that its true period implies.
Tampering with either field therefore fails verification, and producing a tick for a period the CA has not yet revealed requires inverting the hash function ({{security-considerations}}).
The only tick an attacker can present that still verifies is a genuine, already-revealed one, and step 4 bounds how stale that may be.

# Tick Distribution {#distribution}

The CA MUST provide a mechanism for authenticating parties to obtain current hash chain ticks.
This document defines an HTTP interface for this purpose.

## HTTP Interface

The CA (or a mirror) serves ticks over HTTP.
Given a tick base URL for the CA (see {{discovery}}), the tick for a particular certificate is fetched from:

    GET {tick_base_url}/.well-known/mtcrs/tick/{entry_hash}

where {entry_hash} is the lowercase hex-encoded SHA-256 hash of the certificate's TBSCertificateLogEntry, computed over exactly the same octets that the base specification commits to the Merkle Tree for that entry (the tbs_cert_entry_data byte string defined by {{I-D.ietf-plants-merkle-tree-certs}}, i.e. the encoded contents of the entry with no enclosing tag or length prefix), so that the CA and the authenticating party derive an identical value.
entry_hash is always computed with SHA-256, even for a CA whose Merkle Tree uses a different hash function: it is only a stable identifier for the tick URL, not a tree leaf hash.
The authenticating party computes {entry_hash} from the TBSCertificateLogEntry it already possesses; no additional per-request metadata from the CA is required.

The tick base URL is not derived from the CA's identifier.
A Merkle Tree CA is identified by a TrustAnchorID, which is a relative object identifier (Section 5.1 of {{I-D.ietf-plants-merkle-tree-certs}}) rather than a hostname, so it cannot be turned into an origin.
The base URL is instead conveyed to the authenticating party out of band, as described in {{discovery}}.

The scheme (`http://` or `https://`) is whatever the CA specifies as part of the base URL.
Because each tick is self-authenticating (the relying party verifies it by hashing it forward to the anchor committed in the Merkle Tree), the tick fetch does not require transport-layer integrity, and because the tick value is public, it does not require transport-layer confidentiality of the response body.
CAs MAY therefore publish an `http://` base URL, which eliminates TLS handshake overhead and permits caching by any HTTP intermediary.
The one property plain HTTP does not provide is confidentiality of the request itself: an on-path observer can see which {entry_hash} is being requested.
CAs whose deployments consider this metadata sensitive SHOULD publish an `https://` base URL instead.

For example, if a CA's tick base URL is `http://mtcrs.ca.example`, ticks are served at:

    http://mtcrs.ca.example/.well-known/mtcrs/tick/a1b2c3...f0

The base URL is an origin (scheme, host, and optional port); the `.well-known/mtcrs/tick/{entry_hash}` path is rooted at that origin.
A CA MAY point that origin's hostname at a CDN or mirror through ordinary DNS or HTTP routing, so no path prefix is needed.

## Discovering the Tick Base URL {#discovery}

Because the CA's TrustAnchorID is an identifier and not a locator, the tick base URL MUST be conveyed to the authenticating party out of band.
This is not a gap: the authenticating party already obtains its certificate through a provisioning channel that involves a real CA endpoint (for example, an ACME directory), so that channel is the natural carrier for the base URL, and no locator need be derived from the certificate.

A CA MUST make the tick base URL available through at least one of the following mechanisms, and an authenticating party MUST support at least the provisioning-channel mechanism appropriate to how it obtains certificates:

- **Provisioning channel (primary).**
  The base URL is delivered when the certificate is provisioned.
  {{acme-integration}} defines this for ACME.
  CAs using other issuance protocols MUST provide an equivalent mechanism; the details are out of scope for this document.

- **CA certificate SIA (optional).**
  The base URL MAY additionally be published in the CA's certificate representation (Section 5.5 of {{I-D.ietf-plants-merkle-tree-certs}}) using the id-ad-mtcrsTicks Subject Information Access access method defined in {{iana-considerations}}, whose accessLocation is a uniformResourceIdentifier giving the tick base URL.
  This carries a single per-CA URL on a single object, adds no per-log-entry bytes, and provides a protocol-independent record that an authenticating party (or its tooling) can read once.
  When both mechanisms are present and disagree, the provisioning-channel value takes precedence.
  This mechanism carries only the base URL, so it does not apply when unguessable tick URLs ({{unguessable-urls}}) are used; in that case the full per-certificate URL is delivered through the provisioning channel and the SIA SHOULD NOT be published.

Keeping the base URL out of the certificate is not a secrecy measure -- the URL is derivable by anyone holding the certificate ({{rp-no-fetch}}) -- but a way to avoid standardizing a per-certificate fetch affordance in a field relying parties routinely parse.
Only the authenticating party is given the base URL through provisioning, because only it needs to refresh the value it presents; relying parties verify the embedded tick offline ({{verification}}) and MUST NOT fetch ticks ({{rp-no-fetch}}).

Because MTC certificates are renewed frequently (Section 10.4 of {{I-D.ietf-plants-merkle-tree-certs}} recommends renewal at about 75% of lifetime), a CA that migrates its tick infrastructure can update the base URL it hands out and rely on renewals to propagate the change, optionally serving HTTP redirects from the old origin in the meantime.

## ACME Integration {#acme-integration}

When the CA issues certificates via ACME, it SHOULD convey the tick base URL in the ACME order object as a new field:

    "tickBaseURL": "https://mtcrs.cdn.ca.example"

The `tickBaseURL` field contains the base URL (an origin) from which the authenticating party derives its tick fetch URL, by appending `/.well-known/mtcrs/tick/{entry_hash}` ({{distribution}}).
A single value covers all of the CA's certificates and lets the CA direct authenticating parties to a CDN, regional mirror, or any origin, without adding bytes to the certificate or log entry.

If the `tickBaseURL` field is absent from the ACME order, the authenticating party obtains the base URL through another mechanism in {{discovery}} (for example, the CA certificate SIA).

CAs using issuance protocols other than ACME SHOULD provide an equivalent mechanism for communicating the tick base URL during certificate provisioning.

## Unguessable Tick URLs {#unguessable-urls}

The tick fetch path described above is `.well-known/mtcrs/tick/{entry_hash}`, and {entry_hash} is derivable from the certificate by anyone who holds it, including a relying party ({{rp-no-fetch}}).
Keeping the base URL out of the certificate therefore does not make the tick URL unguessable.
A CA that wishes to make relying-party fetching infeasible by construction, rather than only forbidding it normatively, MAY replace the derivable path component with an unguessable per-certificate capability token:

    {tick_base_url}/.well-known/mtcrs/tick/{tick_token}

tick_token:
: A high-entropy (at least 128-bit) value that does not appear anywhere in the certificate.
  Because the token is absent from the certificate, a relying party cannot construct the URL, while the authenticating party is given it at provisioning time (see below).

The CA MAY generate the token by either of the following methods:

- **Random, with server-side state.**
  The CA generates a random token per certificate and maps it to the corresponding hash chain.
  This adds one indexed lookup to the CA's existing per-certificate state.

- **Deterministic, stateless (RECOMMENDED).**
  The CA derives the token by applying a deterministic authenticated encryption scheme (for example, AES-SIV {{RFC5297}}) keyed by a CA-held secret to the entry identifier:

      tick_token = key_id || DAE(K_ca, entry_hash)

  The CA recovers entry_hash by decrypting the token, so no additional per-certificate state is required.
  The token is unguessable without K_ca and is stable for the certificate's lifetime, which preserves caching.
  The key_id prefix identifies K_ca so that it can be rotated; the CA retains superseded keys for decryption during an overlap window, and because MTC certificates are renewed frequently (Section 10.4 of {{I-D.ietf-plants-merkle-tree-certs}}), rotated tokens propagate through renewal, as for base-URL migration ({{discovery}}).

When this hardening is used, discovery is necessarily per-certificate: the CA delivers the complete tick URL (base URL and token together) to the authenticating party through the provisioning channel.
For ACME, the order object carries the full URL in a `tickURL` field in place of `tickBaseURL` ({{acme-integration}}).
The CA-certificate SIA ({{discovery}}) conveys only the per-CA base URL, which cannot locate a token-addressed tick, and only the provisioning channel carries the token.
The SIA therefore provides no operational value when unguessable tick URLs are used, and a CA that uses them SHOULD NOT publish the id-ad-mtcrsTicks access method.

This hardening preserves the properties of the base HTTP interface.
Each token addresses a value that is immutable within a period, so per-period caching and CDN distribution ({{load-distribution}}) are unchanged.
The token is an addressing capability, not a confidentiality secret: the tick it locates is public and self-authenticating, so the fetch still requires no transport-layer integrity or confidentiality and MAY be served over plain HTTP.

The token is a bearer capability, and this hardening is defense in depth rather than a hard security boundary.
An authenticating party could disclose the token, and an on-path observer of a plain-HTTP fetch can see it; but possession of the token grants only the ability to fetch a public, self-authenticating non-revocation value (or to observe its absence).
It does not permit forging ticks, which requires the secret chain values ({{security-considerations}}), nor use of the certificate, which requires the corresponding private key.
Its benefit is that a relying party, or a third party holding a captured certificate, can no longer derive the tick URL from the certificate and probe the CA for its status ({{rp-no-fetch}}).

## Response Format {#response-format}

The response body is the serialized HashChainTick structure: a 4-byte big-endian period followed by HASH_SIZE bytes of value (36 bytes total for SHA-256).
The response Content-Type MUST be `application/octet-stream`.

The CA uses HTTP status codes ({{RFC9110}}) as follows:

- **200 (OK):** the response body is the current HashChainTick for the entry.
- **404 (Not Found):** the CA is not serving a current tick for this entry. This covers both a revoked certificate, for which the CA has stopped revealing values ({{revealing-values}}), and a tick that is merely not yet available -- for example during the period 0 grace, before the CA has published the chain ({{period-zero-rationale}}). The status code does not distinguish these cases, so an authenticating party MUST NOT treat a 404 as definitive proof of revocation; it means only that no fresh tick was obtained on this attempt. The authenticating party continues to serve its most recent still-valid tick and MAY retry (see the Operational Model below).
- **429 (Too Many Requests) or 503 (Service Unavailable):** transient overload; the authenticating party retries according to the Retry-After header ({{load-distribution}}).

Any other status code carries its ordinary HTTP semantics ({{RFC9110}}); an authenticating party treats any non-200 response as "no fresh tick obtained on this attempt" and falls back to its most recent still-valid tick.

The CA SHOULD set HTTP cache headers with a max-age no longer than revocation_period seconds.
For example:

    Cache-Control: public, max-age=3600

## Operational Model

The authenticating party periodically fetches its current tick from the CA:

1. At least once per revocation_period, the authenticating party fetches its updated HashChainTick.

2. The authenticating party SHOULD verify the fetched tick against the anchor committed in its own certificate before installing it: that hashing tick.value forward tick.period times yields the anchor ({{verification}}), and that tick.period is the period it expects to be current.
   This catches a corrupted, truncated, misrouted (wrong-entry), or unexpectedly stale response before it is ever presented in a handshake, where it would otherwise cause relying parties to reject the certificate.

3. The authenticating party updates the HashChainTick carried in its certificate's MTCProof (signatureValue) with the newly fetched value.
   The inclusion proof and cosignatures remain unchanged.

4. During TLS handshakes, the authenticating party presents the certificate with the current tick.

During period 0 the authenticating party need not fetch at all: the period 0 tick is the public anchor committed in its own certificate ({{revealing-values}}), which it can construct and present directly.
A 404 during period 0 is therefore expected and harmless, because the CA has until the start of period 1 to publish the chain ({{period-zero-rationale}}).

If the authenticating party is unable to obtain a fresh tick (e.g., due to CA unavailability), it continues to serve the most recent tick until that tick's period expires.
After expiry, the certificate becomes unusable until a fresh tick is obtained or a new certificate is provisioned.
{{objections}} (This Creates a New Availability Dependency) discusses this dependency and its mitigations, including widening the acceptance window ({{clock-skew}}) and holding certificates from multiple CAs.

At large deployment scale, tick distribution is dominated by aggregate request volume rather than per-request cost.
A CA serving 10^9 active certificates with a one-hour period sees on the order of 10^5 to 10^6 tick requests per second, and this load tends to concentrate at period boundaries if authenticating parties refresh in lockstep.
At this scale, edge caching (each tick is immutable within its period and cacheable for up to revocation_period seconds) and spreading of client refresh timing are required, not merely recommended, to avoid a thundering-herd load on the origin.
{{load-distribution}} describes recommended techniques.

## Distributing Tick Requests {#load-distribution}

Because a relying party also accepts a tick for the immediately preceding period ({{verification}}), an authenticating party has up to one full revocation_period of slack in which to fetch each new tick and need not fetch at the period boundary.
Two complementary mechanisms exploit this slack to prevent a period-boundary thundering herd.

### Client-Side: Deterministic Per-Entry Offset

Rather than fetching at the start of each period, an authenticating party SHOULD fetch at a fixed offset into the first half of the period, derived deterministically from its own entry_hash:

    offset = UINT32(entry_hash[0..3]) mod max(1, revocation_period / 2)

where entry_hash is the binary (pre-hex-encoding) SHA-256 hash of the TBSCertificateLogEntry, UINT32 interprets its first four bytes as a big-endian unsigned integer, and the division is integer division.
The authenticating party fetches the current period's tick at (period_start + offset), where period_start is the start time of that period.
During the first offset seconds of the period it continues to serve the preceding period's tick.
The serving delay and a verifier whose clock runs ahead both draw on the same one-period preceding-tick grace ({{clock-skew}}): a verifier whose clock is ahead by more than (revocation_period - offset) already expects the following period and rejects a tick two periods behind its expectation.
Bounding the offset to half of revocation_period leaves at least half a period of that grace available to absorb verifier clock skew, while still spreading fetches across a wide window.

Because entry hashes are uniformly distributed, deriving the offset this way spreads fetches uniformly across the period with no coordination, shared state, or central scheduler, and the offset is stable from period to period, which aids caching and diagnosis.
This is preferable to independent random jitter, which can still cluster and which varies each period.

### Server-Side: Cache Freshness and Retry-After

The CA (or an edge cache) SHOULD serve each tick with a Cache-Control max-age no longer than revocation_period seconds ({{response-format}}), so that a caching layer collapses many client requests for the same entry into a single origin fetch per period.
A CA MAY additionally apply a small per-response jitter to max-age so that cache entries for different entries do not all expire simultaneously.

Under transient overload, the CA or edge MAY respond with HTTP status code 429 (Too Many Requests) or 503 (Service Unavailable) together with a Retry-After header indicating when the authenticating party should retry.
To avoid a synchronized second wave, the CA SHOULD randomize Retry-After values across clients rather than returning a single fixed value.
Because the authenticating party retains its previously fetched tick, which remains valid until the end of the current period, backing off in response to Retry-After does not interrupt service, provided a fresh tick is obtained before the previous one expires.

## Delegated Tick Distribution {#delegated-distribution}

Because a tick is self-authenticating -- a relying party verifies it by hashing it forward to the anchor committed in the Merkle Tree ({{verification}}) -- the party that serves ticks need not be trusted for integrity or authenticity.
A distributor cannot forge a tick for a period the CA has not revealed (preimage resistance; {{security-considerations}}), and cannot serve a tampered value that verifies.
Tick distribution is therefore safe to delegate to third parties, which serve only public, self-authenticating values and hold no seed and no signing key.

Each period, the CA publishes to its authorized distributors the set of revealed values for that period -- a bundle keyed by entry_hash -- and each distributor serves them through the HTTP interface of {{distribution}}.
To revoke a certificate, the CA omits it from the next period's bundle: absence is revocation, so no revocation list is exchanged.
Because a distributor only ever receives already-revealed values, compromising it exposes nothing that is not already public and does not let it defeat revocation.

MTC mirrors are a natural home for this role: they already replicate and serve MTC log data at high availability, and extending a mirror to also serve the current period's ticks reuses that infrastructure without adding any trust, since the ticks it serves are self-authenticating.
Content delivery networks and relying-party-side operators -- including browser providers, which already run large-scale revocation-distribution infrastructure -- can serve as distributors on the same terms.
Operating such a service is distinct from the prohibition in {{rp-no-fetch}}, which forbids a relying party from using the endpoint as its own online responder during validation; it does not prevent a relying-party-side organization from running a distribution service that authenticating parties fetch from.
The only trust placed in any distributor is for availability, addressed by operating several and by the multi-CA strategy of {{objections}}.

What is delegated is distribution, not revocation authority.
The CA retains the seed and the unrevealed chain values ({{security-considerations}}), so it alone decides what to reveal each period; a distributor can at most withhold or delay the values it was given ({{dos-withholding}}), which is an availability fault mitigated by redundancy, not a way to un-revoke a certificate.

A CA MAY push only the current period's bundle, in which case each distributor depends on the CA every period and the CA retains tight, sole control of revocation.

Alternatively, as part of disaster-recovery planning, a CA MAY pre-provision a distributor with a small buffer of future periods' values, so that the distributor can keep certificates usable through a CA-side outage.
This is continuity (liveness) delegation, not delegation of revocation: sharing future ticks lets the holder keep certificates alive, and correspondingly removes the CA's ability to revoke them through that distributor for the buffered window, because a certificate cannot be revoked from a distributor that already holds its future values.
The buffer length therefore caps how quickly those certificates can be revoked through the hash chain; during the window the only remaining lever is the base MTC revoked-ranges fallback ({{interaction-with-base-mtc-revocation}}), which the CA controls independently.
Future values held by a distributor are as sensitive as the CA's own unrevealed chain values ({{security-considerations}}): compromising the distributor lets an attacker keep a revoked certificate alive for the remainder of the buffer.
A CA SHOULD therefore keep the buffer short -- sized to its outage-tolerance versus revocation-latency budget, the same trade-off as the period-0 grace ({{period-zero-rationale}}) -- and pre-provision only distributors trusted to stop serving on the CA's instruction.

Such a buffer is compact and inherently bounded.
For a buffer of N periods the CA need send each distributor only a single value per certificate -- the value that will be revealed N periods ahead -- from which the distributor derives every intervening period's value by hashing forward ({{revealing-values}}).
One value per certificate thus covers the whole buffer, and it confers no power beyond period t+N, since serving any later period would require inverting the hash.
A CA MUST NOT instead share the seed-derivation secret ({{derived-seeds}}) with a distributor: unlike a bounded buffer of already-revealed values, that secret would grant the unbounded ability to forge non-revocation for the entire certificate population.

This prohibition holds even in disaster recovery: a CA facing an unrecoverable failure MUST NOT hand its seed-derivation secret (or its per-certificate seeds) to a successor operator as a continuity measure.
That secret is as sensitive as the issuance signing key ({{derived-seeds}}), so transferring it is a root-key-custody event -- not a lightweight recovery step -- and it destroys the mechanism's forward security while transferring unbounded forging power and revocation authority over the entire population.
It is also unnecessary.
Continuity for already-issued certificates is provided by the bounded pre-provisioned buffer above, which keeps them usable through the outage without conferring any power beyond period t+N; and because MTC certificates are short-lived and renewed frequently (Section 10.4 of {{I-D.ietf-plants-merkle-tree-certs}}), the failing CA's population ages out within the buffer and remaining-lifetime window while subscribers migrate to a successor that issues fresh certificates under its own key and its own seed -- which never requires the old seed.
If the disaster is itself a seed or key compromise, the correct response is the revoked-ranges fallback ({{interaction-with-base-mtc-revocation}}), which contains the damage, rather than widening custody of a possibly-tainted forging secret.
The only scenario in which seed handover is even coherent is a full corporate succession that also transfers the signing key and trust anchors, governed by the same ceremony and root-program rules; even then, letting the old population expire under the buffer is cleaner than importing another CA's forging secret.

The feed from CA to distributor SHOULD be authenticated and integrity-protected; this is not required for relying-party security, which rests on self-authentication and the authenticating party's own pre-installation check ({{verification}}), but it prevents a distributor from being fed corrupt bundles that would cause authenticating parties to reject ticks and refetch.

# Privacy Considerations

The Privacy Considerations of {{I-D.ietf-plants-merkle-tree-certs}} (Section 11) apply to Merkle Tree Certificates that use this mechanism.
This mechanism adds one network interaction -- the authenticating party's periodic tick fetch ({{distribution}}) -- and deliberately adds none on the relying-party side.

No relying-party activity is exposed.
The current tick is embedded in the certificate presentation and verified offline against the committed anchor, and relying parties MUST NOT fetch ticks ({{rp-no-fetch}}).
Consequently the CA learns nothing about which certificates a relying party validates or which sites it visits.
This is the central privacy difference from client-driven OCSP {{RFC6960}}, whose status fetches revealed relying-party browsing to the CA; that failure mode is avoided here by construction rather than by policy.

The authenticating party's tick fetch, by contrast, exposes request metadata.
An on-path observer of a tick fetch, or the CA (or CDN) serving it, sees which entry_hash -- or, with unguessable tick URLs, which tick_token ({{unguessable-urls}}) -- is being requested, and can thereby learn which certificate the authenticating party holds.
For a public-facing server this reveals little, since the certificate it serves is itself public; the request identifies the authenticating party's own certificate, not any relying party.
Two points nonetheless bear noting:

- Because a tick is self-authenticating and public, the fetch does not require transport-layer confidentiality for correctness, so a CA MAY serve ticks over plain HTTP ({{distribution}}). Plain HTTP leaves the requested entry_hash or tick_token visible to on-path observers. A deployment that considers this metadata sensitive -- for example, one serving certificates that are not otherwise publicly enumerable -- SHOULD publish an https base URL instead.
- Unguessable tick URLs ({{unguessable-urls}}) are an addressing and access-control measure, not a confidentiality one: the tick_token appears in the request URL, so it offers no confidentiality against an observer of the authenticating party's own fetch. Its privacy benefit is solely that a relying party, or a third party holding only the certificate, cannot derive the URL and probe the CA for the certificate's status ({{rp-no-fetch}}).

# Security Considerations

## Hash Function Requirements

The security of this mechanism depends on the preimage resistance of the hash function used.
SHA-256 {{SHS}} provides 256 bits of preimage resistance, which is sufficient for all foreseeable certificate lifetimes.
With a one-hour revocation_period and a 47-day lifetime, the chain length is 1,128, which does not meaningfully degrade the security margin.

## Seed Confidentiality

The CA MUST keep the hash chain seed (h\[0\]) and all not-yet-revealed chain values confidential.
Compromise of these values would allow an attacker to produce future ticks, defeating revocation.

A CA that derives per-certificate seeds from a single long-term secret ({{derived-seeds}}) concentrates this requirement into that secret: it MUST then be protected at least as strongly as the issuance signing key, and per-log or per-epoch sub-seed derivation SHOULD be used to bound the impact of a compromise.

If the CA's seed storage is compromised, the CA MUST revoke all affected certificates via the base MTC revocation mechanism (revoked ranges of serial numbers) as a fallback; see {{interaction-with-base-mtc-revocation}}.

## Denial of Service via Tick Withholding {#dos-withholding}

A compromised or malicious CA could withhold ticks from a legitimate authenticating party -- either broadly or targeted at a specific subscriber, in which case it revokes that certificate with no auditable signal.
This is analogous to a CA refusing to issue OCSP responses, or refusing to issue or renew certificates at all: it is inherent in the CA trust model rather than novel to this mechanism, and it is mitigated by the same forces that discipline CA behaviour today:

- **Detectability.** The authenticating party knows it did not receive a tick, and can raise an alarm, switch to another CA, or fall back to a traditionally-signed certificate.
- **Third-party observability.** The tick distribution endpoint can be monitored externally (CT-style auditing), making selective withholding observable.
- **Market pressure.** An authenticating party that cannot reliably obtain ticks will switch CAs.

Because ticks are small (36 bytes) and cacheable, they are readily distributed via CDN, which further reduces the attack surface for withholding.

## Relying Parties Do Not Fetch Ticks {#rp-no-fetch}

The current tick is embedded in the MTCProof presented during the handshake and is verified offline against the anchor committed in the Merkle Tree ({{verification}}).
A relying party therefore has no need to contact the CA, and MUST NOT fetch ticks or otherwise use the tick distribution endpoint as an online revocation responder.

This is a privacy and availability protection, not a secrecy one.
The tick distribution URL is not secret: the fetch path is `.well-known/mtcrs/tick/{entry_hash}` with {entry_hash} computable by anyone holding the certificate, and the origin is low-entropy and, when the CA certificate SIA ({{discovery}}) is used, available to relying parties as well.
By default the design does not, and cannot, technically prevent a relying party from constructing the URL and fetching; it declines to standardize or advertise such a fetch as an affordance to relying parties.
A CA that wishes to remove this derivability entirely MAY use the optional per-certificate capability-token hardening in {{unguessable-urls}}, which makes the tick URL unguessable to a party holding only the certificate.
A relying-party fetch would gain nothing over the embedded tick -- the authenticating party already presents the current value -- while reintroducing the CA-visibility of relying-party activity (the CA learning which sites a relying party visits), the added latency, and the soft-fail behaviour that made client-driven OCSP {{RFC6960}} problematic.

The CA certificate SIA access method ({{discovery}}) exists to convey the base URL to authenticating-party tooling.
Relying parties possess the CA certificate but MUST NOT use its tick base URL to fetch tick status.

## Unauthenticated Proof Extensions

The RECOMMENDED trailing status_tick encoding ({{tick-trailing-field}}) appends a fixed-size, fully verified value and so adds no general "ignore if unknown" region.
If the base specification instead adopts the alternative proof_extensions encoding ({{mtcproof-extensibility}}), note that this field is not committed to the Merkle Tree and is covered by no signature: it is mutable and can carry data that relying parties ignore.
Hash chain revocation does not rely on its authenticity -- the tick is self-authenticating and its presence is mandated by the committed id-pe-hashChainAnchor extension.
{{proof-extensions-considerations}} discusses the general risks of this field (bloat, covert channels, and a strippable soft-fail for other mechanisms) and the constraints recommended for the base specification.

## Interaction with Base MTC Revocation

The hash chain mechanism complements rather than replaces the base MTC revoked ranges mechanism.
Revoked ranges provide a fallback for scenarios where the hash chain mechanism is insufficient:

- Compromise of the CA's hash chain seed storage
- Bulk revocation of many certificates simultaneously
- Relying parties that have not yet implemented hash chain verification

Relying parties that support both mechanisms SHOULD check both: a certificate is considered revoked if either mechanism indicates revocation.

## Client-Side Enforcement Latency and Session Resumption {#enforcement-latency}

A relying party checks the non-revocation proof ({{verification}}) only when it validates the certificate, which happens during a full TLS handshake.
Two common TLS behaviours mean this check does not recur for the life of a connection or a resumed session, so the effective client-side revocation latency is bounded not by revocation_period alone but by how long a client keeps or resumes a connection:

- **Established connections.** Once a full handshake completes, the certificate -- and hence the tick -- is not re-evaluated for the lifetime of that connection. A long-lived connection (HTTP keep-alive, HTTP/2, or HTTP/3) may continue to use a certificate that has since been revoked until the connection closes.

- **Session resumption.** A resumed TLS session carries no Certificate message: the server's authentication is derived from the original full handshake and is not re-validated, so no tick is presented and none is checked. A client may therefore resume without re-checking revocation for as long as its session tickets remain usable. TLS 1.3 caps a ticket's lifetime at seven days ({{RFC8446}}, Section 4.6.1), and implementations commonly use shorter, configurable limits, but within that window resumption bypasses tick verification.

- **Renegotiation.** TLS 1.3 removed renegotiation, and browsers have disabled or restricted TLS 1.2 renegotiation, so renegotiation cannot be relied upon to re-present a fresh tick. There is likewise no mechanism for a server to push an updated certificate or tick mid-connection.

The effective latency before a revocation takes effect at a given client is therefore approximately the maximum of revocation_period, the remaining lifetime of any established connection, and the client's session-resumption window.
A deployment that wants revocation to take effect within about one revocation_period SHOULD bound the session-ticket lifetime (and, where practical, the lifetime of long-lived connections) to a value near revocation_period, so that a fresh full handshake -- and thus a fresh tick -- is forced within that period.

This limitation is not specific to this mechanism.
Every handshake-time revocation mechanism (OCSP {{RFC6960}}, CRLite {{CRLite}}, CRLSets {{CRLSets}}) is likewise consulted only when the certificate is validated, and the base MTC short-lived-certificate model has the same property: a revoked-but-unexpired certificate is equally accepted on a resumed session.
Relative to passive expiry, this mechanism still improves matters, because every full handshake re-checks a per-period non-revocation proof rather than trusting a static notAfter.

## Clock Skew {#clock-skew}

Verification step 4 accepts a tick whose period is the verifier's expected_period, the immediately preceding period (expected_period - 1), or the immediately following period (expected_period + 1).
This tolerates a verifier clock that is behind or ahead of the authenticating party's by up to one full revocation_period in either direction, and also an authenticating party that is still serving the previous period's tick for caching or staggered refresh ({{load-distribution}}).

The two directions are not equivalent in cost.
Accepting the immediately following period -- what a verifier whose clock is behind will see -- costs nothing in revocation terms: that tick is a fresher non-revocation proof than the verifier expected, and a tick for a period the CA has not yet reached cannot be forged (preimage resistance; {{security-considerations}}).
Accepting the immediately preceding period -- a verifier clock that is ahead, or a deliberately stale tick -- accepts a non-revocation proof up to one revocation_period old, which is the intended one-period grace.

Deployments with known clock-skew or availability concerns MAY widen the window: accepting further preceding periods tolerates a tick-distribution outage ({{objections}}) at the cost of correspondingly delayed revocation enforcement, while accepting further following periods tolerates a verifier clock that runs further behind and carries no revocation cost.

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

The id-ad-mtcrsTicks access method is used as a Subject Information Access access method ({{RFC5280}}) in a Merkle Tree CA certificate (Section 5.5 of {{I-D.ietf-plants-merkle-tree-certs}}).
Its accessLocation is a uniformResourceIdentifier giving the CA's tick base URL ({{discovery}}).

    id-ad-mtcrsTicks OBJECT IDENTIFIER ::= { id-ad TBD }

## Well-Known URI

IANA is requested to register the following entry in the "Well-Known URIs" registry ({{RFC8615}}):

| Field | Value |
|-------|-------|
| URI Suffix | mtcrs |
| Change Controller | IETF |
| Reference | This document |
| Status | permanent |
| Related Information | Path prefix for the MTCRS tick distribution HTTP interface: `/.well-known/mtcrs/tick/{entry_hash}` ({{distribution}}) |

## ACME Order Object Fields

IANA is requested to register the following entries in the "ACME Order Object Fields" registry ({{RFC8555}}):

| Field Name  | Field Type | Configurable | Reference     |
|-------------|------------|--------------|---------------|
| tickBaseURL | string     | false        | This document |
| tickURL     | string     | false        | This document |

Both fields are set by the server in the order object; neither is configurable by the client in a newOrder request.
A CA uses tickBaseURL for the derivable tick URL scheme ({{acme-integration}}) and tickURL for the unguessable per-certificate URL scheme ({{unguessable-urls}}); the two are mutually exclusive for a given order.

## MTCProof Extension Type

The proof-extension encoding of the tick ({{tick-proof-extension}}) relies on an MTCProofExtensionType code point, hash_chain_tick(0), within a proof_extensions field that the base MTC specification does not currently define ({{mtcproof-extensibility}}).
This document does not create an MTCProofExtensionType registry.
If the base MTC specification {{I-D.ietf-plants-merkle-tree-certs}} adopts the proof_extensions mechanism, it -- not this document -- is expected to establish the corresponding IANA registry, following the allocation policy recommended in {{proof-extensions-considerations}}.
This document requests that, in that event, the value hash_chain_tick be allocated in that registry with a reference to this document.
When the RECOMMENDED trailing status_tick encoding ({{tick-trailing-field}}) is used instead, no such registry or code point is required.

--- back

# ASN.1 Module {#asn1-module}

This appendix provides an ASN.1 module for the structures this document defines, following the conventions of {{RFC5912}}.

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
      revocationPeriod  INTEGER (1..MAX) DEFAULT 3600,
      anchor            OCTET STRING }

    -- Tick distribution Subject Information Access method

    id-ad-mtcrsTicks OBJECT IDENTIFIER ::= { id-ad TBD }

    END

The id-mod-mtcrs-2026, id-pe-hashChainAnchor, and id-ad-mtcrsTicks arcs contain TBD values to be replaced with the OIDs assigned by IANA ({{iana-considerations}}).

# Hash Chain Input Encoding {#encoding}

The HashChainInput structure provides domain separation for hash chain computations:

    struct {
        uint8 label[7] = "MTCRS\n\0";
        TrustAnchorID issuer_id<1..2^8-1>;
        uint16 log_number;
        uint48 index;
        HashValue preimage;
    } HashChainInput;

label:
: A fixed ASCII string providing domain separation from other uses of the hash function in MTC, so that a chain value cannot be reinterpreted as, or collide with, another MTC hash computation (for example, a Merkle Tree leaf or node hash).
  The trailing "\n\0" follows the convention of the base MTC specification's label (`"subtree/v1\n\0"`); the NUL terminator keeps the MTC label space prefix-free, so no label can be a prefix of another.
  The label's length is not otherwise security-relevant, and this short value keeps a typical HashChainInput within a single hash compression block.

issuer_id:
: The CA's trust anchor ID.

log_number:
: The log number of the issuance log containing this entry.

index:
: The entry's index within the issuance log.

preimage:
: The previous hash chain value being hashed.

The issuer_id, log_number, and index fields together identify the log entry and act as a per-entry salt, placing each certificate's chain in a distinct hash domain.
This salting is not load-bearing for the core guarantee: each chain already starts from an independent, cryptographically random seed, and the anchor committed in the certificate ({{assertion-integration}}) binds each revealed value to that specific chain.
Its contribution is defense in depth.
It keeps chains distinct even if a seed-generation fault were to repeat a seed across entries, and it frustrates any amortized precomputation that would otherwise target the whole population of chains at once (the same rationale as salting).

The Hash function is the same hash function used by the Merkle Tree CA (SHA-256 for CAs using SHA-256).

# Test Vectors {#test-vectors}

This appendix gives a worked example that pins down the exact HashChainInput byte layout ({{encoding}}) and hashing order.
All values are hexadecimal, and the hash function is SHA-256 (HASH_SIZE = 32).

The example uses:

- issuer_id: TrustAnchorID 32473.1, whose binary representation is 81fd5901; as a <1..2^8-1> vector it encodes with its length prefix as 04 81fd5901.
- log_number = 1
- index = 42
- chain_length = 5
- seed h\[0\] = the 32 bytes 00 01 ... 1f (a fixed value for this example; a real CA uses a cryptographically random, secret seed)

The fixed fields of HashChainInput therefore encode as:

    label       4d544352530a00        ("MTCRS\n\0")
    issuer_id   0481fd5901
    log_number  0001
    index       00000000002a

Each step computes h\[i\] = SHA-256(HashChainInput(h\[i-1\])), where HashChainInput(preimage) is the concatenation label || issuer_id || log_number || index || preimage.
For example, HashChainInput(h\[0\]) is the following 52 bytes:

    4d544352530a000481fd5901000100000000002a000102030405060708090a0b
    0c0d0e0f101112131415161718191a1b1c1d1e1f

The resulting chain is:

    h[0]  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    h[1]  a99c801b389eed84c31eb04c970d2fbe63608bbd8911d54e63eb7f18adcf286a
    h[2]  8721e95cbd26d1f2789c859d89858ca1c37193f0772aa171da6f02b71acb51cd
    h[3]  4dab657fef30e247ed04565cbfc0ba1f7c977df06544563e9dc5a697c9d21ec4
    h[4]  b8c0f6b6aac2f65177c9c2481e50b1070cfd31a348f27f94d5318ecfea385aca
    h[5]  f855b7134602eee167305c1a0314ffbf435c8d1b2e49ee3e7b18cd445bdeb234

The anchor committed in the certificate is h\[chain_length\] = h\[5\].

For period t = 2, the CA reveals h\[chain_length - t\] = h\[3\].
The HashChainTick is { period = 2, value = h\[3\] }, which serializes (a 4-byte big-endian period followed by the 32-byte value; {{response-format}}) as the following 36 bytes:

    000000024dab657fef30e247ed04565cbfc0ba1f7c977df06544563e9dc5a697
    c9d21ec4

To verify, a relying party hashes tick.value forward tick.period (2) times ({{verification}}):

    v0 = h[3] = 4dab657f...c9d21ec4
    v1 = SHA-256(HashChainInput(v0)) = b8c0f6b6...ea385aca  (= h[4])
    v2 = SHA-256(HashChainInput(v1)) = f855b713...5bdeb234  (= h[5])

v2 equals the anchor h\[5\], so verification succeeds.

# Design Rationale {#rationale}

This section provides rationale for the choices made in this document.

## Why Hash Chains (Micali) Instead of Other Revocation Mechanisms

Hash chains {{MICALI}} were selected because they are the only known mechanism that simultaneously provides:

1. **Self-authentication:** The tick is verified against data already committed in the Merkle Tree (the anchor).
   No additional signatures, certificates, or trust relationships are needed.

2. **Zero CA signing load:** Each revocation period, the CA reveals a precomputed value.
   There is no per-certificate, per-period signing operation.
   This is critical for CAs with millions of active certificates.

3. **Mandatory enforcement:** Because the tick is structurally part of the certificate presentation, relying parties can hard-fail on its absence.
   This avoids the soft-fail problem that plagued OCSP.

4. **Minimal bandwidth:** 36 bytes per handshake (4-byte period + 32-byte hash value).

5. **Simple implementation:** The mechanism requires only a hash function and basic arithmetic.
   No new cryptographic primitives are introduced.

## Why One Hour (or One Day) Periods

A one-hour revocation_period provides a good balance:

- **Revocation latency:** A compromised key is unusable within at most two hours (current period + grace period).

- **Operational feasibility:** Authenticating parties must fetch a new tick once per hour.
  This is a trivial HTTP request for a 36-byte response.

- **Chain length:** For 47-day certificates, the chain length is 1,128.
  Verification requires at most 1,127 hash computations, which takes microseconds on modern hardware.

- **CA storage:** The CA must store one seed per active certificate.
  With 32 bytes per seed, 1 billion certificates require 32 GB.

A one-day period is also viable, reducing operational frequency at the cost of up to 48-hour revocation latency.
Deployments SHOULD choose the shortest period operationally feasible.

## CA-Side Storage and Computation Trade-off {#storage-tradeoff}

A CA has two largely independent implementation choices for each certificate's hash chain of length `chain_length` (denoted L below): how to produce each period's revealed value, and where the per-certificate seed comes from.
Both are CA-side only; the on-the-wire tick and the relying party's verification procedure ({{verification}}) are unchanged.

### Storing Versus Recomputing Chain Values {#chain-traversal}

Within a single chain, a CA does not have to choose between the two naive extremes:

- **Store the entire chain:** O(L) storage per certificate, but each revealed value is a free lookup.
  For L = 1128 (a 47-day lifetime with a one-hour period), this is roughly 35 KiB per certificate, or about 36 TB across 1 billion certificates.

- **Store only the seed:** O(1) storage per certificate, but recomputing the value revealed in period t costs up to L hash evaluations (L/2 on average).
  Over a certificate's lifetime this is O(L^2) hashing.

A CA MAY instead use **fractal hash-chain traversal** {{FRACTAL}} {{ALMOST-OPTIMAL}} to obtain a logarithmic middle ground.
The chain is revealed in reverse of the order in which it is computed (the CA computes `h[1..L]` forward from the secret seed `h[0]`, but reveals `h[L-1], h[L-2], ..., h[1]` over time), which is exactly the setting these algorithms address.
Instead of the whole chain or just the seed, the CA maintains a small set of precomputed helper values ("pebbles") parked at self-similar positions along the chain.
When the value for the current period is needed, a pebble is already there; between periods the CA spends a small fixed budget of hash evaluations advancing the more distant pebbles toward the positions where they will next be needed.
The scheduling guarantees:

    storage  ~ log2(L)      hash values per certificate
    work     ~ (1/2) log2(L) hash evaluations per revealed value

For L = 1128, this is approximately 10 to 11 stored values (~320 to 350 bytes) per certificate and about 5 hash evaluations per period.
Across 1 billion certificates that is roughly 340 GB of state and, if the traversal is advanced once per period and the resulting value served to all requests in that period, on the order of 10^6 hash evaluations per second in aggregate.
This dominates a simple square-root checkpoint scheme (which would need ~1.1 TB and up to ~34 hashes per value) on both axes, and turns the seed-only extreme's O(L^2) lifetime cost into O(L log L).

The pebbles are unrevealed chain values and therefore carry the same confidentiality requirement as the seed ({{security-considerations}}).

### Deriving Seeds from a Long-Term CA Secret {#derived-seeds}

The per-certificate seed itself can also be eliminated from storage.
Instead of generating and storing an independent random seed per certificate, a CA MAY derive each seed from a single long-term CA secret with a keyed key-derivation function -- for example `h[0] = HMAC-SHA256(ca_seed, label || issuer_id || log_number || index)`, or the equivalent with HKDF.
A raw `Hash(ca_seed || ...)` construction MUST NOT be used, as it invites length-extension and MAC-misuse; a proper PRF/KDF is required so that derived seeds are computationally indistinguishable from the independent random seeds of {{construction}}.
Any chain is then recomputable on demand from `ca_seed` and the (public) entry identity, giving O(1) secret storage for the entire CA and stateless, reconstructible issuance, with no change visible to verifiers.
The cost is concentration: compromise of `ca_seed` exposes every certificate's chain, past, present, and future, so it MUST be protected at least as strongly as the CA's issuance signing key ({{seed-confidentiality}}) -- though, being a single small key, it is better suited to HSM custody than a bulk per-certificate seed store.
To bound the blast radius, a CA SHOULD derive per-log or per-epoch sub-seeds (`log_seed = KDF(ca_seed, log_number)`, then `h[0] = KDF(log_seed, label || index)`), which can be retired as their logs expire; as with any seed compromise, rotation protects only certificates issued afterward, and already-committed anchors still require the revoked-ranges fallback ({{seed-confidentiality}}).
Rotation is by issuance epoch, not by tick period: a certificate's entire chain derives from the seed fixed at issuance, so per-log or per-epoch sub-seeds are the finest granularity at which a compromise can be bounded.

## Why Embed the Tick in the MTCProof

The MTCProof is the bundle of evidence a relying party checks to accept a certificate: the inclusion proof and cosignatures establish authenticity, and the tick completes it with non-revocation, so embedding the tick extends the certificate's proof of validity rather than attaching unrelated data.
It is embedded directly in the MTCProof (the certificate's signatureValue) rather than delivered via a separate channel because:

1. **Inseparable from acceptance:** The tick is part of the certificate presentation, not a separate signal.
   When the committed id-pe-hashChainAnchor extension is present, the amended Section 7.2 parse ({{tick-trailing-field}}) requires the MTCProof to carry the tick, so a relying party that implements this mechanism rejects the certificate if the tick is absent.
   The tick is not itself covered by a CA signature -- like the rest of the MTCProof it is mutable, which is precisely what lets it be refreshed each period -- so an active attacker can remove the bytes; what it cannot do is remove them and leave a certificate that still verifies.
   Stripping the tick therefore forces a hard failure rather than the silent soft-fail that let a stripped OCSP staple pass ({{ocsp-stapling-comparison}}): the guarantee is that revocation status cannot be dropped undetectably, not that the bytes are physically immovable.

2. **No new protocol machinery:** No TLS CertificateEntry extension or other signaling mechanism is needed.
   The tick travels inside the existing certificate structure, requiring no changes to TLS implementations beyond MTC support.

3. **Safe to update dynamically:** The MTCProof is not committed to the Merkle Tree — only the TBSCertificateLogEntry is.
   The authenticating party can freely replace the signatureValue each period without invalidating the inclusion proof or cosignatures.

4. **No additional round-trips:** The tick travels with the certificate in the same TLS message.
   No DNS lookups or side-channel fetches are needed by the relying party.

5. **Server must participate:** The authenticating party is already responsible for maintaining its MTC certificate and refreshing it before expiry.
   Adding a lightweight hourly tick refresh is an incremental burden, not a new class of operational requirement.

## Comparison with OCSP Stapling {#ocsp-stapling-comparison}

OCSP stapling delivers a CA-signed status response inside the TLS handshake, and is the closest existing analogue to this mechanism.
It has nonetheless failed to become an enforceable revocation channel, for reasons this mechanism is specifically designed to avoid.
The major browsers' migration away from live OCSP and stapling toward pushed revocation lists was itself a verdict on soft-fail; {{objections}} (Browsers Already Abandoned Handshake and Online Revocation) addresses how this mechanism differs.

### Why OCSP Stapling Is Not Enforceable

OCSP stapling ({{RFC6960}}, carried via the TLS status_request extension) is optional and strippable: the client requests it, and the server -- or a network attacker -- can omit the stapled response with no signal that one was expected.
A relying party therefore cannot distinguish a deliberately stripped response from a temporarily unavailable responder, so it must soft-fail (treat missing status as "not revoked") to avoid breaking legitimate connections.
Soft-fail, in turn, provides almost no protection against an active attacker, who can simply suppress the response.
This is a self-reinforcing loop: because enforcement is impossible, stapling yields little security benefit; because it yields little benefit, servers have weak incentive to deploy it; and because deployment is incomplete, relying parties can never move from soft-fail to hard-fail.

OCSP Must-Staple ({{RFC7633}}) was introduced to break this loop by letting a certificate commit to requiring a stapled response.
It saw little adoption: enabling it risks self-inflicted outages if the responder or the server's stapling path fails, and the ecosystem never reached the coverage that would let relying parties depend on it.
The stapled response remains a separate TLS signal with its own failure modes, layered on a CA-operated responder that must sign every response.

### Why This Mechanism Is Enforceable

The hash chain tick is not a separate, optional signal: it is carried inside the MTCProof, which is part of the certificate presentation itself ({{cert-format}}).
A relying party that parses the certificate necessarily encounters the tick; there is no request step to omit, and nothing a middlebox or misconfigured server can strip while leaving a valid certificate.
A relying party can therefore hard-fail on a missing or invalid tick from the outset -- precisely what stapling could never achieve.
In effect this mechanism provides the property Must-Staple aimed at, a certificate that cannot be presented without current status, but makes it un-strippable by construction rather than by a policy flag, and does so with no per-response CA signature.

### Why It Is More Readily Deployable

Several differences lower the deployment barrier relative to stapling:

- **No responder infrastructure and no per-response signatures.**
  The CA reveals a precomputed hash value per period; there is no OCSP responder fleet, responder certificate, or per-check signing operation.
  Ticks are static within a period, self-authenticating, and cacheable by any HTTP intermediary, so distribution is far more robust than a signing responder -- the very fragility that made Must-Staple risky to enable.

- **No TLS-stack changes.**
  The tick travels inside the existing certificate structure, so no status_request negotiation or CertificateStatus handling is required in TLS implementations beyond MTC support itself.
  Stapling requires status_request support on both ends.

- **A small, cacheable refresh instead of stapling machinery.**
  A server refreshes a 36-byte value once per period ({{distribution}}), with no cryptographic operations, rather than fetching, validating, and stapling CA-signed OCSP responses with their own validity windows.

- **Greenfield enforcement.**
  MTC is new, so there is no legacy soft-fail install base to accommodate.
  Within an MTC ecosystem, enforcement can be mandatory from day one (or made so by marking the anchor extension critical; see {{objections}}), avoiding the transition that stapling never completed.

The counterweight is that a tick, unlike a soft-failed OCSP response, is a hard dependency: a server that cannot refresh its tick within a period becomes unusable until it does.
{{objections}} discusses this availability dependency and its mitigations.

### Operational Simplicity and Resilience {#operational-resilience}

Beyond the deployment barrier, tick distribution is simpler to operate and more resilient than an OCSP responder.
The serving path holds no online signing key and no responder certificate: it returns precomputed values that are immutable within a period, so it is a static, cacheable, CDN-offloadable, plain-HTTP key-value service ({{distribution}}) with no per-request cryptography and nothing security-critical in the request path.
A compromised or overloaded tick service can only serve public precomputed values; it cannot mint a false non-revocation statement, unlike a responder whose signing key is a high-value online target.
Relying parties impose no load at all, because they never fetch ({{rp-no-fetch}}) -- removing the responder-in-the-hot-path that made online OCSP a latency, availability, and privacy problem.

Two qualifications apply.
First, the new cost is on the generation side: the CA must produce the current tick for every non-revoked certificate each period, a precompute workload ({{storage-tradeoff}}) rather than OCSP's sign-on-demand.
Second, the failure mode differs by design: an OCSP responder outage fails open (relying parties soft-fail and proceed), whereas a tick-distribution outage lasting longer than one period fails closed for the affected certificate -- bounded by the one-period buffer and mitigated by caching, multi-CA operation, and window-widening ({{objections}}).

# Alternatives Considered {#alternatives}

## DNS-Based Tick Distribution

An alternative to the HTTP-based tick distribution described in {{distribution}} is for the CA to publish current ticks via DNS records, which the authenticating party fetches and embeds in the MTCProof.
For example, a TXT or other record type at a well-known name derived from the CA, log number, and entry index.

Since the tick is embedded in the MTCProof regardless of how it was obtained, the relying party's verification procedure is unchanged.
The choice of distribution channel is purely between the CA and the authenticating party.

DNS-based distribution has some advantages over HTTP:

- **Caching infrastructure:** DNS's hierarchical caching architecture is well-suited to distributing small, frequently updated values.
  Recursive resolvers naturally cache and serve ticks without requiring the CA to operate CDN infrastructure.

However, DNS-based distribution also has limitations:

- **Record size constraints:** While a single tick (36 bytes) fits easily in a DNS record, scaling to millions of entries may require careful zone design.
  The CA would need one record per active certificate, which could result in very large zones.

- **Update propagation delay:** DNS TTLs and caching may delay propagation of new ticks.
  The CA SHOULD set TTLs no longer than revocation_period seconds, but cached stale records could cause authenticating parties to serve expired ticks briefly.

- **Operational complexity for the CA:** The CA must update DNS records for every non-revoked certificate each period.
  Depending on the DNS infrastructure, this may be more complex than serving an HTTP endpoint.

These limitations are largely addressable.
Rather than provisioning a static zone with one record per certificate, a CA can answer queries dynamically: a programmable authoritative server synthesizes the response for `{entry_hash}._tick.<zone>` on demand from the same chain state the HTTP interface uses ({{distribution}}), so no per-certificate records are stored and record count ceases to be a scaling concern; the namespace can also be sharded by entry_hash prefix across delegated sub-zones.
Staleness is bounded by the record TTL, which SHOULD be no longer than revocation_period; because a relying party already accepts a tick for the immediately preceding period ({{clock-skew}}), a briefly stale record remains acceptable, and the authenticating party's pre-installation check ({{verification}}) rejects an unexpectedly stale record and refetches.
For revocation, a cached record extends the window in which a revoked certificate remains usable by at most the TTL beyond the normal one-period grace, so a short TTL bounds it.
Under dynamic synthesis the per-period work is the same the HTTP interface performs, merely fronted by a DNS responder; and because ticks are self-authenticating, the delegated-distribution model ({{delegated-distribution}}) applies unchanged, with edge DNS nodes fed the per-period bundle answering authoritatively.

Deployments MAY use DNS-based distribution as an alternative or complement to HTTP-based distribution.
The choice does not affect interoperability, since the relying party only sees the tick in the MTCProof.

DNSSEC is not required for DNS-based tick distribution and SHOULD NOT be used.
Each tick is self-authenticating: the relying party verifies it by hashing it forward to the anchor already committed in the Merkle Tree.
An attacker who modifies a tick in transit cannot produce a value that passes this verification without inverting the hash function.
An attacker who suppresses a tick only prevents the authenticating party from obtaining a fresh tick, which is equivalent to a network-level denial of service against any distribution channel.
Adding DNSSEC would introduce unnecessary operational complexity (key management, signature generation for frequently changing records) and increase DNS response sizes, without improving the security of the revocation mechanism.

## AIA-Based Tick URL Discovery

Another alternative is to convey the tick distribution URL via a new Authority Information Access (AIA) access method in the certificate, following the established pattern used for OCSP responder URLs in {{RFC5280}}.

This approach was rejected because:

- **Inflates log entries:** AIA is part of the TBSCertificate, which is committed to the Merkle Tree.
  A ~50-80 byte URL in every log entry increases tree size and inclusion proof transmission costs, conflicting with MTC's goal of compactness.

- **Immutable once issued:** If the CA migrates its tick distribution infrastructure, all existing certificates still contain the old URL.
  Delivering the URL out of band ({{discovery}}) lets the CA migrate its tick infrastructure without certificate reissuance.

- **Only the authenticating party needs it, and only it should fetch:** Relying parties verify the embedded tick offline against the committed anchor and MUST NOT fetch ticks ({{rp-no-fetch}}).
  Putting a per-certificate URL in the certificate would not make fetching infeasible -- the URL is derivable regardless ({{rp-no-fetch}}) -- but placing it in a field relying parties routinely parse would standardize and encourage client-side tick fetching, reintroducing the OCSP-style privacy leak, latency, and soft-fail problems this mechanism avoids.

- **Redundant given existing CA relationship:** The authenticating party obtained the certificate from the CA (e.g., via ACME) and can receive the tick base URL through that same channel at zero per-certificate cost ({{discovery}}).

Out-of-band delivery of the base URL at provisioning ({{discovery}}) conveys it at zero per-certificate cost.
CAs MAY additionally publish the base URL in the CA certificate SIA ({{discovery}}) for a protocol-independent record.

## TLS Extension (Separate from Certificate)

Another alternative was carrying the hash chain tick in a TLS CertificateEntry extension or a separate TLS extension, rather than embedding it in the MTCProof.

This approach was rejected because:

- **Strippable:** A TLS extension can potentially be omitted by middleboxes or misconfigured servers, with the relying party unable to tell an omitted extension from one that was never sent, so it must soft-fail.
  Embedding the tick in the MTCProof does not make the bytes physically immovable -- they are covered by no signature -- but it makes the tick inseparable from the certificate's acceptance: when the committed anchor is present, an aware relying party rejects the certificate if the tick is missing ({{tick-trailing-field}}), so stripping forces a hard failure rather than a silent soft-fail.

- **The OCSP stapling lesson:** any mechanism carried in a separate, optional signalling channel is strippable and forces relying parties to soft-fail -- exactly the failure mode analysed in {{ocsp-stapling-comparison}}. Embedding the tick in the MTCProof avoids it.

- **Unnecessary complexity:** Defining a new TLS extension type requires IANA registration and implementation changes in TLS stacks.
  Embedding in the MTCProof requires no TLS-layer changes beyond MTC support itself.

## TLS status_request Extension

The TLS `status_request` extension (defined for OCSP stapling) uses a `CertificateStatusType` enum that is designed to be extensible beyond OCSP.
In TLS 1.2, a new status type could deliver the tick in a `CertificateStatus` message; in TLS 1.3, it could be carried per-certificate in the `CertificateEntry` extensions.

This approach was rejected for the same fundamental reason as a generic TLS extension: status_request is inherently opt-in -- the client requests it and the server can omit it with no hard failure -- so reusing it for a mandatory validity condition reintroduces the strippable soft-fail analysed in {{ocsp-stapling-comparison}}.

Additionally, `status_request` carries `OCSPResponse` semantics (a signed assertion from a responder); repurposing it for a bare hash value that is self-authenticating against the certificate would be a poor semantic fit.

## Shorter Certificate Lifetimes

The simplest revocation strategy is to make certificates short-lived enough that revocation is unnecessary.
For example, 1-day certificates have at most 24-hour exposure after compromise.
{{revocation-vs-expiry}} makes the general case that functional revocation is superior to passive expiry; this section catalogues the specific costs that nonetheless motivate longer lifetimes.

This approach has trade-offs that motivate longer lifetimes:

- **Issuance infrastructure load:** Shorter lifetimes require more frequent issuance.
  With millions of subscribers, daily certificate issuance produces proportionally larger logs and more frequent Merkle Tree constructions.

- **Availability risk:** An authenticating party that cannot reach the CA for one day loses its certificate entirely.
  Longer lifetimes provide more buffer against CA outages.

- **Trusted subtree state:** The number of landmark subtrees relying parties must maintain grows with shorter lifetimes and more frequent landmark allocation, at the cost of increased CA operational complexity.

- **Deployment constraints:** Root program policies such as {{CHROME-MTC}} have set maximum lifetimes (e.g., 47 days) based on ecosystem-wide operational feasibility assessments.
  Not all deployments can support arbitrarily short lifetimes.

Hash chain revocation provides the revocation latency benefits of short-lived certificates while retaining the operational advantages of longer lifetimes.

## CRLite / CRLSets / External Revocation

External revocation systems like {{CRLite}} and {{CRLSets}} compress revocation information into compact data structures pushed to relying parties.
The base MTC specification suggests using these as a complement.

This approach has limitations when used as the sole revocation mechanism for MTC:

- **Push latency:** These systems are updated on the order of hours to days, depending on the deployment.
  They do not provide a guaranteed upper bound on revocation latency.

- **Relying party coverage:** Not all relying parties subscribe to external revocation feeds.
  A mechanism that depends on the relying party having an up-to-date feed cannot provide universal revocation enforcement.

- **Separate trust path:** External revocation requires the relying party to trust the feed provider (e.g., the browser vendor) in addition to the CA.
  Hash chain revocation uses only the existing CA trust relationship.

These mechanisms remain valuable as defense-in-depth and as a fallback for the hash chain mechanism, as discussed in {{security-considerations}}.

## Per-Certificate Signatures (OCSP-like)

A CA could sign per-certificate non-revocation statements each period, analogous to OCSP responses.

This approach was rejected because:

- **Signing load:** A CA with a billion active certificates would need to produce a billion signatures per period.
  With post-quantum signature algorithms, this is computationally expensive.

- **Response size:** OCSP responses include a full signature (e.g., 3,309 bytes for ML-DSA-65).
  Hash chain ticks are 36 bytes.

- **Complexity:** OCSP requires its own responder infrastructure, certificate chain, and protocol.
  Hash chains require only a hash function.

# Anticipated Objections {#objections}

This section gives concise answers to objections likely to arise in the PLANTS community.
Where an objection touches a topic developed at length elsewhere, the answer summarizes and points to the fuller treatment (for example {{rationale}} or {{alternatives}}) rather than repeating it.

## "MTC Was Designed to Avoid Revocation Complexity"

The base MTC specification deliberately uses short-lived certificates to sidestep the complexity of traditional revocation mechanisms (CRLs, OCSP).
Adding a revocation layer may appear to reintroduce the very complexity MTC was designed to eliminate.

However, this mechanism is fundamentally simpler than traditional revocation.
It requires no new PKI infrastructure (no responder certificates, no separate signing keys), no new protocols (no OCSP request/response), and no per-check signatures.
The entire mechanism is a single hash function applied iteratively.
The complexity budget is closer to "one additional hash computation per handshake" than to "deploy and operate an OCSP responder fleet."
The alternative — living with up to 47-day exposure windows after key compromise — is a concrete security cost, not a simplification.

## "This Creates a New Availability Dependency"

Authenticating parties must fetch a fresh tick at least once per revocation_period.
If the CA's tick distribution infrastructure is unavailable for longer than one period, the certificate becomes unusable.
This may be seen as undermining MTC's advantage of decoupling certificate validity from real-time CA availability.

The revocation period is effectively the outage tolerance budget: a one-hour period means the authenticating party can tolerate at most one hour of tick distribution unavailability before its certificate becomes unusable.
Shorter revocation periods provide faster revocation enforcement but leave less margin for infrastructure failures.
Conversely, a one-day period provides 24 hours of buffer but delays revocation enforcement proportionally.
Deployments must choose a revocation period that balances their revocation latency requirements against their realistic availability expectations for tick distribution infrastructure.

This concern is real but bounded.
First, the dependency is on a trivial HTTP GET returning 36 bytes — far less fragile than ACME issuance or OCSP responder availability.
Second, the authenticating party has a full period (e.g., one hour) of buffer; brief outages are invisible to relying parties.
Third, CAs already operate high-availability infrastructure for issuance; tick distribution is a strictly simpler service (static content, cacheable, CDN-friendly), and is simpler to operate and more resilient than an OCSP responder ({{operational-resilience}}).
Additionally, deployments with availability concerns MAY widen the acceptance window to tolerate an outage longer than one period, trading revocation latency for resilience ({{clock-skew}}).

As a further mitigation, authenticating parties SHOULD obtain Merkle Tree Certificates from multiple independent CAs.
If one CA's tick distribution infrastructure becomes unavailable, the authenticating party can immediately switch to presenting a certificate from a different CA whose ticks remain current.
This multi-CA strategy eliminates the single point of failure: a tick distribution outage at one CA causes no service disruption as long as at least one other CA's infrastructure remains operational.
Since MTC certificates are lightweight to obtain and maintain, the incremental cost of holding certificates from two or three CAs is modest compared to the resilience benefit.

Finally, the alternative (no in-band revocation) means the ecosystem depends entirely on external revocation systems whose availability the CA does not control.

## "Just Use Shorter Certificate Lifetimes"

If revocation latency is the concern, reducing certificate lifetimes (e.g., to one day) achieves similar bounds without new mechanism complexity.

Shorter lifetimes and hash chain revocation are not mutually exclusive, but shorter lifetimes alone impose issuance-scaling and availability costs that hash chains avoid, and they cannot act on anything the CA learns mid-lifetime.
{{revocation-vs-expiry}} makes the general case for functional revocation over passive expiry, and the Shorter Certificate Lifetimes entry in {{alternatives}} catalogues the specific trade-offs.
Concretely, a 47-day certificate with hash chain revocation survives a multi-hour CA outage that would strand a one-day certificate, while still bounding post-compromise exposure to about two revocation periods.

## "CRLite/CRLSets Already Solve This Problem"

Browser vendors already push compressed revocation data to relying parties, so an in-band mechanism may appear redundant.

The two are complementary and serve different roles, as the CRLite / CRLSets / External Revocation entry in {{alternatives}} details.
The distinguishing point is reach and control: external revocation is vendor-controlled, best-effort, and reaches only relying parties that subscribe to the feed, whereas hash chain revocation is CA-operated, has a deterministic one-period latency bound, and is enforced by every relying party that validates the certificate -- including non-browser TLS clients and IoT devices with no external feed.
External revocation is defense-in-depth; hash chains provide a universal baseline.

## "Browsers Already Abandoned Handshake and Online Revocation"

The major browsers disabled live OCSP checking and never pushed OCSP stapling to ubiquity; instead they moved to client-side pushed revocation (Chrome's CRLSets {{CRLSets}}, Mozilla's OneCRL and CRLite {{CRLite}}, and Apple's on-device revocation data).
A handshake-carried status mechanism may look like a return to an approach the ecosystem already rejected.

The reasons for that move are specific, and this mechanism is designed around each of them:

- **Soft-fail.** Online OCSP had to treat an unreachable responder as "not revoked," so an active attacker could simply suppress the check, making enforcement impossible.
  The non-revocation proof here is structurally part of the certificate presentation and cannot be stripped while leaving a usable certificate, so relying parties hard-fail by construction ({{ocsp-stapling-comparison}}) -- the property OCSP Must-Staple ({{RFC7633}}) aimed at but never achieved at scale.
- **Relying-party privacy.** Client-driven OCSP leaked relying-party browsing to CAs. Relying parties here never contact the CA ({{rp-no-fetch}}); the only fetch is server-side.
- **Operator and responder fragility.** Must-Staple saw negligible adoption because a stapling-pipeline failure caused self-inflicted outages, and clients could not hard-fail until coverage was universal.
  Here the refresh is a trivial cacheable 36-byte GET with no signing, backed by a full period of buffer and multi-CA fallback ({{dos-withholding}}), and MTC is greenfield, so enforcement can be mandatory from the outset.

The pushed-list systems remain valuable and complementary -- comprehensive and fail-closed, but vendor-controlled and effective only for relying parties that ship the feed.
This mechanism provides a universal, CA-operated baseline enforced by every relying party, including non-browser TLS clients with no external feed (see the CRLite / CRLSets objection above).
Their success in fact validates the design choices adopted here: fail-closed enforcement with no handshake-time relying-party network dependency.

## "The Non-Critical Extension Means Split Enforcement"

Since id-pe-hashChainAnchor is marked non-critical, relying parties that have not implemented this mechanism will ignore it.
This creates a transition period where revocation via hash chains is enforced by some relying parties but not others.

This is an intentional deployment strategy, not a design flaw.
Marking the extension non-critical enables incremental deployment: CAs can begin issuing certificates with hash chain anchors today, and relying parties can adopt enforcement as implementations mature.
During the transition, the base MTC revoked-ranges mechanism and external revocation systems continue to provide coverage.
This is consistent with how many X.509 extensions are specified as non-critical (e.g., Authority Information Access, Authority Key Identifier, CRL Distribution Points per {{RFC5280}}): the extension carries useful information that aware implementations act on, while unaware implementations can safely proceed without it.

Furthermore, this document specifies SHOULD rather than MUST for the non-critical marking.
An MTC ecosystem in which all relying parties are known to support hash chain revocation MAY mark the extension critical, providing hard enforcement from day one within that ecosystem.
A root program policy could similarly mandate critical marking once adoption is deemed sufficient.

## "CA Seed Compromise Is Catastrophic"

If an attacker compromises the CA's stored hash chain seeds, they can compute valid ticks for revoked certificates, completely defeating the mechanism.

This is true, and is acknowledged in {{security-considerations}}.
However, the threat model is no worse than the status quo: a CA whose signing key is compromised can issue arbitrary certificates.
Seeds require confidentiality and integrity protection — for example, encrypted-at-rest storage with strong access controls and monitoring — but their operational profile differs from signing keys: a CA with millions of active certificates must store and retrieve seeds in bulk, which is better suited to encrypted database storage than to HSMs designed for a small number of high-value keys.
The recovery path for a detected compromise -- revoking the affected serial-number ranges via the base MTC mechanism -- is described in {{seed-confidentiality}} and {{interaction-with-base-mtc-revocation}}.

## "Modifying MTCProof Breaks Existing Implementations"

Adding a status_tick field to MTCProof requires changes to every MTC implementation.
The base MTC specification may not have anticipated this kind of extension.

This objection is well-founded.
The addition is conceptually natural -- the tick is not foreign data but the non-revocation component of the MTCProof ({{cert-format}}), so the amendment extends the proof's meaning rather than repurposing the structure -- but it is a structural change that the base specification must accommodate.
Section 7.2 of {{I-D.ietf-plants-merkle-tree-certs}} explicitly requires relying parties to reject an MTCProof if the signatureValue contains "extra data after the MTCProof."
The current MTCProof structure has no extensibility mechanism: it is a fixed sequence of fields with no trailing extensions block or version indicator.

Consequently, appending a status_tick to the MTCProof will cause any existing MTC implementation to reject the certificate — regardless of whether the X.509 extension is marked critical or non-critical.
An unaware relying party will ignore the non-critical id-pe-hashChainAnchor extension, proceed to parse the MTCProof, find 36 unexpected trailing bytes, and fail verification.

This means that, in practice, deploying this mechanism requires one of the following:

1. **Amendment to the base MTC specification:** The MTCProof structure is amended so that conforming parsers accept the tick -- either by appending the fixed status_tick field ({{tick-trailing-field}}) or by adding the general proof_extensions field (see {{mtcproof-extensibility}}).
   This is the preferred approach and is proposed by this document.

2. **Critical extension only:** The id-pe-hashChainAnchor extension is marked critical, so unaware implementations reject at the X.509 extension stage (before reaching MTCProof parsing).
   This sacrifices incremental deployment.

3. **Concurrent deployment:** Since MTC is not yet deployed at scale, both the base spec and this extension can be implemented together before the ecosystem ossifies.
   Early implementations can adopt the extended MTCProof structure from the start.

Both encodings this document describes take option 1 ({{cert-format}}): each amends the base MTC specification so that conforming parsers accept the tick, the RECOMMENDED trailing status_tick field being the minimal such amendment ({{tick-trailing-field}}).
Options 2 and 3 remain available as transition strategies for an ecosystem that deploys before the chosen amendment is widely implemented.

## "Hourly Tick Refresh Adds Operational Burden to Servers"

Authenticating parties already perform periodic certificate management: renewing certificates before expiry (recommended at 75% of lifetime, per Section 10.4 of {{I-D.ietf-plants-merkle-tree-certs}}) and optionally fetching landmark-relative certificates as new landmarks are allocated.
Adding an hourly tick refresh introduces a new operational loop with a tighter cadence than certificate renewal and — unlike the landmark-relative fetch, which is optional and best-effort — a hard deadline: if the tick is not refreshed in a timely manner, the certificate becomes unusable.

The refresh is a single HTTP GET returning 36 bytes, with no cryptographic operations required on the authenticating party's side.
This is orders of magnitude simpler than ACME certificate renewal (which involves key generation, CSR construction, challenge completion, and certificate installation).
The authenticating party can implement tick refresh as a lightweight background process with retry logic and local caching.
If the period is set to one day instead of one hour, the operational cadence matches what servers already do for DNS record TTL refreshes.

## "This Introduces a Covert Denial-of-Service Vector"

A CA can selectively withhold ticks from a specific subscriber, effectively revoking their certificate without any auditable signal.
This weaponizes the revocation mechanism as a censorship tool.

This threat is real but neither novel nor unmitigated: selective tick withholding is no more powerful than a CA's existing ability to refuse issuance or renewal, and it is detectable, externally observable (CT-style auditing), and disciplined by market pressure and CA switching.
It is addressed in {{dos-withholding}}.

## "Verification Cost Grows Linearly with Certificate Age"

A relying party verifying a tick near the end of a 47-day certificate's lifetime must compute up to 1,127 hashes.
This linear cost may be unacceptable for constrained devices.

On modern hardware, 1,127 SHA-256 operations take approximately 10-20 microseconds — negligible compared to the TLS handshake's asymmetric cryptography (ECDHE key exchange, signature verification).
Even on constrained IoT devices, SHA-256 is typically hardware-accelerated and the computation completes in under a millisecond.
For comparison, verifying a single Ed25519 signature costs roughly the same as hundreds of SHA-256 operations.
If the linear cost is nonetheless a concern for a specific deployment, choosing a shorter certificate lifetime (reducing chain_length) or a longer revocation_period (also reducing chain_length) provides a direct mitigation.

# Proposed MTCProof Extensibility {#mtcproof-extensibility}

The RECOMMENDED way to carry the tick is the fixed trailing status_tick field ({{tick-trailing-field}}), which needs no general extensibility mechanism.
This section describes an alternative: a general, reusable proof-level extensions field that the base MTC specification {{I-D.ietf-plants-merkle-tree-certs}} MAY adopt if it wants future mechanisms (beyond hash chain revocation) to attach data to the certificate presentation without a further structural change each time.
It is not required for hash chain revocation alone, and it carries the abuse surface discussed in {{proof-extensions-considerations}}.

## Motivation

The current MTCProof is a fixed sequence of fields with no extensibility point, and Section 7.2 of {{I-D.ietf-plants-merkle-tree-certs}} requires relying parties to reject any data trailing it, so no field can be appended without amending the base specification ({{tick-trailing-field}}):

    struct {
        MerkleTreeCertEntryExtension extensions<0..2^16-1>;
        uint48 start;
        uint48 end;
        HashValue inclusion_proof<0..2^16-1>;
        MTCSignature signatures<0..2^16-1>;
    } MTCProof;

The existing `extensions` field carries the log entry's MerkleTreeCertEntryExtension values, which are committed to the Merkle Tree and so cannot carry dynamic, per-period data like hash chain ticks: the inclusion proof would fail.

A proof-level extensions field -- not committed to the tree and freely updatable by the authenticating party -- would let the MTCProof carry revocation ticks and other future self-authenticating proof-level values without a new version of the base specification for each.

## Proposed Amendment

This document proposes updating {{I-D.ietf-plants-merkle-tree-certs}} with the following extended MTCProof structure:

    enum { hash_chain_tick(0), (2^16-1) } MTCProofExtensionType;

    struct {
        MTCProofExtensionType extension_type;
        opaque extension_data<0..2^16-1>;
    } MTCProofExtension;

    struct {
        MerkleTreeCertEntryExtension entry_extensions<0..2^16-1>;
        uint48 start;
        uint48 end;
        HashValue inclusion_proof<0..2^16-1>;
        MTCSignature signatures<0..2^16-1>;
        MTCProofExtension proof_extensions<0..2^16-1>;
    } MTCProof;

The `proof_extensions` field is a variable-length list with a 2-byte length prefix.
When empty, it encodes as two zero bytes (0x0000), adding minimal overhead to certificates that do not use any proof extensions.

The existing `extensions` field is renamed to `entry_extensions` to distinguish it from the new `proof_extensions` field.
Both are variable-length lists of tag-length-value structures, but they serve different roles: `entry_extensions` carries the log entry's MerkleTreeCertEntryExtension values (committed to the Merkle Tree), while `proof_extensions` carries proof-level data that can be freely updated without affecting the inclusion proof.

Relying parties MUST ignore unrecognized proof extension types.

The "extra data" check in Section 7.2 of {{I-D.ietf-plants-merkle-tree-certs}} would be amended to account for the trailing `proof_extensions` field.

## Hash Chain Tick as a Proof Extension

With this extensibility mechanism, the hash chain tick is carried as a proof extension rather than a bare trailing field:

    struct {
        uint32 period;
        HashValue value;
    } HashChainTick;

The HashChainTick is encoded as an MTCProofExtension with `extension_type` set to `hash_chain_tick(0)` and `extension_data` containing the serialized HashChainTick (4 + HASH_SIZE bytes).

## Backward Compatibility

Because the `proof_extensions` field uses a length-prefixed encoding, an implementation that supports the extended structure but does not recognize a particular extension type can skip over it by consuming the declared length.
Implementations that predate the amendment will reject the certificate at the MTCProof parsing stage (due to trailing bytes), which is acceptable: such implementations would also not recognize the id-pe-hashChainAnchor extension's semantics, so they cannot verify hash chain revocation regardless.

For the transition period, ecosystems have two options:

- **Mark the extension critical:** Unaware implementations reject at the X.509 extension stage, producing a clear error rather than an opaque parse failure.

- **Deploy the base spec amendment first:** Once the proof_extensions field is adopted into the base MTC specification, all conforming implementations will parse it (ignoring unknown types), enabling incremental deployment of hash chain revocation with a non-critical X.509 extension.

## Considerations for the proof_extensions Field {#proof-extensions-considerations}

The `proof_extensions` field is, by design, an unauthenticated and freely mutable region: it is not committed to the Merkle Tree, no cosignature covers the MTCProof, and relying parties ignore unrecognized types.
These properties are what let the hash chain tick be updated each period, but as a general-purpose extension point they also let an authenticating party, or any intermediary that relays the certificate, add, alter, or strip proof extensions undetectably, and insert arbitrary data that relying parties silently ignore ("stuffing").
This does not affect hash chain revocation itself -- the tick is self-authenticating and its presence is mandated by the id-pe-hashChainAnchor extension, which is committed to the tree, so stuffed or stripped data can neither forge nor suppress a tick.
But if the base MTC specification adopts `proof_extensions` as a general mechanism, the following constraints SHOULD apply so that the field is not abused or misused:

Bounded size and count:
: `proof_extensions` is transmitted in every handshake, so an unbounded ignored field undercuts the compactness that motivates MTC and creates a bloat and denial-of-service surface.
  The base specification SHOULD set a small maximum total size and extension count, well below the 2^16-1 the length prefix permits, and relying parties MAY reject certificates that exceed it.

Strict, canonical encoding:
: Proof extensions SHOULD appear in ascending order by `extension_type` with no duplicate types, and parsers SHOULD require the declared lengths to consume the field exactly, with no trailing bytes.
  This mirrors the ordering discipline the base specification already applies to cosignatures and limits ambiguity and abuse through many or malformed extensions.

Registration:
: `MTCProofExtensionType` values SHOULD be administered by an IANA registry with a defined allocation policy and a delimited private-use range, rather than left as an open channel.

Security-relevant extensions must be anchored:
: Because unrecognized or absent proof extensions are ignored, any future proof extension carrying security-relevant data MUST make its presence mandatory and self-authenticating through an element committed to the Merkle Tree, as hash chain revocation does with the id-pe-hashChainAnchor extension ({{assertion-integration}}).
  Otherwise "ignore if unknown" becomes a strippable soft-fail -- exactly the failure mode described in {{ocsp-stapling-comparison}}.

No transparency:
: Unlike `entry_extensions`, `proof_extensions` are neither logged nor committed to the tree, so monitors never observe them.
  Mechanisms that require transparency MUST use `entry_extensions` instead; `proof_extensions` MUST NOT be treated as a transparent or auditable channel.

Identity:
: `proof_extensions` widen the malleability of the signatureValue already noted in Section 12.6 of {{I-D.ietf-plants-merkle-tree-certs}}.
  Applications that derive a unique identifier from a certificate MUST derive it from the TBSCertificate, never from the MTCProof.

# Acknowledgments
{:numbered="false"}

The hash chain revocation concept is based on Silvio Micali's foundational work on efficient certificate revocation {{MICALI}}.
The name "MTCRS" is a nod to Micali's Certificate Revocation System (CRS); and coincidentally, "RS" also happens to be the initials of the author of this document.

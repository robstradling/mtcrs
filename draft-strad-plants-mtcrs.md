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
  RFC8174:
  RFC8446:
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
  RFC6960:
  RFC6962:
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
Periodically, the CA reveals hash chain values that serve as proof of non-revocation.
The authenticating party embeds the current hash chain value (a "tick") in the certificate's MTCProof, enabling the relying party to cryptographically verify that the certificate has not been revoked, with granularity as fine as one hour.

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

This approach achieves the following properties:

- **Timely revocation:** Revocation takes effect within one period (e.g., one hour), regardless of when the relying party last updated its trusted subtrees.

- **No per-check signatures:** Unlike OCSP {{RFC6960}}, verification requires only hash computations, not signature verification.
  The CA incurs no signing load for revocation status.

- **Mandatory enforcement:** The hash chain value is a required component of the certificate presentation.
  Unlike OCSP stapling, the mechanism cannot be silently omitted by the authenticating party.

- **Self-authenticating:** The hash chain value is verified against the anchor already committed in the Merkle Tree.
  No new trust relationships or authenticated channels are needed.

- **Minimal overhead:** A single hash value (32 bytes for SHA-256) is added to the certificate's MTCProof.

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

# Hash Chain Construction {#construction}

## Parameters

The hash chain mechanism introduces the following additional parameter to the Merkle Tree CA configuration:

revocation_period:
: A duration, in seconds, that determines the granularity of revocation.
  This MUST evenly divide the CA's certificate lifetime.
  The number of periods in a certificate's lifetime is: `chain_length = lifetime / revocation_period`.

## Chain Generation

At certificate issuance time, for each log entry, the CA generates a hash chain as follows:

1. Generate a cryptographically random seed of HASH_SIZE bytes (32 bytes for SHA-256).

2. Compute the hash chain of length chain_length + 1:

       h[0] = seed
       h[i] = Hash(HashChainInput(h[i-1], i))  for i = 1, ..., chain_length

   Where HashChainInput is defined in {{encoding}}.

3. The anchor (target) is `h[chain_length]`, the final value in the chain.

The anchor is included in the certificate as an X.509 extension (see {{assertion-integration}}).

## Period Numbering

Periods are numbered starting from 0.
Period 0 begins at the certificate's issuance time and each subsequent period begins revocation_period seconds later.
The period number at any given time t is:

    period = floor((t - issuance_time) / revocation_period)

## Revealing Values

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

The domain separation in HashChainInput ({{encoding}}) prevents values from being confused with other protocol elements or with hash chain values at different positions.

## Rationale for Using the Target as the Period 0 Tick {#period-zero-rationale}

Revealing the anchor `h[chain_length]` as the period 0 tick means the mechanism does not enforce revocation during period 0.
The earliest period for which the CA can withhold a secret value is period 1, and, because a relying party accepts the tick for the current or the immediately preceding period ({{verification}}), the public anchor remains acceptable throughout period 1.
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

# Integration with MTC Log Entries {#assertion-integration}

## Hash Chain Anchor Extension

This document defines a new X.509 certificate extension for carrying the hash chain anchor.
This extension is included in the TBSCertificateLogEntry's extensions field, and thus appears in the TBSCertificate of the resulting Merkle Tree Certificate.

    id-pe-hashChainAnchor OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) dod(6) internet(1)
        security(5) mechanisms(5) pkix(7) pe(1) TBD }

The extension value contains the DER encoding of the following ASN.1 structure:

    HashChainAnchorInfo ::= SEQUENCE {
        revocationPeriod  INTEGER,
        anchor            OCTET STRING
    }

revocationPeriod:
: The revocation period in seconds.
  MUST match the CA's configured revocation_period.

anchor:
: The hash chain anchor value `h[chain_length]` (HASH_SIZE bytes).

The id-pe-hashChainAnchor extension SHOULD be marked non-critical, so that relying parties that do not implement this mechanism can still process the certificate.
However, relying parties that do implement this mechanism MUST enforce hash chain verification as described in {{verification}} when the extension is present.
An MTC ecosystem in which all relying parties are expected to support hash chain revocation MAY mark the extension critical, causing implementations that do not recognize it to reject the certificate.

The extension MUST appear at most once in a certificate.

# Certificate Presentation {#cert-format}

## Hash Chain Tick

When a hash chain anchor extension is present in the certificate, the authenticating party MUST include a hash chain tick in the MTCProof structure (carried in the certificate's signatureValue).
This document extends the MTCProof with a status_tick field:

    struct {
        MerkleTreeCertEntryExtension extensions<0..2^16-1>;
        uint48 start;
        uint48 end;
        HashValue inclusion_proof<0..2^16-1>;
        MTCSignature signatures<0..2^16-1>;
        HashChainTick status_tick;
    } MTCProof;

    struct {
        uint32 period;
        opaque value[HASH_SIZE];
    } HashChainTick;

period:
: The period number for which this tick is valid.

value:
: The hash chain value `h[chain_length - period]`.

The status_tick field MUST be present in the MTCProof whenever the certificate's TBSCertificate contains the id-pe-hashChainAnchor extension.

Since the MTCProof is not committed to the Merkle Tree (only the TBSCertificateLogEntry is hashed into the tree), the status_tick can be updated each period without affecting the inclusion proof or cosignatures.
The authenticating party reconstructs or replaces the signatureValue with a fresh tick while reusing the same inclusion proof and signatures.

The authenticating party MUST include a HashChainTick with a period value that is current at the time of the TLS handshake.
A relying party SHOULD accept ticks for the current period or the immediately preceding period, to allow for clock skew and caching.

## Use in TLS {#tls-use}

No new TLS extension type is required.
When the authenticating party presents a Merkle Tree Certificate, the hash chain tick is carried within the certificate's signatureValue as part of the MTCProof, which is already transmitted in the CertificateEntry.

The presence of id-pe-hashChainAnchor in the TBSCertificate signals to the relying party that the MTCProof contains a status_tick field.
If the field is absent, malformed, or fails verification, the relying party MUST reject the certificate.

# Verification {#verification}

When a relying party receives a Merkle Tree Certificate with the id-pe-hashChainAnchor extension, it performs the following steps in addition to the base MTC verification procedure:

1. Extract the HashChainAnchorInfo from the certificate's id-pe-hashChainAnchor extension.
   If not present, skip hash chain verification (the certificate does not use this mechanism).

2. Extract the HashChainTick from the status_tick field of the MTCProof (in the certificate's signatureValue).
   If the id-pe-hashChainAnchor extension is present but the MTCProof does not contain a status_tick, reject the certificate with a bad_certificate error.

3. Compute the expected period from the current time:

       expected_period = floor((current_time - issuance_time) / revocation_period)

4. Check that `tick.period` is equal to expected_period or expected_period - 1.
   If not, reject the certificate with a certificate_expired error.

5. Starting from `tick.value`, iteratively hash `tick.period` times:

       v = tick.value
       for i = chain_length - tick.period + 1 to chain_length:
           v = Hash(HashChainInput(v, i))

6. Compare the result with anchor from the HashChainAnchorInfo.
   If they do not match, reject the certificate with a bad_certificate error.

If all steps succeed, the hash chain verification passes, confirming that the CA has not revoked this certificate as of the indicated period.

# Tick Distribution {#distribution}

The CA MUST provide a mechanism for authenticating parties to obtain current hash chain ticks.
This document defines an HTTP interface for this purpose.

## HTTP Interface

The CA (or a mirror) exposes the following endpoint:

    GET {base_url}/.well-known/mtcrs/tick/{entry_hash}

where {entry_hash} is the lowercase hex-encoded SHA-256 hash of the certificate's TBSCertificateLogEntry, and {base_url} is derived from the CA's issuer_id.
Specifically, the canonical tick distribution URL for a CA is constructed by interpreting the CA's TrustAnchorID as a DNS name and prepending either `http://` or `https://`:

    base_url = ( "http://" | "https://" ) || issuer_id

Because each tick is self-authenticating (the relying party verifies it by hashing it forward to the anchor committed in the Merkle Tree), the tick fetch does not require transport-layer integrity, and because the tick value is public, it does not require transport-layer confidentiality of the response body.
CAs MAY therefore serve ticks over plain HTTP, which eliminates TLS handshake overhead and permits caching by any HTTP intermediary.
An authenticating party deriving the URL from the issuer_id SHOULD use `http://` by default.
The one property plain HTTP does not provide is confidentiality of the request itself: an on-path observer can see which {entry_hash} is being requested.
Deployments that consider this metadata sensitive SHOULD use `https://` instead.

To ensure interoperability with authenticating parties that derive either scheme, a CA that relies on the issuer_id-derived default (i.e., that does not advertise an alternative URL per {{acme-integration}}) MUST serve ticks at the `.well-known` path over both `http://` and `https://` on the issuer_id-derived origin, returning identical responses on each.

The authenticating party computes {entry_hash} from the TBSCertificateLogEntry it already possesses (the same structure whose hash is committed as the leaf of the Merkle Tree).
No additional metadata from the CA is required.

For example, a CA with issuer_id "ca.example.com" would expose ticks at:

    http://ca.example.com/.well-known/mtcrs/tick/a1b2c3...f0
    https://ca.example.com/.well-known/mtcrs/tick/a1b2c3...f0

CAs MAY advertise alternative tick distribution URLs (e.g., CDN mirrors) via out-of-band configuration, but the `.well-known` path under the issuer_id-derived origin serves as the default discovery mechanism.

## ACME Integration {#acme-integration}

When the CA issues certificates via ACME, it SHOULD include the tick distribution URL in the ACME order object as a new field:

    "tickDistributionURL": "https://cdn.ca.example.com/.well-known/mtcrs/tick/a1b2c3...f0"

The `tickDistributionURL` field contains the full URL from which the authenticating party fetches its current HashChainTick.
If present, the authenticating party MUST use this URL instead of deriving one from the issuer_id.

This mechanism allows the CA to direct authenticating parties to CDN endpoints, regional mirrors, or infrastructure that does not match the `.well-known` derivation, without adding bytes to the certificate or log entry.

If the `tickDistributionURL` field is absent from the ACME order, the authenticating party derives the tick URL from the issuer_id as described above.

CAs using issuance protocols other than ACME SHOULD provide an equivalent mechanism for communicating the tick distribution URL during certificate provisioning.

## Response Format {#response-format}

The response body is the serialized HashChainTick structure: a 4-byte big-endian period followed by HASH_SIZE bytes of value (36 bytes total for SHA-256).
The response Content-Type MUST be `application/octet-stream`.

A successful response MUST use HTTP status code 200.
If the certificate has been revoked (no tick will be issued), the CA MUST respond with HTTP status code 404.

The CA SHOULD set HTTP cache headers with a max-age no longer than revocation_period seconds.
For example:

    Cache-Control: public, max-age=3600

## Operational Model

The authenticating party periodically fetches its current tick from the CA:

1. At least once per revocation_period, the authenticating party fetches its updated HashChainTick.

2. The authenticating party updates the status_tick field in its certificate's MTCProof (signatureValue) with the newly fetched value.
   The inclusion proof and cosignatures remain unchanged.

3. During TLS handshakes, the authenticating party presents the certificate with the current status_tick.

If the authenticating party is unable to obtain a fresh tick (e.g., due to CA unavailability), it continues to serve the most recent tick until that tick's period expires.
After expiry, the certificate becomes unusable until a fresh tick is obtained or a new certificate is provisioned.

At large deployment scale, tick distribution is dominated by aggregate request volume rather than per-request cost.
A CA serving 10^9 active certificates with a one-hour period sees on the order of 10^5 to 10^6 tick requests per second, and this load tends to concentrate at period boundaries if authenticating parties refresh in lockstep.
At this scale, edge caching (each tick is immutable within its period and cacheable for up to revocation_period seconds) and spreading of client refresh timing are required, not merely recommended, to avoid a thundering-herd load on the origin.
{{load-distribution}} describes recommended techniques.

## Distributing Tick Requests {#load-distribution}

A relying party accepts a tick for either the current period or the immediately preceding period ({{verification}}).
An authenticating party therefore has up to one full revocation_period of slack in which to fetch each new tick and need not fetch at the period boundary.
Two complementary mechanisms exploit this slack to prevent a period-boundary thundering herd.

### Client-Side: Deterministic Per-Entry Offset

Rather than fetching at the start of each period, an authenticating party SHOULD fetch at a fixed offset into the period derived deterministically from its own entry_hash:

    offset = INT32(entry_hash[0..3]) mod revocation_period

where entry_hash is the binary (pre-hex-encoding) SHA-256 hash of the TBSCertificateLogEntry and INT32 interprets its first four bytes as a big-endian unsigned integer.
The authenticating party fetches the current period's tick at (period_start + offset), where period_start is the start time of that period.
During the first offset seconds of the period it continues to serve the preceding period's tick, which remains valid under the grace window, so any offset less than revocation_period introduces no verification risk.

Because entry hashes are uniformly distributed, deriving the offset this way spreads fetches uniformly across the period with no coordination, shared state, or central scheduler, and the offset is stable from period to period, which aids caching and diagnosis.
This is preferable to independent random jitter, which can still cluster and which varies each period.

### Server-Side: Cache Freshness and Retry-After

The CA (or an edge cache) SHOULD serve each tick with a Cache-Control max-age no longer than revocation_period seconds ({{response-format}}), so that a caching layer collapses many client requests for the same entry into a single origin fetch per period.
A CA MAY additionally apply a small per-response jitter to max-age so that cache entries for different entries do not all expire simultaneously.

Under transient overload, the CA or edge MAY respond with HTTP status code 429 (Too Many Requests) or 503 (Service Unavailable) together with a Retry-After header indicating when the authenticating party should retry.
To avoid a synchronized second wave, the CA SHOULD randomize Retry-After values across clients rather than returning a single fixed value.
Because the authenticating party retains its previously fetched tick, which remains valid until the end of the current period, backing off in response to Retry-After does not interrupt service, provided a fresh tick is obtained before the previous one expires.

# Security Considerations

## Hash Function Requirements

The security of this mechanism depends on the preimage resistance of the hash function used.
SHA-256 {{SHS}} provides 256 bits of preimage resistance, which is sufficient for all foreseeable certificate lifetimes.
With a one-hour revocation_period and a 47-day lifetime, the chain length is 1,128, which does not meaningfully degrade the security margin.

## Seed Confidentiality

The CA MUST keep the hash chain seed (h\[0\]) and all not-yet-revealed chain values confidential.
Compromise of these values would allow an attacker to produce future ticks, defeating revocation.

If the CA's seed storage is compromised, the CA MUST revoke all affected certificates via the base MTC revocation mechanism (revoked ranges of serial numbers) as a fallback.

## Denial of Service via Tick Withholding

A compromised or malicious CA could withhold ticks from a legitimate authenticating party, effectively denying service.
This is analogous to a CA refusing to issue OCSP responses and is mitigated by the same market forces: an authenticating party that cannot obtain ticks will switch to another CA.

Additionally, since ticks are small (36 bytes), they can be efficiently distributed via CDN, reducing the attack surface for tick withholding.

## Interaction with Base MTC Revocation

The hash chain mechanism complements rather than replaces the base MTC revoked ranges mechanism.
Revoked ranges provide a fallback for scenarios where the hash chain mechanism is insufficient:

- Compromise of the CA's hash chain seed storage
- Bulk revocation of many certificates simultaneously
- Relying parties that have not yet implemented hash chain verification

Relying parties that support both mechanisms SHOULD check both: a certificate is considered revoked if either mechanism indicates revocation.

## Clock Skew

The grace period of accepting the current or immediately preceding period's tick ({{verification}}, step 4) provides tolerance for clock skew of up to one full revocation_period.
Deployments with known clock skew issues MAY extend this to two preceding periods at the cost of slightly delayed revocation enforcement.

# IANA Considerations

## Certificate Extension

IANA is requested to register the following entry in the "SMI Security for PKIX Certificate Extension" registry:

| Decimal | Description          | Reference     |
|---------|----------------------|---------------|
| TBD     | id-pe-hashChainAnchor | This document |

--- back

# Hash Chain Input Encoding {#encoding}

The HashChainInput structure provides domain separation for hash chain computations:

    struct {
        uint8 label[24] = "MTC HashChain Revocation";
        TrustAnchorID issuer_id<1..2^8-1>;
        uint16 log_number;
        uint48 index;
        uint32 position;
        opaque preimage[HASH_SIZE];
    } HashChainInput;

label:
: A fixed ASCII string providing domain separation from other uses of the hash function in MTC.

issuer_id:
: The CA's trust anchor ID.
  Binds the chain to a specific CA.

log_number:
: The log number of the issuance log containing this entry.
  Binds the chain to a specific log.

index:
: The entry's index within the issuance log.
  Binds the chain to a specific entry.

position:
: The position in the chain (1 to chain_length).
  Prevents values at different positions from being interchangeable.

preimage:
: The previous hash chain value being hashed.

The Hash function is the same hash function used by the Merkle Tree CA (SHA-256 for CAs using SHA-256).

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
  Verification requires at most 1,128 hash computations, which takes microseconds on modern hardware.

- **CA storage:** The CA must store one seed per active certificate.
  With 32 bytes per seed, 1 billion certificates require 32 GB.

A one-day period is also viable, reducing operational frequency at the cost of up to 48-hour revocation latency.
Deployments SHOULD choose the shortest period operationally feasible.

## CA-Side Storage and Computation Trade-off {#storage-tradeoff}

A CA does not have to choose between the two naive extremes for managing each certificate's hash chain of length `chain_length` (denoted L below):

- **Store the entire chain:** O(L) storage per certificate, but each revealed value is a free lookup.
  For L = 2160 (a 90-day lifetime with a one-hour period), this is roughly 67.5 KiB per certificate, or about 69 TB across 1 billion certificates.

- **Store only the seed:** O(1) storage per certificate, but recomputing the value revealed in period t costs up to L hash evaluations (L/2 on average).
  Over a certificate's lifetime this is O(L^2) hashing.

A CA MAY instead use **fractal hash-chain traversal** {{FRACTAL}} {{ALMOST-OPTIMAL}} to obtain a logarithmic middle ground.
The chain is revealed in reverse of the order in which it is computed (the CA computes `h[1..L]` forward from the secret seed `h[0]`, but reveals `h[L-1], h[L-2], ..., h[1]` over time), which is exactly the setting these algorithms address.
Instead of the whole chain or just the seed, the CA maintains a small set of precomputed helper values ("pebbles") parked at self-similar positions along the chain.
When the value for the current period is needed, a pebble is already there; between periods the CA spends a small fixed budget of hash evaluations advancing the more distant pebbles toward the positions where they will next be needed.
The scheduling guarantees:

    storage  ~ log2(L)      hash values per certificate
    work     ~ (1/2) log2(L) hash evaluations per revealed value

For L = 2160, this is approximately 11 to 12 stored values (~384 bytes) per certificate and about 6 hash evaluations per period.
Across 1 billion certificates that is roughly 384 GB of state and, if the traversal is advanced once per period and the resulting value served to all requests in that period, on the order of 10^6 hash evaluations per second in aggregate.
This dominates a simple square-root checkpoint scheme (which would need ~1.5 TB and up to ~46 hashes per value) on both axes, and turns the seed-only extreme's O(L^2) lifetime cost into O(L log L).

This is purely a CA-side implementation choice: the on-the-wire tick and the relying party's verification procedure ({{verification}}) are unchanged.
The pebbles are unrevealed chain values and therefore carry the same confidentiality requirement as the seed ({{security-considerations}}).

## Why Embed the Tick in the MTCProof

The tick is embedded directly in the MTCProof (the certificate's signatureValue) rather than delivered via a separate channel because:

1. **Structurally inseparable:** The tick is part of the certificate itself.
   A relying party that parses the MTCProof will always encounter the status_tick field.
   There is no possibility of the tick being stripped or omitted in transit.

2. **No new protocol machinery:** No TLS CertificateEntry extension or other signaling mechanism is needed.
   The tick travels inside the existing certificate structure, requiring no changes to TLS implementations beyond MTC support.

3. **Safe to update dynamically:** The MTCProof is not committed to the Merkle Tree — only the TBSCertificateLogEntry is.
   The authenticating party can freely replace the signatureValue each period without invalidating the inclusion proof or cosignatures.

4. **No additional round-trips:** The tick travels with the certificate in the same TLS message.
   No DNS lookups or side-channel fetches are needed by the relying party.

5. **Server must participate:** The authenticating party is already responsible for maintaining its MTC certificate and refreshing it before expiry.
   Adding a lightweight hourly tick refresh is an incremental burden, not a new class of operational requirement.

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
  Deriving the URL from the issuer_id allows the CA to update DNS routing without certificate reissuance.

- **Only the authenticating party needs it:** Relying parties never contact the tick endpoint.
  Adding per-certificate bytes visible to all parties to convey a URL used by only one party is wasteful.

- **Redundant given existing CA relationship:** The authenticating party obtained the certificate from the CA (e.g., via ACME) and can receive the tick URL at that point, or derive it from the issuer_id at zero per-certificate cost.

The `.well-known` derivation from issuer_id ({{distribution}}) provides a zero-overhead default.
CAs that require non-default URLs can communicate them out-of-band during certificate provisioning.

## TLS Extension (Separate from Certificate)

Another alternative was carrying the hash chain tick in a TLS CertificateEntry extension or a separate TLS extension, rather than embedding it in the MTCProof.

This approach was rejected because:

- **Strippable:** A TLS extension can potentially be omitted by middleboxes or misconfigured servers.
  Embedding the tick in the MTCProof makes it structurally inseparable from the certificate.

- **The OCSP stapling lesson:** OCSP stapling was defined as optional, requiring servers to opt in.
  After more than a decade, stapling adoption remains incomplete, and browsers have been unable to enforce hard-fail policies.
  Any mechanism that relies on a separate signaling channel risks the same outcome.

- **Unnecessary complexity:** Defining a new TLS extension type requires IANA registration and implementation changes in TLS stacks.
  Embedding in the MTCProof requires no TLS-layer changes beyond MTC support itself.

## TLS status_request Extension

The TLS `status_request` extension (defined for OCSP stapling) uses a `CertificateStatusType` enum that is designed to be extensible beyond OCSP.
In TLS 1.2, a new status type could deliver the tick in a `CertificateStatus` message; in TLS 1.3, it could be carried per-certificate in the `CertificateEntry` extensions.

This approach was rejected for the same fundamental reason as a generic TLS extension: it makes the tick delivery optional and strippable.
The `status_request` mechanism is inherently opt-in — the client must request it, and the server can omit it without causing a hard failure.
Reusing an optional delivery channel for a mandatory validity condition is semantically contradictory and reintroduces the soft-fail problem that this mechanism is designed to eliminate.

Additionally, `status_request` carries `OCSPResponse` semantics (a signed assertion from a responder); repurposing it for a bare hash value that is self-authenticating against the certificate would be a poor semantic fit.

## Shorter Certificate Lifetimes

The simplest revocation strategy is to make certificates short-lived enough that revocation is unnecessary.
For example, 1-day certificates have at most 24-hour exposure after compromise.

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

This section addresses some potential objections that may arise from the PLANTS community regarding this proposal.

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
Third, CAs already operate high-availability infrastructure for issuance; tick distribution is a strictly simpler service (static content, cacheable, CDN-friendly).
Additionally, relying parties can choose to accept ticks that are slightly stale (e.g., two or three periods old rather than only the current or immediately preceding period), according to local policy.
This trades revocation latency for resilience: if a CA outage prevents the authenticating party from obtaining a fresh tick, relying parties with a more permissive staleness policy will continue to accept the certificate while the outage is resolved.
The base verification procedure ({{verification}}, step 4) already allows the immediately preceding period; deployments with known availability concerns MAY extend this window further.

As a further mitigation, authenticating parties SHOULD obtain Merkle Tree Certificates from multiple independent CAs.
If one CA's tick distribution infrastructure becomes unavailable, the authenticating party can immediately switch to presenting a certificate from a different CA whose ticks remain current.
This multi-CA strategy eliminates the single point of failure: a tick distribution outage at one CA causes no service disruption as long as at least one other CA's infrastructure remains operational.
Since MTC certificates are lightweight to obtain and maintain, the incremental cost of holding certificates from two or three CAs is modest compared to the resilience benefit.

Finally, the alternative (no in-band revocation) means the ecosystem depends entirely on external revocation systems whose availability the CA does not control.

## "Just Use Shorter Certificate Lifetimes"

If revocation latency is the concern, reducing certificate lifetimes (e.g., to one day) achieves similar bounds without new mechanism complexity.
The PLANTS community may prefer this simpler approach.

Shorter lifetimes and hash chain revocation are not mutually exclusive, but shorter lifetimes alone impose costs that hash chains avoid.
Daily issuance for millions of subscribers produces proportionally larger Merkle Trees, more frequent log publications, and tighter availability requirements on issuance infrastructure.
A one-day certificate that cannot be renewed due to a 2-hour CA outage causes immediate service disruption; a 47-day certificate with hash chain revocation survives the same outage with no impact (the tick was already fetched).
Hash chains provide short revocation latency while preserving the operational headroom that longer lifetimes afford.

## "CRLite/CRLSets Already Solve This Problem"

Browser vendors already push compressed revocation data to relying parties.
Adding an in-band mechanism may appear redundant.

External revocation systems and hash chain revocation serve different roles.
CRLite and CRLSets are controlled by the browser vendor, not the CA; they operate on the vendor's update schedule; and they provide coverage only to relying parties that subscribe to the feed.
Hash chain revocation is CA-operated, has a deterministic latency bound (one period), and is enforced by every relying party that validates the certificate — including non-browser TLS clients, IoT devices, and any implementation that supports MTC but has no external revocation feed.
The two mechanisms are complementary: external revocation is defense-in-depth, while hash chains provide a universal baseline.

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
Additionally, the fallback to revoked ranges provides a recovery path: if seed compromise is detected, the CA revokes affected certificates via ranges, which relying parties enforce regardless of hash chain state.

## "Modifying MTCProof Breaks Existing Implementations"

Adding a status_tick field to MTCProof requires changes to every MTC implementation.
The base MTC specification may not have anticipated this kind of extension.

This objection is well-founded.
Section 7.2 of {{I-D.ietf-plants-merkle-tree-certs}} explicitly requires relying parties to reject an MTCProof if the signatureValue contains "extra data after the MTCProof."
The current MTCProof structure has no extensibility mechanism: it is a fixed sequence of fields with no trailing extensions block or version indicator.

Consequently, appending a status_tick to the MTCProof will cause any existing MTC implementation to reject the certificate — regardless of whether the X.509 extension is marked critical or non-critical.
An unaware relying party will ignore the non-critical id-pe-hashChainAnchor extension, proceed to parse the MTCProof, find 36 unexpected trailing bytes, and fail verification.

This means that, in practice, deploying this mechanism requires one of the following:

1. **Amendment to the base MTC specification:** The MTCProof structure is extended with a trailing extensions field (see {{mtcproof-extensibility}}) that existing parsers can safely skip.
   This is the preferred approach and is proposed by this document.

2. **Critical extension only:** The id-pe-hashChainAnchor extension is marked critical, so unaware implementations reject at the X.509 extension stage (before reaching MTCProof parsing).
   This sacrifices incremental deployment.

3. **Concurrent deployment:** Since MTC is not yet deployed at scale, both the base spec and this extension can be implemented together before the ecosystem ossifies.
   Early implementations can adopt the extended MTCProof structure from the start.

This document pursues option 1 as the primary path, with option 3 as a practical fallback during the current development window.
See {{mtcproof-extensibility}} for the proposed MTCProof amendment.

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

This concern applies equally to any CA-mediated revocation system and is inherent in the CA trust model.
A CA can already refuse to issue or renew certificates for any subscriber.
Tick withholding is detectable: the authenticating party knows it did not receive a tick and can raise an alarm, switch CAs, or fall back to a traditionally-signed certificate.
Furthermore, the tick distribution endpoint can be monitored by third parties (CT-style auditing), making selective withholding observable.
The threat is real but not novel, and the mitigations (market pressure, monitoring, CA switching) are the same ones that discipline CA behavior today.

## "Verification Cost Grows Linearly with Certificate Age"

A relying party verifying a tick near the end of a 47-day certificate's lifetime must compute up to 1,128 hashes.
This linear cost may be unacceptable for constrained devices.

On modern hardware, 1,128 SHA-256 operations take approximately 10-20 microseconds — negligible compared to the TLS handshake's asymmetric cryptography (ECDHE key exchange, signature verification).
Even on constrained IoT devices, SHA-256 is typically hardware-accelerated and the computation completes in under a millisecond.
For comparison, verifying a single Ed25519 signature costs roughly the same as hundreds of SHA-256 operations.
If the linear cost is nonetheless a concern for a specific deployment, choosing a shorter certificate lifetime (reducing chain_length) or a longer revocation_period (also reducing chain_length) provides a direct mitigation.

# Proposed MTCProof Extensibility {#mtcproof-extensibility}

This document proposes that the base MTC specification {{I-D.ietf-plants-merkle-tree-certs}} amend the MTCProof structure to include a trailing proof-level extensions field, enabling future mechanisms (including hash chain revocation) to attach additional data to the certificate presentation without breaking existing parsers.

## Motivation

The current MTCProof structure is a fixed sequence of fields with no extensibility point:

    struct {
        MerkleTreeCertEntryExtension extensions<0..2^16-1>;
        uint48 start;
        uint48 end;
        HashValue inclusion_proof<0..2^16-1>;
        MTCSignature signatures<0..2^16-1>;
    } MTCProof;

Section 7.2 of {{I-D.ietf-plants-merkle-tree-certs}} requires implementations to reject certificates where the signatureValue contains extra data after the MTCProof.
This means no trailing data can be added without breaking all existing parsers.

The existing `extensions` field in MTCProof carries the log entry's MerkleTreeCertEntryExtension values, which are committed to the Merkle Tree.
These cannot carry dynamic, per-period data like hash chain ticks because the Merkle Tree inclusion proof would fail.

A proof-level extensions field — not committed to the tree and freely updatable by the authenticating party — would allow the MTCProof to carry revocation ticks and potentially other future mechanisms (e.g., key transparency signals, policy assertions) without requiring a new version of the base specification for each.

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
        opaque value[HASH_SIZE];
    } HashChainTick;

The HashChainTick is encoded as an MTCProofExtension with `extension_type` set to `hash_chain_tick(0)` and `extension_data` containing the serialized HashChainTick (4 + HASH_SIZE bytes).

## Backward Compatibility

Because the `proof_extensions` field uses a length-prefixed encoding, an implementation that supports the extended structure but does not recognize a particular extension type can skip over it by consuming the declared length.
Implementations that predate the amendment will reject the certificate at the MTCProof parsing stage (due to trailing bytes), which is acceptable: such implementations would also not recognize the id-pe-hashChainAnchor extension's semantics, so they cannot verify hash chain revocation regardless.

For the transition period, ecosystems have two options:

- **Mark the extension critical:** Unaware implementations reject at the X.509 extension stage, producing a clear error rather than an opaque parse failure.

- **Deploy the base spec amendment first:** Once the proof_extensions field is adopted into the base MTC specification, all conforming implementations will parse it (ignoring unknown types), enabling incremental deployment of hash chain revocation with a non-critical X.509 extension.

# Acknowledgments
{:numbered="false"}

The hash chain revocation concept is based on Silvio Micali's foundational work on efficient certificate revocation {{MICALI}}.
The name "MTCRS" is a nod to Micali's Certificate Revocation System (CRS); and coincidentally, "RS" also happens to be the initials of the author of this document.

---
title: "Hash Chain Revocation for Merkle Tree Certificates"
abbrev: "MTC Hash Chain Revocation"
category: exp

docname: draft-strad-plants-mtc-hash-chain-revocation-latest
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
  github: "robstradling/mtc-with-hash-chain-revocation"
  latest: "https://robstradling.github.io/mtc-with-hash-chain-revocation/draft-strad-plants-mtc-hash-chain-revocation.html"

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
    target: https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Digital%20Signatures/Efficient_Certificate_Revocation.pdf
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

...

--- abstract

This document defines a hash chain revocation mechanism for Merkle
Tree Certificates (MTC) {{I-D.ietf-plants-merkle-tree-certs}}.  A
Merkle Tree CA commits a hash chain anchor into the certificate at
issuance time.  Periodically, the CA reveals hash chain values that
serve as proof of non-revocation.  The authenticating party includes
the current hash chain value (a "tick") in the TLS handshake,
enabling the relying party to cryptographically verify that the
certificate has not been revoked, with granularity as fine as one
hour.

This mechanism provides timely revocation without requiring
signatures per revocation check, without relying on the relying
party to poll for revocation updates, and without introducing new
trust relationships beyond the existing CA.


--- middle

# Introduction

Merkle Tree Certificates {{I-D.ietf-plants-merkle-tree-certs}}
authenticate TLS connections using compact inclusion proofs into a
Merkle Tree maintained by a certification authority (CA).  The base
MTC specification uses a short-lived certificates model, where
certificate expiration replaces explicit revocation signals.

However, deployments such as Chrome's draft MTC policy {{CHROME-MTC}}
permit certificate lifetimes of up to 47 days.  At this timescale,
key compromise or certificate misissuance can cause significant harm
before natural expiry.  The base MTC specification acknowledges this
gap and suggests that relying parties with access to external
revocation systems like {{CRLite}} or {{CRLSets}} SHOULD use them,
but does not define an in-band revocation mechanism.

This document defines such a mechanism based on hash chains
{{MICALI}}.  At issuance, the CA commits a hash chain anchor into
the MTC log entry as an X.509 extension.  Each revocation period
(e.g., every hour), the CA reveals the next hash chain value for all
non-revoked certificates.  To revoke a certificate, the CA simply
stops revealing values.  The authenticating party (server) includes
the current hash chain value in its TLS Certificate message, and the
relying party (client) verifies it against the anchor committed in
the log entry.

This approach achieves the following properties:

- **Timely revocation:** Revocation takes effect within one period
  (e.g., one hour), regardless of when the relying party last
  updated its trusted subtrees.

- **No per-check signatures:** Unlike OCSP {{RFC6960}}, verification
  requires only hash computations, not signature verification.  The
  CA incurs no signing load for revocation status.

- **Mandatory enforcement:** The hash chain value is a required
  component of the certificate presentation.  Unlike OCSP stapling,
  the mechanism cannot be silently omitted by the authenticating
  party.

- **Self-authenticating:** The hash chain value is verified against
  the anchor already committed in the Merkle Tree.  No new trust
  relationships or authenticated channels are needed.

- **Minimal overhead:** A single hash value (32 bytes for SHA-256)
  is added to the TLS Certificate message.

## Rationale for This Approach

Several alternative revocation mechanisms were considered and
rejected.  {{alternatives}} provides detailed analysis of each.
The hash chain approach was selected because it uniquely combines
mandatory enforcement (the value is structurally required for
certificate validity), zero signing overhead, self-authentication
against an already-trusted anchor, and minimal bandwidth cost.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Hash Chain Construction {#construction}

## Parameters

The hash chain mechanism introduces the following additional
parameter to the Merkle Tree CA configuration:

revocation_period:
: A duration, in seconds, that determines the granularity of
  revocation.  This MUST evenly divide the CA's certificate lifetime.
  The number of periods in a certificate's lifetime is:
  `chain_length = lifetime / revocation_period`.

## Chain Generation

At certificate issuance time, for each log entry, the CA generates a
hash chain as follows:

1. Generate a cryptographically random seed of HASH_SIZE bytes
   (32 bytes for SHA-256).

2. Compute the hash chain of length chain_length + 1:

       h[0] = seed
       h[i] = Hash(HashChainInput(h[i-1], i))  for i = 1, ..., chain_length

   Where HashChainInput is defined in {{encoding}}.

3. The anchor is `h[chain_length]`, the final value in the chain.

The anchor is included in the certificate as an X.509 extension (see
{{assertion-integration}}).

## Period Numbering

Periods are numbered starting from 0.  Period 0 begins at the
certificate's issuance time and each subsequent period begins
revocation_period seconds later.  The period number at any given time
t is:

    period = floor((t - issuance_time) / revocation_period)

## Revealing Values

For each non-revoked certificate, at the start of period t, the CA
reveals the hash chain value `h[chain_length - t]`.  This value can
be verified by hashing it t times and comparing with the anchor.

To revoke a certificate, the CA stops revealing new values.  Once the
previous value expires (at the start of the next period), the
certificate is effectively revoked: no party can produce a valid
value without knowledge of unrevealed chain elements, which requires
inverting the hash function.

## Security of the Hash Chain

The security of this mechanism relies on the preimage resistance of
the hash function.  Given `h[i]`, it is computationally infeasible to
compute `h[i-1]` (which would be needed to forge a future validity
proof).  The chain is revealed in reverse order precisely for this
reason: knowledge of the current value does not help compute future
values.

The domain separation in HashChainInput ({{encoding}}) prevents
values from being confused with other protocol elements or with hash
chain values at different positions.

# Integration with MTC Log Entries {#assertion-integration}

## Hash Chain Anchor Extension

This document defines a new X.509 certificate extension for carrying
the hash chain anchor.  This extension is included in the
TBSCertificateLogEntry's extensions field, and thus appears in the
TBSCertificate of the resulting Merkle Tree Certificate.

    id-pe-hashChainAnchor OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) dod(6) internet(1)
        security(5) mechanisms(5) pkix(7) pe(1) TBD }

The extension value contains the DER encoding of the following
ASN.1 structure:

    HashChainAnchorInfo ::= SEQUENCE {
        revocationPeriod  INTEGER,
        anchor            OCTET STRING
    }

revocationPeriod:
: The revocation period in seconds.  MUST match the CA's configured
  revocation_period.

anchor:
: The hash chain anchor value `h[chain_length]` (HASH_SIZE bytes).

The id-pe-hashChainAnchor extension MUST be marked non-critical, so
that relying parties that do not implement this mechanism can still
process the certificate.  However, relying parties that do implement
this mechanism MUST enforce hash chain verification as described in
{{verification}} when the extension is present.

The extension MUST appear at most once in a certificate.

# Certificate Presentation {#cert-format}

## Hash Chain Tick

When a hash chain anchor extension is present in the certificate,
the authenticating party MUST include a hash chain tick in the
TLS CertificateEntry alongside the certificate.  The tick is
carried in a new TLS CertificateEntry extension:

    struct {
        uint32 period;
        opaque value[HASH_SIZE];
    } HashChainTick;

period:
: The period number for which this tick is valid.

value:
: The hash chain value `h[chain_length - period]`.

The authenticating party MUST include a HashChainTick with a
period value that is current at the time of the TLS handshake.  A
relying party SHOULD accept ticks for the current period or the
immediately preceding period, to allow for clock skew and caching.

## Use in TLS {#tls-use}

This document defines a new TLS CertificateEntry extension type:

    enum {
        ...
        hash_chain_tick(TBD),
        (2^16-1)
    } ExtensionType;

When an authenticating party presents a Merkle Tree Certificate
whose TBSCertificate contains the id-pe-hashChainAnchor extension,
it MUST include the hash_chain_tick extension in the
CertificateEntry.  The extension_data contains the serialized
HashChainTick structure.

The presence of id-pe-hashChainAnchor in the certificate signals to
the relying party that a hash_chain_tick extension is required in
the CertificateEntry.  If the extension is absent or the tick
fails verification, the relying party MUST reject the certificate.

# Verification {#verification}

When a relying party receives a Merkle Tree Certificate with the
id-pe-hashChainAnchor extension, it performs the following steps in
addition to the base MTC verification procedure:

1. Extract the HashChainAnchorInfo from the certificate's
   id-pe-hashChainAnchor extension.  If not present, skip hash chain
   verification (the certificate does not use this mechanism).

2. Extract the HashChainTick from the hash_chain_tick
   CertificateEntry extension.  If the id-pe-hashChainAnchor
   extension is present but no hash_chain_tick extension is
   provided, reject the certificate with a bad_certificate error.

3. Compute the expected period from the current time:

       expected_period = floor((current_time - issuance_time) / revocation_period)

4. Check that `tick.period` is equal to expected_period or
   expected_period - 1.  If not, reject the certificate with a
   certificate_expired error.

5. Starting from `tick.value`, iteratively hash `tick.period`
   times:

       v = tick.value
       for i = chain_length - tick.period + 1 to chain_length:
           v = Hash(HashChainInput(v, i))

6. Compare the result with anchor from the HashChainAnchorInfo.  If
   they do not match, reject the certificate with a bad_certificate
   error.

If all steps succeed, the hash chain verification passes, confirming
that the CA has not revoked this certificate as of the indicated
period.

# Tick Distribution {#distribution}

The CA MUST provide a mechanism for authenticating parties to obtain
current hash chain ticks.  This document defines an HTTP
interface for this purpose.

## HTTP Interface

The CA (or a mirror) exposes the following endpoint:

    GET {prefix}/tick/{log_number}/{index}

This returns the current HashChainTick for the log entry at the
given index in the given issuance log.  The response is the
serialized HashChainTick structure (4 bytes period + HASH_SIZE
bytes value).

The CA SHOULD set HTTP cache headers with a max-age no longer than
revocation_period seconds.

## Operational Model

The authenticating party periodically fetches its current tick
from the CA:

1. At least once per revocation_period, the authenticating party
   fetches its updated HashChainTick.

2. The authenticating party replaces its stored tick with the
   newly fetched value.

3. During TLS handshakes, the authenticating party includes the
   stored tick in its certificate presentation.

If the authenticating party is unable to obtain a fresh tick
(e.g., due to CA unavailability), it continues to serve the most
recent tick until that tick's period expires.  After expiry,
the certificate becomes unusable until a fresh tick is obtained
or a new certificate is provisioned.

# Security Considerations

## Hash Function Requirements

The security of this mechanism depends on the preimage resistance of
the hash function used.  SHA-256 {{SHS}} provides 256 bits of
preimage resistance, which is sufficient for all foreseeable
certificate lifetimes.  With a one-hour revocation_period and a
47-day lifetime, the chain length is 1,128, which does not
meaningfully degrade the security margin.

## Seed Confidentiality

The CA MUST keep the hash chain seed (h\[0\]) and all not-yet-revealed
chain values confidential.  Compromise of these values would allow an
attacker to produce future ticks, defeating revocation.

If the CA's seed storage is compromised, the CA MUST revoke all
affected certificates via the base MTC revocation mechanism
(revoked ranges of serial numbers) as a fallback.

## Denial of Service via Tick Withholding

A compromised or malicious CA could withhold ticks from a
legitimate authenticating party, effectively denying service.  This
is analogous to a CA refusing to issue OCSP responses and is
mitigated by the same market forces: an authenticating party that
cannot obtain ticks will switch to another CA.

Additionally, since ticks are small (36 bytes), they can be
efficiently distributed via CDN, reducing the attack surface for
tick withholding.

## Interaction with Base MTC Revocation

The hash chain mechanism complements rather than replaces the base
MTC revoked ranges mechanism.  Revoked ranges provide a fallback
for scenarios where the hash chain mechanism is insufficient:

- Compromise of the CA's hash chain seed storage
- Bulk revocation of many certificates simultaneously
- Relying parties that have not yet implemented hash chain
  verification

Relying parties that support both mechanisms SHOULD check both:
a certificate is considered revoked if either mechanism indicates
revocation.

## Clock Skew

The grace period of accepting the current or immediately preceding
period's tick ({{verification}}, step 4) provides tolerance for
clock skew of up to one full revocation_period.  Deployments with
known clock skew issues MAY extend this to two preceding periods at
the cost of slightly delayed revocation enforcement.

# IANA Considerations

## Certificate Extension

IANA is requested to register the following entry in the "SMI
Security for PKIX Certificate Extension" registry:

| Decimal | Description          | Reference     |
|---------|----------------------|---------------|
| TBD     | id-pe-hashChainAnchor | This document |

## TLS ExtensionType

IANA is requested to register the following entry in the TLS
ExtensionType Values registry:

| Value | Extension Name      | TLS 1.3  | Reference     |
|-------|---------------------|----------|---------------|
| TBD   | hash_chain_tick     | CH, CT   | This document |

--- back

# Hash Chain Input Encoding {#encoding}

The HashChainInput structure provides domain separation for hash
chain computations:

    struct {
        uint8 label[24] = "MTC HashChain Revocation";
        TrustAnchorID issuer_id<1..2^8-1>;
        uint16 log_number;
        uint48 index;
        uint32 position;
        opaque preimage[HASH_SIZE];
    } HashChainInput;

label:
: A fixed ASCII string providing domain separation from other uses
  of the hash function in MTC.

issuer_id:
: The CA's trust anchor ID.  Binds the chain to a specific CA.

log_number:
: The log number of the issuance log containing this entry.  Binds
  the chain to a specific log.

index:
: The entry's index within the issuance log.  Binds the chain to a
  specific entry.

position:
: The position in the chain (1 to chain_length).  Prevents values
  at different positions from being interchangeable.

preimage:
: The previous hash chain value being hashed.

The Hash function is the same hash function used by the Merkle Tree
CA (SHA-256 for CAs using SHA-256).

# Design Rationale {#rationale}

This section provides rationale for the choices made in this
document.

## Why Hash Chains (Micali) Instead of Other Revocation Mechanisms

Hash chains {{MICALI}} were selected because they are the only known
mechanism that simultaneously provides:

1. **Self-authentication:** The tick is verified against data
   already committed in the Merkle Tree (the anchor).  No additional
   signatures, certificates, or trust relationships are needed.

2. **Zero CA signing load:** Each revocation period, the CA reveals a
   precomputed value.  There is no per-certificate, per-period
   signing operation.  This is critical for CAs with millions of
   active certificates.

3. **Mandatory enforcement:** Because the tick is structurally
   part of the certificate presentation, relying parties can hard-
   fail on its absence.  This avoids the soft-fail problem that
   plagued OCSP.

4. **Minimal bandwidth:** 36 bytes per handshake (4-byte period +
   32-byte hash value).

5. **Simple implementation:** The mechanism requires only a hash
   function and basic arithmetic.  No new cryptographic primitives
   are introduced.

## Why One Hour (or One Day) Periods

A one-hour revocation_period provides a good balance:

- **Revocation latency:** A compromised key is unusable within at
  most two hours (current period + grace period).

- **Operational feasibility:** Authenticating parties must fetch a
  new tick once per hour.  This is a trivial HTTP request for a
  36-byte response.

- **Chain length:** For 47-day certificates, the chain length is
  1,128.  Verification requires at most 1,128 hash computations,
  which takes microseconds on modern hardware.

- **CA storage:** The CA must store one seed per active certificate.
  With 32 bytes per seed, 10 million certificates require 320 MB.

A one-day period is also viable, reducing operational frequency at
the cost of up to 48-hour revocation latency.  Deployments SHOULD
choose the shortest period operationally feasible.

## Why Include the Tick in the Certificate Structure

The tick is included as a mandatory part of the certificate
presentation rather than delivered via a separate channel because:

1. **No soft-fail ambiguity:** If the tick is separate (e.g., via
   DNS or a TLS extension), a missing tick could indicate either
   revocation or a delivery failure.  When the tick is mandatory,
   its absence always means the certificate is invalid.

2. **No additional round-trips:** The tick travels with the
   certificate in the same TLS message.  No DNS lookups or
   side-channel fetches are needed by the relying party.

3. **Universal applicability:** Works for all TLS connections, not
   only HTTPS.  Mechanisms that depend on DNS or HTTP are limited to
   protocols where those channels are available.

4. **Server must participate:** The authenticating party is already
   responsible for maintaining its MTC certificate and refreshing it
   before expiry.  Adding a lightweight hourly tick refresh is an
   incremental burden, not a new class of operational requirement.

# Alternatives Considered {#alternatives}

## DNS-Based Tick Distribution

One alternative considered was distributing hash chain ticks via
DNS records (e.g., a TXT record at `_mtc-tick.example.com`).
Under this model, clients would fetch the tick independently via
DNS, removing the requirement for server participation.

This approach was rejected for several reasons:

- **Soft-fail risk:** If the DNS lookup fails (network issue,
  resolver misconfiguration, etc.), the client must decide whether to
  fail the connection or proceed without the tick.  Any allowance
  for "proceed without" defeats the revocation mechanism.

- **Protocol dependency:** DNS-based distribution only works when
  the relying party can perform DNS lookups in the context of
  certificate verification.  This excludes some TLS use cases (e.g.,
  embedded devices, TLS within TLS).

- **Operational complexity for subscribers:** If the subscriber
  publishes the DNS record, they must update DNS every period.
  While feasible for sophisticated operators, this is a significant
  burden for smaller deployments.  If the CA publishes under its own
  zone, the DNS becomes a single point of failure and a target for
  denial-of-service attacks.

- **Latency:** An additional DNS lookup adds latency to connection
  establishment, even when parallelized with the A/AAAA lookup.

However, DNS-based distribution does have one notable advantage: it
does not require server software changes.  Deployments that prioritize
this property over hard-fail semantics MAY define a DNS-based
distribution profile in a separate document.

## TLS Extension (Optional Stapling)

Another alternative was defining a new TLS extension that optionally
carries the hash chain tick, analogous to the status_request
extension used for OCSP stapling.

This approach was rejected because:

- **The OCSP stapling lesson:** OCSP stapling was defined as
  optional, requiring servers to opt in.  After more than a decade,
  stapling adoption remains incomplete, and browsers have been unable
  to enforce hard-fail policies.  Any optional mechanism will repeat
  this outcome.

- **Semantic ambiguity:** An absent extension could mean "server
  doesn't support it," "server forgot to configure it," or
  "certificate has been revoked."  Without universal deployment,
  hard-fail is impossible.

## Shorter Certificate Lifetimes

The simplest revocation strategy is to make certificates short-lived
enough that revocation is unnecessary.  For example, 1-day
certificates have at most 24-hour exposure after compromise.

This approach has trade-offs that motivate longer lifetimes:

- **Issuance infrastructure load:** Shorter lifetimes require more
  frequent issuance.  With millions of subscribers, daily
  certificate issuance produces proportionally larger logs and
  more frequent Merkle Tree constructions.

- **Availability risk:** An authenticating party that cannot reach
  the CA for one day loses its certificate entirely.  Longer
  lifetimes provide more buffer against CA outages.

- **Trusted subtree state:** The number of landmark subtrees relying
  parties must maintain grows with shorter lifetimes and more
  frequent landmark allocation, at the cost of increased CA
  operational complexity.

- **Deployment constraints:** Root program policies such as
  {{CHROME-MTC}} have set maximum lifetimes (e.g., 47 days) based
  on ecosystem-wide operational feasibility assessments.  Not all
  deployments can support arbitrarily short lifetimes.

Hash chain revocation provides the revocation latency benefits of
short-lived certificates while retaining the operational advantages
of longer lifetimes.

## CRLite / CRLSets / External Revocation

External revocation systems like {{CRLite}} and {{CRLSets}} compress
revocation information into compact data structures pushed to relying
parties.  The base MTC specification suggests using these as a
complement.

This approach has limitations when used as the sole revocation
mechanism for MTC:

- **Push latency:** These systems are updated on the order of hours
  to days, depending on the deployment.  They do not provide a
  guaranteed upper bound on revocation latency.

- **Relying party coverage:** Not all relying parties subscribe to
  external revocation feeds.  A mechanism that depends on the relying
  party having an up-to-date feed cannot provide universal
  revocation enforcement.

- **Separate trust path:** External revocation requires the relying
  party to trust the feed provider (e.g., the browser vendor) in
  addition to the CA.  Hash chain revocation uses only the existing
  CA trust relationship.

These mechanisms remain valuable as defense-in-depth and as a
fallback for the hash chain mechanism, as discussed in
{{security-considerations}}.

## Per-Certificate Signatures (OCSP-like)

A CA could sign per-certificate non-revocation statements each
period, analogous to OCSP responses.

This approach was rejected because:

- **Signing load:** A CA with millions of active certificates would
  need to produce millions of signatures per period.  With post-
  quantum signature algorithms, this is computationally expensive.

- **Response size:** OCSP responses include a full signature (e.g.,
  3,309 bytes for ML-DSA-65).  Hash chain ticks are 36 bytes.

- **Complexity:** OCSP requires its own responder infrastructure,
  certificate chain, and protocol.  Hash chains require only a hash
  function.

# Acknowledgments
{:numbered="false"}

The hash chain revocation concept is based on Silvio Micali's
foundational work on efficient certificate revocation {{MICALI}}.

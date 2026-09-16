# Ethics, Legal & Responsible Disclosure

An IEEE reviewer WILL look for this section. Honeypot papers are increasingly
expected to include an ethics statement. Write the paper's ethics subsection
from this file.

## 1. No harm to third parties
- The honeypot **never executes, downloads, resolves, or relays** attacker
  input. `wget`/`curl` are faked; egress is kernel-blocked (see DEPLOYMENT.md).
  So GenShells cannot become a stepping-stone in an attack chain.
- No captured malware is executed or redistributed. Payload URLs/hashes are
  recorded as strings only.

## 2. Data minimisation & privacy
- Source IPs are stored as `HMAC(salt, ip)` tokens in shipped data; the raw IP
  never enters the released dataset. Attacker-typed content can contain
  credentials from *other* compromised hosts — scrub obvious secrets before
  release and never publish raw credential dumps.
- No attempt is made to deanonymise or attribute individual attackers.
- Under GDPR-style regimes an IP can be personal data; the hashing + minimisation
  above is your mitigation. State this in the paper.

## 3. Institutional review
- As a university-level project, ask your department whether an IRB / ethics
  committee determination is needed. Many treat honeypot traffic as
  non-human-subjects (no interaction with identifiable persons), but **get the
  determination in writing** and cite it. This single sentence in the paper
  ("Our institution's IRB determined this work exempt, ref #…") removes a common
  reviewer objection.

## 4. Provider terms
- Confirm the VPS provider's AUP permits running a honeypot / receiving
  hostile traffic. Most do; some require a heads-up. Keep the email.

## 5. Deception & the LLM
- The LLM is constrained to emulate a shell and filtered for character breaks;
  it is not used to generate real malware, exploits, or working payloads. The
  system prompt forbids producing functional attack code.

## 6. Responsible disclosure
- If you observe a novel, in-the-wild exploit or a compromised third-party host,
  report it to the relevant CERT (e.g., CERT-In in India) rather than publishing
  operational details that aid attackers.

## 7. Release
- Release: code, the labeling guide, aggregate stats, and the hashed/scrubbed
  session dataset.
- Do **not** release: the salt, raw IPs, live malware samples, or anything that
  identifies your infrastructure.

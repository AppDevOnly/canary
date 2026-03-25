# Canary Threat Report: We've blocked your account! Your photos and videos will be deleted -- [X] Phishing

Date: 2026-03-24
Target: victim@example.com, blocked-account-icloud-phish.eml
Sent: Mon, 23 Mar 2026 12:12:14 +0000
From: victim <ujqmwmk@vwjlqjys.mlpoydgzeg.fexorlink.biz>
Evaluation: Email threat analysis
Tool: Canary v2.8


## Reading This Report

| Report Verdict | Meaning | What to do |
|---|---|---|
| [OK] Likely Legitimate | No significant threat indicators found. | No action required. |
| [!] Caution | Issues found, no proof of intentional harm. | Read findings before acting. |
| [X] Phishing | Deliberate attempt to steal credentials or deliver malware via links or attachments. | Do not click anything. Report and delete. |
| [X] Scam | Deliberate attempt to defraud you directly (money mule, advance fee, fake job, crypto investment). | Do not reply. Do not provide any information. |
| [X] Malware Delivery | Email contains or links to malware. | Do not open attachments or click links. |
| [?] Inconclusive | Mixed or insufficient signals. | Read findings. Treat with caution. |

| Findings Severity | Meaning |
|---|---|
| CRITICAL | Confirmed threat. Do not proceed. |
| HIGH | Strong indicator. Changes the overall verdict. |
| MEDIUM | Supporting evidence. Consistent with the verdict. |
| LOW | Minor signal. Low weight on its own. |
| INFO | Informational. Context only. |

| Security Domain | Question being answered |
|---|---|
| Confidentiality | Does this email attempt to steal your data or expose information about you? |
| Integrity | Is this email what it claims to be? |
| Availability | Could acting on this email harm your systems or accounts? |


## Verdict: [X] Phishing -- Apple iCloud credential and payment harvest

This is a fake Apple iCloud payment notice designed to steal your Apple ID and payment card details. The "Update my payment details" button leads to an attacker-controlled phishing page hosted in a Google Cloud Storage bucket -- a technique specifically chosen because Google's domain bypasses most URL reputation filters. Do not click anything.


## Executive Summary

This email impersonates Apple iCloud, threatening deletion of photos and videos unless the recipient updates their payment method immediately. The "Update my payment details" link resolves to a phishing page hosted in a Google Cloud Storage bucket (`storage.googleapis.com/ous2gsjdhx/`) -- an attacker-controlled bucket using Google's domain to appear trustworthy. The email was not sent by Apple; it originated from `fexorlink.biz` infrastructure using a Brazilian-hosted server that is listed on Spamhaus's Policy Block List. The body text uses character-level HTML obfuscation (each letter in a separate `<span>` tag) to defeat keyword-scanning spam filters, and embeds hundreds of lines of irrelevant scraped text in a hidden element to confuse machine-learning classifiers. The sender's display name is set to the recipient's own username (`victim`) -- a social engineering trick to create confusion about the source of the email. Three infrastructure components are flagged as malicious across VirusTotal and Spamhaus.

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High     | 5 |
| Medium   | 3 |
| Low      | 0 |
| Info     | 3 |


## Findings Summary

| # | Severity | Domain | Category | What was found |
|---|----------|--------|----------|----------------|
| 1 | CRITICAL | Availability | Fraud | Phishing page hosted on Google Cloud Storage to bypass URL filters |
| 2 | CRITICAL | Integrity | Social Engineering | Fake iCloud payment notice with false deletion deadline |
| 3 | HIGH | Integrity | Obfuscation | Character-level span fragmentation defeats keyword scanning |
| 4 | HIGH | Integrity | Obfuscation | Garbage text injection (`<ObjecT>`) confuses ML spam classifiers |
| 5 | HIGH | Integrity | Social Engineering | Display name set to victim's own username |
| 6 | HIGH | Integrity | Infrastructure | Sending IP 154.29.78.158 on Spamhaus PBL; self-signed cert; port 1234 open |
| 7 | HIGH | Integrity | Infrastructure | efianalytics.com relay and 216.244.76.116 both flagged malicious on VT |
| 8 | MEDIUM | Integrity | Infrastructure | fexorlink.biz -- infrastructure-only domain; no web presence; random-character subdomain cascade |
| 9 | MEDIUM | Integrity | Infrastructure | To: me@aol.com while delivered to Gmail -- misdirection / list mismatch |
| 10 | MEDIUM | Integrity | Infrastructure | DomainKey-Signature (deprecated 2011) alongside DKIM -- specialized bulk sending platform |
| 11 | INFO | Integrity | Infrastructure | X-Google-Sender-Delegation header -- unusual in inbound email |
| 12 | INFO | Integrity | Infrastructure | DKIM passes for fexorlink.biz subdomain, not for Apple |
| 13 | INFO | Confidentiality | Privacy | Email delivered to victim@example.com -- new account, no prior exposure history |


## Findings


### 1. Phishing link hosted in Google Cloud Storage bucket to bypass URL trust filters

| Field | Value |
|-------|-------|
| Severity | CRITICAL |
| Domain | Availability |
| Category | Fraud |
| Indicator | https://storage.googleapis.com/ous2gsjdhx/adasfdsdfdsfsaapo.html |
| MITRE | T1583.006 - Resource Development: Acquire Infrastructure: Web Services |

The "Update my payment details" button -- and all three links in the email -- point to an HTML file hosted in a Google Cloud Storage bucket named `ous2gsjdhx`. The page (`adasfdsdfdsfsaapo.html` -- random characters = disposable filename) is controlled by the attacker, not by Apple. The URL uses `storage.googleapis.com`, which is Google's legitimate CDN domain. This is a deliberate technique: most URL reputation systems whitelist Google's own domains, so this link passes many spam and phishing filters that would catch a link to an unknown attacker-controlled domain. The landing page is almost certainly a fake Apple ID login form or payment details page that sends whatever you enter directly to the attacker.

Do not visit this URL under any circumstances. If you have already clicked and entered any information (Apple ID, password, payment card number), treat that information as compromised immediately.

**Fix:**
1. Do not click. Delete the email.
2. If you clicked and entered Apple ID credentials: change your Apple ID password immediately at appleid.apple.com and enable two-factor authentication if not already enabled.
3. If you entered payment details: contact your bank or card issuer to report potential fraud and request a card replacement.
4. Report the GCS bucket to Google: https://safebrowsing.google.com/safebrowsing/report_phish/

**Countermeasure:** Enable phishing-resistant authentication (passkeys or hardware security keys) on your Apple ID so that a stolen password alone is not sufficient to access your account. (D3-CH Credential Hardening)


### 2. Content impersonates Apple iCloud with false deletion deadline

| Field | Value |
|-------|-------|
| Severity | CRITICAL |
| Domain | Integrity |
| Category | Fraud |
| Indicator | Fake Subscription ID: 59838016, Expiration Date: 03-23-2026 (day of sending) |
| MITRE | T1656 - Defense Evasion: Impersonation |

The email body is designed to look like an official Apple iCloud notice, using Apple's visual style (blue/red alert boxes, iCloud branding) and threatening imminent deletion of photos and videos. The expiration date is set to the same day the email was sent (March 23, 2026) to create maximum urgency. The subscription ID (59838016) and product details are fabricated. Apple does not send payment notifications from `fexorlink.biz` -- Apple's legitimate email domains are `@apple.com` and `@email.apple.com`. The email was not sent by Apple in any capacity.

**Fix:** If you receive any iCloud-related notices, navigate directly to appleid.apple.com in your browser (do not click email links) to check your actual account status.


### 3. Character-level HTML span fragmentation -- keyword filter evasion

| Field | Value |
|-------|-------|
| Severity | HIGH |
| Domain | Integrity |
| Category | Obfuscation |
| Indicator | `<span>i</span><span>C</span><span>l</span><span>o</span><span>u</span><span>d</span>` (every character wrapped individually) |
| MITRE | T1027 - Defense Evasion: Obfuscated Files or Information |

Every word in the visible email body is split into individual single-character `<span>` tags. Rendered in an email client, this looks completely normal -- the browser reassembles the characters into readable words. But spam filters that scan raw HTML for keywords ("iCloud", "payment", "expired", "delete") see no complete words at all, only isolated characters. This is a different technique from BiDi obfuscation: no text is reversed and no RTL direction is involved. The sole purpose is to defeat text-pattern matching at the raw HTML level. This technique requires deliberate, automated HTML generation -- it is not a side effect of any standard email composer.

Decoded visible content: "Your payment method has expired: Update your payment information... Your photos and videos will be Deleted !! ... We failed to renew your iCloud storage !! ... Update my payment details"


### 4. Garbage text injection in hidden `<ObjecT>` element

| Field | Value |
|-------|-------|
| Severity | HIGH |
| Domain | Integrity |
| Category | Obfuscation |
| Indicator | `<ObjecT>` containing citrus gardening guide, French university emails, forum templates, random strings |
| MITRE | T1027 - Defense Evasion: Obfuscated Files or Information |

After the visible body content, the email contains a large hidden block wrapped in `<ObjecT>` (note the mixed case -- `<object>` in lowercase would be filtered; mixed case evades tag-based filters). The content is scraped from unrelated sources: a gardening article about growing citrus trees indoors, French-language university student election communications, placeholder templates ("CUSTOMER NAME", "City: City"), forum archival notices, and long random alphanumeric strings. This content is invisible to the reader but present in the raw HTML. Machine-learning spam classifiers score emails partly on word content -- injecting large amounts of innocent text about lemons, gardening, and student elections lowers the overall "spam" probability score of the email. The mixed-case `<ObjecT>` tag is used specifically because `<object>` is commonly blocked by both spam filters and mail clients as a potentially dangerous tag.


### 5. Sender display name set to victim's own username

| Field | Value |
|-------|-------|
| Severity | HIGH |
| Domain | Integrity |
| Category | Social Engineering |
| Indicator | From: victim <ujqmwmk@vwjlqjys.mlpoydgzeg.fexorlink.biz> |
| MITRE | T1036 - Defense Evasion: Masquerading |

The display name in the From field is `victim` -- the recipient's own email username. In most email clients, only the display name is shown by default; many users never see the actual sending address. A recipient glancing at the From field sees what looks like an email from themselves, which creates immediate confusion: "Did Apple somehow associate this notice with my own account? Is this something I triggered?" This disorientation lowers the recipient's defensive posture exactly when it needs to be highest. The actual sending address (`ujqmwmk@vwjlqjys.mlpoydgzeg.fexorlink.biz`) is a random-character address at a multi-level random subdomain of fexorlink.biz -- nothing to do with the account owner.


### 6. Sending IP on Spamhaus PBL with open SMTP port and port 1234

| Field | Value |
|-------|-------|
| Severity | HIGH |
| Domain | Integrity |
| Category | Infrastructure |
| Indicator | 154.29.78.158 -- ASN 211014 "Elite Techno Solution"; PTR: bottlegame.uol.com.br; Spamhaus PBL 127.0.0.4; Shodan: ports 25, 80, 1234, 8181; self-signed cert |
| MITRE | T1584.004 - Resource Development: Compromise Infrastructure: Server |

The originating send server (154.29.78.158) is listed on Spamhaus's Policy Block List -- indicating its IP class is flagged as unauthorized for direct email delivery. Shodan shows this IP running an open SMTP server (port 25), a web server (port 80), and two non-standard ports: 1234 and 8181. Port 1234 is not associated with any standard service and is commonly used for C2 communications or custom attack tooling. The PTR record claims to be `bottlegame.uol.com.br` (a Brazilian internet company domain) but the actual ASN is "Elite Techno Solution" -- the PTR is misleading. A self-signed certificate is present, meaning no legitimate CA has verified this server's identity. This is a purpose-built spam/phishing server, not an accidentally misconfigured one.


### 7. efianalytics.com relay and 216.244.76.116 both flagged malicious on VirusTotal

| Field | Value |
|-------|-------|
| Severity | HIGH |
| Domain | Integrity |
| Category | Infrastructure |
| Indicator | efianalytics.com: VT malicious=1; 216.244.76.116: VT malicious=1 |
| MITRE | T1584.004 - Resource Development: Compromise Infrastructure: Server |

Two components of the email delivery chain carry VirusTotal malicious flags. `efianalytics.com` appears in the Received headers as an intermediate hop (IP 216.244.76.116, ASN 27323 Wowrack.com hosting) and has at least one AV engine detection in VT despite being 18 years old -- an established domain that has been flagged for abuse. `216.244.76.116` also carries a malicious detection. Both appearing in the same email's routing chain is consistent with a coordinated infrastructure cluster used for phishing delivery.


### 8. fexorlink.biz -- infrastructure-only domain with random-character subdomain cascade

| Field | Value |
|-------|-------|
| Severity | MEDIUM |
| Domain | Integrity |
| Category | Infrastructure |
| Indicator | fexorlink.biz: no A record, no MX, no creation date; Cloudflare NS; mlpoydgzeg.fexorlink.biz SPF: ip4:154.29.78.158 -all |
| MITRE | T1583.001 - Resource Development: Acquire Infrastructure: Domains |

`fexorlink.biz` has no A record, no MX record, and no discoverable web presence -- it exists purely as a domain for generating sending subdomains. The three-level subdomain pattern (`vwjlqjys.mlpoydgzeg.fexorlink.biz`) uses random characters at each level: `mlpoydgzeg` is the sending subdomain, `vwjlqjys` is the DKIM signing subdomain. Random characters at each level mean: (a) the subdomains are disposable and can be rotated per campaign, (b) no brand reputation is built up at the subdomain level that could be blocked, and (c) the structure suggests automated bulk campaign infrastructure. The `.biz` TLD is disproportionately represented in phishing and spam campaigns relative to its legitimate use base.


### 9. To: me@aol.com while delivered to Gmail -- list misdirection

| Field | Value |
|-------|-------|
| Severity | MEDIUM |
| Domain | Integrity |
| Category | Infrastructure |
| Indicator | To: me@aol.com / Delivered-To: victim@example.com |

The `To:` header names `me@aol.com` while the email was actually delivered to `victim@example.com`. This mismatch suggests the sender is using a different address in the SMTP envelope than in the message headers -- a common technique in bulk mail to obscure the true recipient list. The `victim@example.com` address received the email via SMTP envelope routing, not because it matched the `To:` header. This makes it harder for recipients to understand why they received the email and harder for abuse reporters to identify other recipients of the same campaign.


### 10. DomainKey-Signature (deprecated standard) included alongside modern DKIM

| Field | Value |
|-------|-------|
| Severity | MEDIUM |
| Domain | Integrity |
| Category | Infrastructure |
| Indicator | DomainKey-Signature header present (v=rsa-sha1; c=nofws) |

DomainKeys was the predecessor to DKIM, deprecated in 2011. Including a DomainKey-Signature alongside a modern DKIM-Signature indicates the sending platform was either built before 2011 and never updated, or deliberately includes the legacy signature to appear legitimate to old mail systems that might still check for it. Most modern spam platforms do not include this header. Its presence is a fingerprint of a specific (likely older or specialized) bulk sending tool.


### 11. X-Google-Sender-Delegation header present on inbound email

| Field | Value |
|-------|-------|
| Severity | INFO |
| Domain | Integrity |
| Category | Infrastructure |
| Indicator | X-Google-Sender-Delegation: victim@example.com Trusted Sender |

This Google header typically appears when an email is processed through Gmail's delegation or forwarding infrastructure. Its presence on an inbound email delivered from an external source (fexorlink.biz) is unusual. Possible explanations: the email passed through a Gmail forwarding rule, or Gmail's handling of the envelope-to address stamped this header during delivery. This does not indicate the victim account was compromised as a relay, but it warrants awareness.


### 12. DKIM passes for fexorlink.biz subdomain, not for Apple

| Field | Value |
|-------|-------|
| Severity | INFO |
| Domain | Integrity |
| Category | Infrastructure |
| Indicator | DKIM d=vwjlqjys.mlpoydgzeg.fexorlink.biz |

DKIM passes -- but for the attacker's own domain (fexorlink.biz), not for Apple. DKIM passing only means the email was not tampered with in transit and was sent by the domain it claims to be from. It does not validate that the sender is who the display name claims. The email is correctly signed by fexorlink.biz; it just has nothing to do with Apple.


### 13. New email account -- victim@example.com

| Field | Value |
|-------|-------|
| Severity | INFO |
| Domain | Confidentiality |
| Category | Privacy |
| Indicator | Delivered-To: victim@example.com |

This is the first email analyzed for the `victim@example.com` account. No prior exposure history for this address in the Canary report archive. The address received an iCloud phishing attempt -- suggesting it appears in consumer-targeting lists that have been paired with assumed Apple device usage patterns. See Tradecraft Assessment.


## MITRE ATT&CK

Techniques mapped from findings in this evaluation.
Full descriptions: https://attack.mitre.org

MITRE ATT&CK(R) is a registered trademark of The MITRE Corporation and is used in accordance
with the MITRE ATT&CK Terms of Use. Technique mappings in this report reference the MITRE
ATT&CK knowledge base, which is published under the Creative Commons Attribution 4.0 license.
https://attack.mitre.org/resources/terms-of-use/

  TA0042 Resource Development
    T1583.001  Acquire Infrastructure: Domains
               (fexorlink.biz registered for sending infrastructure only)
    T1583.006  Acquire Infrastructure: Web Services
               (Google Cloud Storage bucket ous2gsjdhx used to host phishing page)
    T1584.004  Compromise Infrastructure: Server
               (154.29.78.158 PBL-listed server; efianalytics.com malicious relay)

  TA0001 Initial Access
    T1566.002  Phishing: Spearphishing Link
               (GCS-hosted phishing page linked from email body)

  TA0005 Defense Evasion
    T1027      Obfuscated Files or Information
               (character-level span fragmentation + garbage text injection)
    T1036      Masquerading
               (display name impersonates victim's own username; content impersonates Apple)
    T1656      Impersonation
               (Apple iCloud brand impersonation)

  TA0006 Credential Access
    T1598.003  Phishing for Information: Spearphishing Link
               (Apple ID credential and payment details harvest via GCS landing page)

  TA0040 Impact
    T1657      Financial Theft
               (payment card details targeted via fake iCloud renewal page)


## Obfuscation Technique Reference

Two distinct obfuscation techniques were used in this email:

**Technique 1: Character-level span fragmentation**

Every rendered word in the body is split into individual HTML characters, each in its own `<span>` tag:

```
Rendered:  iCloud Payment Notice
Raw HTML:  <span>i</span><span>C</span><span>l</span><span>o</span>
           <span>u</span><span>d</span><span> </span><span>P</span>
           <span>a</span><span>y</span><span>m</span><span>e</span>
           <span>n</span><span>t</span><span> </span><span>N</span>
           <span>o</span><span>t</span><span>i</span><span>c</span>
           <span>e</span>
```

Spam filters scanning raw HTML for "iCloud", "payment", or "expired" find nothing. Email clients render the text normally. This is distinct from BiDi obfuscation (no RTL direction, no character reversal). Note: the canary email analysis spec currently checks for BiDi (RTL span) obfuscation but does not have a dedicated check for this character fragmentation pattern. Backlog item added.

**Technique 2: Garbage text injection via mixed-case `<ObjecT>` tag**

A block of scraped, benign-seeming text (citrus gardening guide, French university communications, forum boilerplate) is hidden inside `<ObjecT>` (mixed case avoids the `<object>` tag filter). Visible body text: approximately 200 words. Hidden garbage text: approximately 1,000 words. ML classifiers that score on word content see the email as approximately 80% citrus gardening, 20% iCloud billing -- significantly lowering the spam probability score.


## Infrastructure Map

```
[Attacker -- unknown origin]
  |
  +--> [154.29.78.158 -- "Elite Techno Solution" / PTR: bottlegame.uol.com.br]
         Spamhaus PBL listed; ports 25, 80, 1234, 8181; self-signed cert
         Subdomain: mlpoydgzeg.fexorlink.biz / SPF: ip4:154.29.78.158 -all
         |
         +--> [efianalytics.com relay -- 216.244.76.116, Wowrack.com]
                VT: 1 malicious engine
                |
                +--> [Gmail -- victim@example.com (delivered)]

Domains linked to this email:
  fexorlink.biz                     no creation date, no A record, Cloudflare NS only
  mlpoydgzeg.fexorlink.biz          sending subdomain, SPF: ip4:154.29.78.158 -all
  vwjlqjys.mlpoydgzeg.fexorlink.biz DKIM signing subdomain
  efianalytics.com                  relay hop, VT: 1 malicious, age 6734d (18yr)
  storage.googleapis.com/ous2gsjdhx attacker-controlled GCS bucket; phishing landing page

IPs observed:
  154.29.78.158   ASN 211014 Elite Techno Solution, US   PBL listed; ports 25/80/1234/8181
  216.244.76.116  ASN 27323 Wowrack.com, US              VT: 1 malicious
  (GCS bucket resolves to Google CDN IPs -- not attacker-controlled at IP level)

Shared infrastructure: fexorlink.biz + 154.29.78.158 form a cohesive sending cluster
Click destination: storage.googleapis.com/ous2gsjdhx/adasfdsdfdsfsaapo.html (GCS phishing page -- not visited)
Attachments: None
```


## Tradecraft Assessment

This campaign is technically sophisticated for a phishing email:

- **GCS bucket for phishing hosting is deliberate and effective.** Hosting the phishing page on Google's own infrastructure (`storage.googleapis.com`) means: the TLS cert is valid and issued by Google, the domain has global reputation whitelisting, and URL reputation systems are slow to flag it because the domain itself is Google's. This is a known-to-work technique that requires attacker infrastructure setup beyond just registering a domain.

- **The character fragmentation obfuscation is automated.** Splitting every character into a `<span>` tag across a multi-paragraph email requires a templating system -- a human did not type this by hand. The garbage text injection is also automated content sourcing. This attacker is running tooling, not manually crafting phishing emails.

- **The display name trick (victim's own username as sender name) is targeted.** To set `victim` as the display name, the attacker knew the recipient's email username before sending. This could come from any purchased email list that records both the username component and the full address.

- **The subject line uses emoji characters** (`??` which appear to be emoji rendered as `?` in the filename). These emoji are used to attract attention in an inbox preview and to defeat text-based subject line filters that don't normalize Unicode.

- **Infrastructure rotation is built in.** The random-character subdomain cascade (`vwjlqjys.mlpoydgzeg.fexorlink.biz`) means each campaign can use a different subdomain, making IP/domain blocklisting ineffective without blocking the root domain. The disposable GCS bucket name (`ous2gsjdhx`) serves the same purpose.

- **This is a consumer-targeted Apple scam, not a job-seeker campaign.** The victim@example.com account is receiving iCloud phishing -- which implies this address appears in lists compiled for Apple device users. This is a completely different exposure channel than the job-board Gmail ([analyst]) or the consumer spam Hotmail ([analyst]).


## Comparison to Previous Emails

First analysis for victim@example.com. No prior reports for this account.

| Dimension | This email (iCloud phish) | Harry & David (Hotmail, Mar 2026) |
|-----------|--------------------------|----------------------------------|
| Verdict | [X] Phishing | [X] Scam |
| Account targeted | victim@example.com | [analyst]@example.com |
| Claimed brand | Apple iCloud | Harry & David |
| Sending domain | fexorlink.biz (throwaway) | hyniq.xyz (141d) |
| Obfuscation | Span fragmentation + garbage injection | None |
| Click destination | Google Cloud Storage (trusted CDN) | Google Cloud VM raw IP |
| Both use Google infra | Yes -- GCS bucket | Yes -- GCP VM |
| Sophistication | HIGH | MEDIUM |

Both the iCloud phish and Harry & David scam use Google infrastructure for the click destination -- GCS bucket and GCP VM respectively. This is likely coincidence (Google infrastructure is widely abused for exactly these purposes) rather than the same operator.


## Tool Coverage

| Tool | Result | Notes |
|------|--------|-------|
| VirusTotal domain API | OK | fexorlink.biz: no creation date, 0/0; efianalytics.com: 6734d, 1 malicious |
| VirusTotal IP API | OK | 154.29.78.158: 0 mal 0 harm; 216.244.76.116: 1 malicious 59 harmless |
| DNSBL (Spamhaus ZEN, SpamCop) | OK | 154.29.78.158 LISTED on zen.spamhaus.org 127.0.0.4 (PBL) |
| Shodan InternetDB | OK | 154.29.78.158: ports 25/80/1234/8181, self-signed; 216.244.76.116: no data |
| urlscan.io | SKIP | URLSCAN_API_KEY not configured |
| crt.sh | SKIP | VT domain API sufficient for age data |
| DNS resolution | OK | 1 issue encountered, 1 resolved (fexorlink.biz no A record -- expected for send-only domain) |
| BiDi decode | N/A | No RTL spans found; character fragmentation obfuscation is a different technique (no decode needed -- each span contains one visible character) |
| Header analysis | OK | Full Received chain, DKIM, SPF, DomainKey-Signature, ARC, delegation headers |


## Recommendation

Do not interact with this email. Treat all links as malicious.

Immediate steps:
1. Do not click the "Update my payment details" button or any other link
2. Delete the email and report it as phishing in Gmail (three-dot menu > Report phishing)
3. Report the phishing page to Google: https://safebrowsing.google.com/safebrowsing/report_phish/ -- paste the storage.googleapis.com URL. This causes Google to revoke the bucket's public access, protecting other potential victims.
4. Check your actual iCloud account status directly at appleid.apple.com (not from email links)

If you already clicked and entered information:
- Apple ID credentials: change password immediately at appleid.apple.com, enable two-factor authentication
- Payment card details: contact your bank to report potential fraud and request a card replacement

Broader context:
- The victim@example.com address appears in consumer-targeting lists associated with Apple device users. Expect future Apple/iCloud-themed phishing to this address.
- Consider enabling Gmail's Enhanced Safe Browsing, which provides faster phishing detection for your account.


## Cleanup

| Item | Status |
|------|--------|
| Source .eml file | Read-only analysis -- file untouched at C:\Users\[user]\Downloads\blocked-account-icloud-phish.eml |
| Links visited by host | None |
| Temporary scripts | C:\temp\icloud-phish-checks.ps1 -- safe to delete |


---
Canary v2.8  use at your own risk. This tool reduces risk but does not guarantee safety.
No security evaluation is a substitute for your own judgment.
https://github.com/AppDevOnly/canary

This report references the MITRE ATT&CK(R) knowledge base. MITRE ATT&CK(R) is a registered
trademark of The MITRE Corporation, used under CC BY 4.0. https://attack.mitre.org

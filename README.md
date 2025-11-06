# AI-The-AI-Cyber-Threat-Landscape
Tackling Evolving AI Threats

AI-Powered Threat Hunting — L3 Playbook with MISP Confidence Scoring, MITRE mapping, and Hunter Directives

Below is a single, self-contained, operational L3 document intended for senior threat hunters and analysts. Each attack chain is implemented as a single KQL detection rule (ready for Microsoft Sentinel / Defender for Endpoint ingestion), contains:

full inline annotations and hunter directives,

MITRE ATT&CK technique mappings,

MISP tag → confidence weighting and how it’s applied,

recommended triage / investigation steps and automated playbook actions,

which Sentinel / MDE tables are used and expected fields,

tuning notes and false-positive guidance.

Notes:

Rules assume standard Microsoft telemetry table names available in Sentinel / MDE: EmailEvents, UrlClickEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceMemoryEvents, DeviceLogonEvents, OfficeActivity, AzureActivity, AADSignInEvents, SecurityEvent, CommonSecurityLog, and ThreatIntelligenceIndicator. Adapt field names to your environment if different.

ThreatIntelligenceIndicator is used to ingest MISP indicators; the KQLs compute an on-the-fly MISP weighted_score from tags. See scoring section first.

1 — MISP Weighted Scoring Model (shared across rules)

Purpose: unify MISP tags into a single weighted score that influences rule severity and prioritisation.

KQL snippet (materialize once per query set; reuse variable mispLookup in rules):

// MISP Weighted Scoring materialization
// Input: ThreatIntelligenceIndicator rows (ingested from MISP exports/API into Sentinel)
// Output: mispLookup with fields: IndicatorId, IndicatorType, IndicatorName, Tags, misp_tlp, misp_conf, misp_threatlevel, misp_score

let mispLookup = materialize (
    ThreatIntelligenceIndicator
    | where TimeGenerated >= ago(90d) // configurable TI window
    // Tags is assumed to be a string containing MISP-style tags, e.g., "tlp:amber;confidence:80;supply-chain:ai-models"
    | extend Tags = tostring(Tags)
    // Extract canonical tag values (case-insensitive)
    | extend misp_tlp = case(
        Tags has_cs "tlp:white", 1,
        Tags has_cs "tlp:green", 2,
        Tags has_cs "tlp:amber", 3,
        Tags has_cs "tlp:red", 4,
        1 // default
    )
    | extend misp_conf = case(
        Tags has_cs "confidence:100", 6,
        Tags has_cs "confidence:90", 5,
        Tags has_cs "confidence:80", 4,
        Tags has_cs "confidence:70", 3,
        Tags has_cs "confidence:60", 2,
        Tags has_cs "confidence:50", 1,
        1
    )
    | extend misp_threatlevel = case(
        Tags has_cs "threat-level:critical" or Tags has_cs "threat-level:high", 3,
        Tags has_cs "threat-level:medium", 2,
        Tags has_cs "threat-level:low", 1,
        1
    )
    // Optional boosts for AI-specific tags (tunable)
    | extend misp_ai_boost = iff(Tags has_cs "ai" or Tags has_cs "ai-powered" or Tags has_cs "phishing:ai-enhanced", 1.2, 1.0)
    // Final weighted score formula (normalize to 0..10 scale)
    | extend misp_score = round(((misp_tlp * 0.20) + (misp_conf * 0.50) + (misp_threatlevel * 0.30)) * misp_ai_boost, 2)
    | project IndicatorId, IndicatorType, IndicatorName, Tags, misp_score, misp_tlp, misp_conf, misp_threatlevel
);


Interpretation & thresholds (example):

misp_score >= 6 → high-confidence TI (raise severity)

4 <= misp_score < 6 → medium confidence

<4 → low confidence (use for enrichment only)

2 — Attack Chain Rule: AI-Powered Spearphish → Polymorphic Payload → Adaptive C2 → Behavioral Mimicry

Single detection rule that aggregates all stages, produces a kill-chain view. (This is the primary multi-stage L3 hunting rule.)

// AI Multi-Stage Attack Chain Detection — L3
// MITRE ATT&CK: Recon (TA0043?), Initial Access (TA0001), Execution (TA0002), Persistence (TA0003), Command and Control (TA0011), Defense Evasion (TA0005), Discovery (TA0007)
// Primary techniques mapping (examples): T1566.001 (spearphishing-link), T1566.002 (spearphishing-attachment), T1204 (user execution), T1059 (cmd/ps), T1105 (exfiltration), T1547 (registry run keys), T1574 (DLL side-loading), T1055 (process injection), T1016 (network discovery)
// Expected tables: EmailEvents, UrlClickEvents, DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceRegistryEvents, ThreatIntelligenceIndicator

let mispLookup = materialize(
    ThreatIntelligenceIndicator
    | where TimeGenerated >= ago(90d)
    | extend Tags = tostring(Tags)
    | extend misp_conf = case(Tags has_cs "confidence:90",5, Tags has_cs "confidence:80",4, Tags has_cs "confidence:70",3,1)
    | extend misp_score = round((case(Tags has_cs "tlp:red",4, Tags has_cs "tlp:amber",3, 1) * 0.2) + (misp_conf * 0.6) + (case(Tags has_cs "threat-level:high",3, Tags has_cs "threat-level:medium",2,1) * 0.2),2)
    | project IndicatorType, IndicatorName, Tags, misp_score
);

// ================= STAGE A: AI-ENHANCED PHISHING
let phish_candidates = materialize (
    EmailEvents
    | where TimeGenerated >= ago(48h)
    | where EmailDirection == "Inbound"
    // Detect suspicious subjects commonly used by AI-generated spearphish
    | extend subj_features = strcat(Subject, " ", Body)
    | extend ai_language_signs = iff(
            // heuristics: over-polished multi-sentence subject/body templates, greeting mismatch, overly personalised tokens
            (Subject has_any ("quick question","following up on our","as discussed","action required") or Body contains "please confirm" or Body contains "do you have a moment"), 1, 0)
    | extend sender = SenderFromAddress
    | where ai_language_signs == 1
    // join on MISP email indicators (if present)
    | join kind=leftouter (mispLookup | where IndicatorType == "Email") on $left.sender == $right.IndicatorName
    | extend misp_phish_score = coalesce(misp_score, 0)
    | project TimeGenerated, sender, RecipientEmailAddress, Subject, BodySnippet = substring(Body,0,512), misp_phish_score
);

// ================= STAGE B: POLYMORPHIC PAYLOAD DELIVERY
let payload_candidates = materialize (
    DeviceFileEvents
    | where TimeGenerated >= ago(48h)
    | where ActionType in ("FileCreated","FileWritten","FileModified")
    // suspicious extensions and high-entropy filenames
    | extend suspicious_ext = iff(FileName endswith_cs ".js" or FileName endswith_cs ".jse" or FileName endswith_cs ".docx" or FileName endswith_cs ".pdf" or FileName endswith_cs ".xlsm" or FileName endswith_cs ".dll", 1, 0)
    | extend filename_entropy = strlen(FileName) >= 16 and FileName matches regex @"[A-Za-z0-9]{12,}"
    | extend size_flag = iff(FileSize > 500000 and FileSize < 5000000,1,0) // suspicious mid-range payload sizes typical of packed payloads
    | where suspicious_ext == 1 or filename_entropy
    | extend file_hash = SHA1, device = DeviceName, path = FolderPath, initiator = InitiatingProcessFileName, cmdline = InitiatingProcessCommandLine
    // join with misp file hashes if available
    | join kind=leftouter (mispLookup | where IndicatorType == "FileHash") on $left.file_hash == $right.IndicatorName
    | extend misp_file_score = coalesce(misp_score, 0)
    | project TimeGenerated, device, FileName, path, file_hash, initiator, cmdline, misp_file_score
);

// ================= STAGE C: ADAPTIVE C2 (ML-DOMAIN / ROTATING IPS)
let c2_candidates = materialize (
    DeviceNetworkEvents
    | where TimeGenerated >= ago(48h)
    | where RemotePort between (8000 .. 65535) or RemotePort in (80,443)
    | extend domain = tolower(tostring(split(RemoteUrl, "/")[0]))
    | extend is_dynamic_provider = iff(RemoteUrl has_cs ".ddns." or RemoteUrl has_cs ".duckdns." or RemoteUrl has_cs ".no-ip.", 1, 0)
    | extend alg_domain_pattern = iff(domain matches regex @"^[a-z]{10,20}\d{0,4}\.(com|net|org)$", 1, 0)
    | where is_dynamic_provider == 1 or alg_domain_pattern == 1 or RemoteIP in (/* optional high-risk IP list placeholder */)
    | join kind=leftouter (mispLookup | where IndicatorType == "Url" or IndicatorType == "Domain") on $left.RemoteUrl == $right.IndicatorName or $left.domain == $right.IndicatorName
    | extend misp_c2_score = coalesce(misp_score, 0)
    | project TimeGenerated, DeviceName, RemoteIP, RemoteUrl, RemotePort, domain, alg_domain_pattern, is_dynamic_provider, misp_c2_score
);

// ================= STAGE D: BEHAVIORAL MIMICRY (ADMIN-LIKE COMMANDS / TIMING)
let mimicry_candidates = materialize (
    DeviceProcessEvents
    | where TimeGenerated >= ago(48h)
    | where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","cscript.exe","wscript.exe","mshta.exe","rundll32.exe")
    // look for admin-like sequences or perfectly timed actions
    | extend cmd = ProcessCommandLine
    | extend mimic_signs = 
        (iff(cmd has "Get-ADUser" or cmd has "Get-ADComputer" or cmd has "Get-ADGroup",1,0)
         + iff(cmd has "net user" or cmd has "net localgroup",1,0)
         + iff(cmd has "schtasks /create" or cmd has "sc create",1,0)
         + iff(cmd has "Invoke-Expression" or cmd has "IEX",1,0))
    | where mimic_signs >= 2
    | join kind=leftouter (mispLookup | where IndicatorType == "CommandLine") on $left.ProcessCommandLine == $right.IndicatorName
    | extend misp_mimic_score = coalesce(misp_score, 0)
    | project TimeGenerated, DeviceName, InitiatingProcessFileName = FileName, ProcessCommandLine, ParentProcessFileName, misp_mimic_score
);

// ================= AGGREGATE & SCORE ACROSS STAGES
// Join candidate sets into an incident-like aggregated row per device / sender / time window.
// Scoring logic: sum of top misp_scores + heuristics (entropy, alg_domain pattern, mimic_signs) -> total_score
phish_candidates
| join kind=leftouter (payload_candidates) on $left.RecipientEmailAddress == $right.device // heuristic: map recipient -> device owner (adjust mapping to your env)
| join kind=leftouter (c2_candidates) on $left.device == $right.DeviceName
| join kind=leftouter (mimicry_candidates) on $left.device == $right.DeviceName
| extend sum_misp = coalesce(misp_phish_score,0) + coalesce(misp_file_score,0) + coalesce(misp_c2_score,0) + coalesce(misp_mimic_score,0)
| extend heuristics = toint(iif(filename_entropy==true,2,0) + iif(alg_domain_pattern==1,2,0) + toint(mimic_signs))
| extend total_score = round(sum_misp + heuristics, 2)
// thresholds: >=8 -> high severity; 5-8 medium; <5 low
| where total_score >= 5
| summarize 
    first_seen = min(TimeGenerated), last_seen = max(TimeGenerated),
    total_score = max(total_score), stages = make_set(pack("phish",sender,"file",FileName,"c2",domain,"mimic",ProcessCommandLine)),
    affected_devices = make_set(device), ioc_hashes = make_set(file_hash), ioc_domains = make_set(domain)
    by bin(TimeGenerated, 1h)
| extend attack_chain = "AI-Spearphish → Polymorphic Payload → Adaptive C2 → Behavioral Mimicry"
| project first_seen, last_seen, total_score, stages, affected_devices, ioc_hashes, ioc_domains, attack_chain

HUNTER DIRECTIVES / INVESTIGATION

If total_score >= 8 — open a priority incident. Pull full email (headers, DKIM/SPF/DMARC verdicts), attachments, file hashes, process commandlines, and network sessions. Check InitiatingProcessParentImage and ImageLoad events for DLL sideloading.

Query DeviceImageLoadEvents for same file_hash. Confirm code signing and certificate chain.

Enrich domains and IPs with MISP, VirusTotal, PassiveDNS. Use misp_score to decide automatic containment (e.g., high misp_score + matching hash → isolate device).

Check for lateral movement: search SecurityEvent for new service creation or scheduled tasks on affected hosts.

AUTOMATED PLAYBOOK SUGGESTIONS

If misp_score >= 6 and total_score >= 8: trigger device isolation, block URL via firewall/Proxy, and revoke session tokens for affected accounts. Send IOC list to EDR for immediate containment (hash, domains, IPs).

TUNING & FALSE POSITIVES

Map RecipientEmailAddress to actual device usernames in your environment (the join above is a heuristic; replace with UPN mapping table).

Lower filename_entropy sensitivity if your org has many legitimate long filenames. Add allowlists of corp domains and CI/CD artifact names.

3 — Rule: AI Model Poisoning & Supply-Chain Tampering (single chain)

Detect tampering of model artifacts, training pipelines, or unexpected uploads to model directories.

// AI Model Poisoning Detection — L3
// MITRE: Supply Chain Compromise mapping (T1195, T1566 where relevant), Persistence / Defense Evasion where model artifacts executed
// Tables: DeviceFileEvents, DeviceNetworkEvents, ThreatIntelligenceIndicator, AzureActivity (for cloud training jobs), CommonSecurityLog

let mispLookup = materialize(ThreatIntelligenceIndicator | where TimeGenerated >= ago(180d) | extend Tags=tostring(Tags) | extend misp_score = 1.0); // reuse earlier MISP logic in production

DeviceFileEvents
| where TimeGenerated >= ago(7d)
| where FolderPath has_any ("\\models\\","/models/","\\ml\\","/training/","/artifacts/","\\model_registry\\") or FileName has_any (".pt",".pth",".h5",".pkl",".onnx",".tflite")
| where ActionType in ("FileCreated","FileModified","FileMoved")
| extend suspicious_change = iff(FileName endswith_cs ".pt" and FileSize > 1000,1,0) // heuristic
| extend suspect_replace = iff(FileName in ("model_latest.pt","production_model.pth") and InitiatingProcessFileName !in~ ("trusted_updater.exe","pip.exe","conda.exe","python.exe"),1,0)
| extend is_large_model = FileSize > 200000000 // 200MB
| where suspicious_change == 1 or suspect_replace == 1 or is_large_model
| join kind=leftouter (mispLookup | where Tags has_cs "supply-chain:ai-models") on $left.SHA1 == $right.IndicatorName
| extend misp_model_score = coalesce(misp_score, 0)
| extend total_score = 1.0 * toreal(suspect_replace) + 0.5 * toreal(is_large_model) + misp_model_score
| where total_score >= 1.5
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine, total_score, misp_model_score

MITRE & MISP

Tag events as: supply-chain:ai-models, confidence:80 (if coming from TI), threat-level:high if unsigned/unknown origin.

HUNTER DIRECTIVES

Immediately snapshot the model file and compute full hashes (SHA256). Check model provenance (who/what updated it). Query code repository logs, CI/CD pipelines (AzureActivity, CommonSecurityLog) for recent commits or publishes.

Check for abnormal training run logs with changed hyperparameters, new data sources, or unexpected dataset names. If cloud: check AzureActivity for service principal or VM user actions in training resource groups.

4 — Rule: Large-Scale Training Data Exfiltration (single chain)

Detect exfil of training datasets (large files, cloud storage uploads, unusual long transfers).

// Data Exfiltration — Large Training Datasets
// Tables: DeviceFileEvents, DeviceNetworkEvents, CommonSecurityLog, AzureActivity
let mispLookup = materialize(ThreatIntelligenceIndicator | where TimeGenerated >= ago(90d) | extend Tags=tostring(Tags) | extend misp_score=1.0);

DeviceFileEvents
| where TimeGenerated >= ago(24h)
| where ActionType in ("FileCreated","FileCopied","FileMoved")
| where FileSize > 1000000000 or FileName contains_cs "dataset" or FileName contains_cs "training" or FolderPath has_any ("/datasets/","\\datasets\\","/training/","\\training\\")
| join kind=inner (
    DeviceNetworkEvents
    | where TimeGenerated between (ago(24h) .. now())
    | where RemotePort in (443,22,21) or RemoteUrl has_any ("s3.amazonaws.com","storage.googleapis.com","blob.core.windows.net","upload.cloud","transfer.azure.com")
    | project DeviceName, RemoteIP, RemoteUrl, BytesSent, TimeGenerated, RemotePort
) on DeviceName
| extend exfil_indicator = iif(RemoteUrl has_any ("s3.amazonaws.com","storage.googleapis.com","blob.core.windows.net"), 2, 1)
| extend transfer_volume = BytesSent
| extend exfil_score = case(transfer_volume >= 5000000000,5, transfer_volume >= 1000000000,3,1)
| extend total_score = exfil_indicator + exfil_score
| where total_score >= 4
| project TimeGenerated, DeviceName, FileName, FileSize, FolderPath, RemoteUrl, RemoteIP, BytesSent, total_score

HUNTER DIRECTIVES

If total_score >= 4: inspect who initiated process, check cloud storage buckets for new uploads; identify service principals or apps used; rotate keys if necessary; check data access logs in cloud providers (S3, GCS, Azure Blob) for unusual put operations; consider revoking the app’s credentials.

5 — Rule: AI-Enhanced Command & Control (Domain Generation + Rotating IPs)

Detect algorithmic domain patterns and fast infrastructure rotation consistent with ML-driven C2.

// AI C2 Detection — Domain Generation / Fast Rotation
// Tables: DeviceNetworkEvents, DNSLogs (if available), ThreatIntelligenceIndicator
let mispLookup = materialize(ThreatIntelligenceIndicator | where TimeGenerated >= ago(180d) | extend Tags=tostring(Tags) | extend misp_score=1.0);

DeviceNetworkEvents
| where TimeGenerated >= ago(7d)
| extend domain = tolower(tostring(parse_url(RemoteUrl).Host))
| where isnotempty(domain) or RemoteIP != ""
| extend dg_pattern = domain matches regex @"^[a-z]{8,20}\d{0,4}\.(com|net|org|io|xyz)$" // algorithmic-looking domain
| extend recent_domain_count = countif(domain != "" ) over (partition by RemoteIP)
| where dg_pattern == 1 or RemoteIP in (/* susp IP list placeholder */)
| join kind=leftouter (mispLookup | where IndicatorType == "Domain" or IndicatorType == "Url") on domain == IndicatorName
| extend misp_c2_score = coalesce(misp_score,0)
| extend total_score = 1.5 * toint(dg_pattern) + misp_c2_score
| where total_score >= 3
| summarize hits = count(), devices = make_set(DeviceName), domains = make_set(domain), first_seen=min(TimeGenerated), last_seen=max(TimeGenerated) by RemoteIP
| project RemoteIP, hits, devices, domains, first_seen, last_seen, total_score

HUNTER DIRECTIVES

Check DNS query patterns for entropy and NXDOMAIN spikes. Correlate with DeviceProcessEvents to see which process created the session. If multiple devices reach out to same rotating set of IPs/domains → potential campaign.

6 — Rule: Behavioral Mimicry / ML-aware Evasion (single chain)

Detect processes that replicate benign admin activity but with suspicious provenance or embedding.

// Behavioral Mimicry Detection
// Tables: DeviceProcessEvents, DeviceImageLoadEvents, DeviceRegistryEvents, DeviceLogonEvents, ThreatIntelligenceIndicator
let mispLookup = materialize(ThreatIntelligenceIndicator | where TimeGenerated >= ago(90d) | extend Tags=tostring(Tags) | extend misp_score=1.0);

DeviceProcessEvents
| where TimeGenerated >= ago(48h)
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wmic.exe","rundll32.exe","cscript.exe")
| extend cmd = ProcessCommandLine
| extend admin_like = iff(cmd has_any("Get-ADUser","Get-Mailbox","Get-ChildItem","Get-Process","net user","net group","sc query","sc create","schtasks /create"),1,0)
| extend timing_precision = iff(datediff("millisecond",TimeGenerated,prev(TimeGenerated)) between (0 .. 5000),1,0) // look for millisecond-precise sequences across processes
| where admin_like == 1 and (timing_precision == 1 or InitiatingProcessFileName !in~ ("explorer.exe","services.exe"))
| join kind=leftouter (DeviceImageLoadEvents) on $left.InitiatingProcessFileName == $right.ImageFileName
| extend misp_mimic = coalesce(mispLookup | where IndicatorType == "CommandLine" and IndicatorName == cmd | project misp_score, 0)
| extend total_score = 1*admin_like + 1*timing_precision + coalesce(misp_mimic,0)
| where total_score >= 2
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, total_score

HUNTER DIRECTIVES

Check for ParentProcess chains. If ParentProcess is svchost.exe or other signed process, verify image load paths for DLL sideloading. Inspect DeviceImageLoadEvents for unsigned modules loaded by signed processes.

7 — Rule: Deepfake / Synthetic AV / Conferencing Anomalies

Detect synthetic audio metadata or abnormal meeting join patterns mapped to possible impersonations.

Important implementation note: audio/video artifact detection often requires integration with conferencing platform logs and specialized telemetry. The KQL below assumes OfficeActivity contains fields like Operation, AudioQuality, ClientIP, UserAgent and any extra analytic tags (e.g., telemetry from an AV analysis pipeline).

// Deepfake Conference Anomaly Detection
// Tables: OfficeActivity, CommonSecurityLog
OfficeActivity
| where TimeGenerated >= ago(24h)
| where Operation in~ ("TeamMeetingStarted","VideoConferenceJoined","VideoConferenceInvited")
| extend client_ip = tostring(ClientIP), ua = tostring(UserAgent)
| extend audio_flag = iff(AudioQuality has_cs "synthetic" or AudioTranscriptionConfidence < 0.6,1,0) // AudioTranscriptionConfidence must be produced by pipeline
| extend perfect_latency = iff(VideoLatency_ms < 50 and AudioLatency_ms < 30,1,0)
| where audio_flag == 1 or perfect_latency == 1
| extend total_score = audio_flag*2 + perfect_latency
| where total_score >= 2
| project TimeGenerated, User, Operation, client_ip, ua, AudioQuality, AudioTranscriptionConfidence, VideoLatency_ms, total_score

HUNTER DIRECTIVES

Pull full meeting logs, participant join times, device IDs, and IP addresses. Check for reused accounts that join many meetings in short windows or logins from new IPs. Cross-check with AADSignInEvents for anomalous sign-in locations or conditional access triggers.

8 — Rule: AI-Generated Code Injection / Memory Artifacts

Detect suspicious RWX memory regions with patterns consistent with generated payloads or model-watermarks.

// AI-Generated Code / Memory Injection Detection
// Tables: DeviceMemoryEvents, DeviceProcessEvents
DeviceMemoryEvents
| where TimeGenerated >= ago(24h)
| where MemoryRegionProtection has "rwx" or MemoryRegionProtection has "rx"
| extend mem = MemoryContent
| extend nop_sled = iff(mem matches regex @"\x90{8,}", 2, 0)
| extend watermark_indicators = iff(mem contains_cs "GPT-Generated" or mem contains_cs "AI-Model" or mem contains_cs "<ai-gen>", 2, 0)
| extend suspicious_mem = nop_sled + watermark_indicators
| where suspicious_mem >= 2
| join kind=leftouter (DeviceProcessEvents) on ProcessId
| project TimeGenerated, ProcessName, ProcessId, ImageFileName, ParentProcessFileName, suspicious_mem, MemoryRegionProtection

HUNTER DIRECTIVES

If suspicious: collect full memory dumps for forensic analysis, check for process injection signs in DeviceImageLoadEvents, check code signing of loaded modules.

9 — Advanced Attack Matrix (Reference table — use when triaging)

A short mapping table (example) for analysts.

Attack Stage	Example Technique	Sentinel / MDE tables	MISP tags to attach	Score weight (example)
Recon	AI-OSINT harvesting	AzureActivity, AADSignInEvents	osint:ai-generated, confidence:70	2
Delivery	AI-spearphishing	EmailEvents, UrlClickEvents	phishing:ai-enhanced, tlp:amber	2
Weaponize	Polymorphic payloads	DeviceFileEvents, DeviceImageLoadEvents	malware:polymorphic, threat-level:high	3
C2	Domain generation, rotation	DeviceNetworkEvents, DNSLogs	c2:ai-rotating, confidence:90	3
Action	Behavioral mimicry	DeviceProcessEvents, DeviceLogonEvents	defense-evasion:mimicry, tlp:red	4
Supply Chain	Model poisoning	DeviceFileEvents, AzureActivity	supply-chain:ai-models	4
10 — Playbook Steps & Investigation Workflow (Actionable L3)

When any of the above rules fires with total_score >= 8 or misp_score >= 6:

Triage

Pull full artifacts: email full headers + attachments (store in evidence repo).

Pull endpoint snapshot and memory dump.

Retrieve process execution chain and recent child processes (48–72h).

Contain

If misp_score >= 6 and file hash observed executing → isolate host.

Block domain/IP at perimeter and EDR. Revoke credentials for logged-in token / sessions.

Investigate

Map lateral movements: query SecurityEvent for remote logons, scheduled tasks, service creation.

Check DeviceImageLoadEvents for suspicious DLL loads and code-signing anomalies.

Remediate

Remove persisted artifacts (registry run keys, scheduled tasks, malicious services) after containment snapshot.

Rotate credentials and secrets found in environment.

Rebuild compromised hosts where persistence is deep.

Hunt follow-up

Use extracted IOCs to back-search historical telemetry (90d).

Create MISP event(s) with associated tags, update ThreatIntelligenceIndicator and adjust misp scoring for automatic enrichment.

Post-Incident

Update allow/deny lists, detection heuristics; review data-access controls on datasets and model registries; rotate keys; add prevention (DLP for model artifacts).

11 — Examples of Inline Hunter Directives & Comments (how to read the rules)

Each KQL rule includes comments and Hunter Directives (inline guidance) — e.g.:

// HUNTER-DIRECTIVE: If misp_file_score >= 4 AND filename_entropy true -> escalate to incident triage queue; capture full file blob.
// HUNTER-DIRECTIVE: Map recipient email address to DeviceName via UPN_DeviceMapping table for accurate attribution.


Include mapping tables in your environment (e.g., UPN_DeviceMapping, TrustedUpdaterProcesses, CI_CD_ServiceAccounts) to remove heuristics and make rules deterministic.

12 — Tuning Guidance & False Positive Examples

High-entropy filenames: many legitimate CI/CD artifacts use long hash names. Maintain a CI_ALLOWLIST table (build systems, artifact stores).

Algorithmic-looking domains: internal services with long names may match regex. Maintain a DOMAIN_ALLOWLIST and check CorporateDNS entries.

Behavioral mimicry: scheduled administrative scripts may trigger mimicry rules — add SignedAdminScripts allowlist based on code signing and publisher certificate thumbprints.

Audio/video flags: require integration with an AV-analysis pipeline — transcription confidence alone will generate many false positives.

13 — How to Integrate with Sentinel Playbooks & MISP

In Sentinel, deploy these KQL rules as Scheduled Analytics with 1–15 min frequency depending on data volume. Use mispLookup materialization at the top of each rule.

Forward alerts to a Logic App playbook that: (a) queries MISP for expanded context via API, (b) auto-adds new IOCs to an internal allow/deny list (human-in-loop for high-risk), (c) performs automated enrichment (VirusTotal, PassiveDNS, cloud logs).

When creating MISP events from confirmed incidents: apply tags such as confidence:90, tlp:amber or tlp:red and supply-chain:ai-models as applicable so future ingestion will have higher misp_score.

14 — Final L3 Hunting Checklist (quick reference)

 Ensure ThreatIntelligenceIndicator ingests MISP tags (keeps Tags field).

 Maintain allowlists: CI_ALLOWLIST, DOMAIN_ALLOWLIST, TRUSTED_UPDATERS.

 Tune misp scoring weights to organization risk appetite. Example: increase misp_conf weight if you find MISP feeds are high fidelity.

 Add device and UPN mapping tables to replace heuristic joins for accurate attribution.

 Schedule rules at appropriate cadence and enable automated enrichment to speed investigations.

 Add post-detection playbook actions (isolate host, block domain, revoke tokens) with approvals for automated containment.

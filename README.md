Aegis-Track: Multi-Node Distributed Edge Detection & Cloud Auditing Architecture

Project Overview

Aegis-Track is an open-source, ultra-lightweight Python automation framework engineered to ingest, parse, and evaluate Linux core authentication telemetry in real-time across resource-constrained endpoints.
In enterprise environments, executing heavyweight, Java-based SIEM software agents at remote edge deployments introduces significant technology risk—specifically resource starvation, memory leaks, and high compute infrastructure costs. Aegis-Track mitigates this risk by serving as a zero-dependency local intrusion detection engine. Operating completely within the Python standard library, the framework maintains an execution profile under 15 MB of RAM while enforcing security control visibility.
To validate control effectiveness across heterogeneous enterprise infrastructure, this project is actively deployed across a distributed physical hardware lab environment comprising multi-generation CPU and cross-platform operating system hypervisors. Telemetry is formatted into structured JSON objects mapping directly to global compliance frameworks and securely streamed out-of-band directly to a cloud log vault, maintaining audit trail immutability against privilege escalation attacks.
Enterprise Architecture & Data Pipeline

The framework isolates compute logic locally at the endpoint while establishing an automated cloud transport layer to decouple detection from centralized storage management:
[ Bare-Metal Node 1 / 2 / 3 ] ──> Runs Rocky Linux 9 Virtual Hypervisor │ ▼ (Continuous Real-Time /var/log/secure Log Aggregation) [ Aegis-Track Execution Engine ] │ ▼ (Pre-compiled Regex Processing & Sliding Window Evaluation) [ Risk Threshold Crossed ] ──> Triggers Automated Critical Triage Hook │ ├──> [ Local File ] Appends JSON Object to local backup (aegis_alerts.json) │ └──> [ Out-of-Band REST ] Signs SigV4 Payload & Streams via HTTPS TLS │ ▼ [ Amazon Web Services (AWS) S3 Cloud Vault ]
1. Ingestion & Dynamic Parsing: The lightweight engine establishes a low-overhead, unbuffered stream reader attached to the system authentication subsystem (/var/log/secure).
2. Deterministic Security Analytics: Pre-compiled regular expressions systematically identify high-velocity anomalous patterns (such as SSH brute-force campaigns or unauthorized local privilege escalations). Sliding time-window arrays accurately isolate sustained attacks from routine human operators.
3. Immutable Out-of-Band Cloud Storage: To fulfill identity governance and auditing verification criteria (NIST SP 800-30 / FFIEC), telemetry must bypass local threat boundaries. Once triggered, the script executes an asynchronous native REST connection directly over HTTPS TLS to an external AWS S3 Bucket, establishing a tamper-proof audit repository out of an adversary's reach.
Laboratory Deployment & Physical Hardware Profile

The multi-node architecture mimics a distributed branch-office deployment model, demonstrating optimization on diverse consumer and enterprise-grade hardware assets:
Node 1: Edge Compute Endpoint (macOS Base)

* Physical Hardware: 2019 MacBook Air (Dual-Core Intel i5 | 8 GB LPDDR3)
* Hypervisor Layer: Oracle VirtualBox running Rocky Linux 9 Core
* Resource Profile: 2 vCPUs | 1.0 GB RAM Allocation | 40 GB Storage
Node 2: Dedicated Legacy Workstation Node (Windows 10 Base)

* Physical Hardware: HP ProDesk 400 G4 SFF (Intel i5-7500 CPU @ 3.40GHz | 8 GB RAM)
* Hypervisor Layer: Oracle VirtualBox running Rocky Linux 9 Core
* Resource Profile: 2 vCPUs | 2.0 GB RAM Allocation | 40 GB Storage (HDD-Backed)
Node 3: High-Throughput Core Node (Windows 11 Base)

* Physical Hardware: HP ProDesk 400 G5 MT (Intel i5-8500 CPU @ 3.00GHz | 8 GB RAM)
* Hypervisor Layer: Oracle VirtualBox running Rocky Linux 9 Core
* Resource Profile: 2 vCPUs | 2.0 GB RAM Allocation | 40 GB Storage (SSD-Backed)
Script Deployment & Local Execution

1. Standalone Execution (Local Mode)

To audit execution metrics locally on any node without cloud-forwarding credentials configured:
sudo python3 aegis_track.py --local-only

2. Production Cloud Architecture Execution

Ensure local system environment profiles possess programmatic IAM permissions (s3:PutObject) prior to starting the production engine:
sudo python3 aegis_track.py

Portfolio Verification Telemetry

(Paste a text block or terminal screenshot from each of your 3 unique hostnames showing the script executing, alongside a screenshot of your AWS S3 bucket showing file outputs organized inside the alerts/Node_Name/ folders here!)
Authorship & Professional Framework Alignments

* Developer: Nicholas Robertson
* Professional Credentials: CompTIA CySA+ | CompTIA Linux+ | CompTIA Security+ | CompTIA Network+ | CompTIA A+
* Framework Mappings: NIST SP 800-30 Risk Assessment, MITRE ATT&CK Framework
[CRITICAL INTERVENTION] [2026-05-16 00:55:23] Target: 192.168.40.25 flagged for SSH Brute Force.
[CRITICAL INTERVENTION] [2026-05-16 01:00:14] Target: 192.168.40.25 flagged for SSH Brute Force.
<img width="553" height="604" alt="terminal-screenshot" src="https://github.com/user-attachments/assets/cf236f20-45ec-4a39-a1c5-4e1234f1d1f5" />

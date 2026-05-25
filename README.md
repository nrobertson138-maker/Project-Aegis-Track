# Aegis-Track: Automated Linux Security Monitor & Cloud Logger

## Project Overview
Aegis-Track is a lightweight, open-source Python tool built to monitor Linux system logins and security events in real time. 

In large companies, running heavy security software on smaller computers or remote office servers can slow them down, use too much memory, and cost a lot of money. Aegis-Track solves this problem. It is designed to run using only the standard tools built into Python, using less than 15 MB of RAM while still keeping your systems safe. 

To prove this tool works on different kinds of systems, I tested it in a physical lab using multiple generations of computer processors and operating systems. The tool takes security logs, turns them into clean JSON files, and securely sends them off-site to a cloud account. This keeps the logs safe from hackers who might try to delete them to hide their tracks.

## How the Data Flows
The tool handles the heavy lifting locally on the computer and automatically sends the data to the cloud:

[ 3 Physical Lab Computers ] ──> Running Rocky Linux 9 Virtual Machines
           │
           ▼ (Monitors /var/log/secure file in real time)
[ Aegis-Track Core Tool ]
           │
           ▼ (Uses Text Matching & Time Windows to catch attacks)
[ Threat Detected ] ──> Triggers Automated Alerts
           ├──> [ Local File ] Saves alert to local backup (aegis_alerts.json)
           └──> [ Cloud Upload ] Encrypts and sends data via HTTPS
                       │
                       ▼
[ Amazon Web Services (AWS) S3 Storage ]

* **Real-Time Monitoring:** The tool watches the Linux login file (`/var/log/secure`) constantly without slowing down the system.
* **Smart Attack Detection:** It uses custom text-matching rules (Regular Expressions) to spot fast attacks, like a hacker trying hundreds of passwords a minute (SSH brute-force). It uses time windows to tell the difference between a real attack and a regular user who just forgot their password.
* **Safe Cloud Storage:** To meet standard financial and IT audit rules (NIST SP 800-30), security records shouldn't be kept where a hacker can reach them. Aegis-Track securely uploads alerts directly to an AWS S3 bucket so they cannot be changed or deleted.

## Lab Setup & Hardware Specs
This setup mimics a company with multiple small branch offices. I tested the tool on three different types of computers:

### Node 1: Laptop Endpoint (macOS Base)
* **Hardware:** 2019 MacBook Air (Dual-Core Intel i5, 8 GB RAM)
* **Virtual Software:** Oracle VirtualBox running Rocky Linux 9
* **Assigned Resources:** 2 vCPUs, 1.0 GB RAM, 40 GB Storage

### Node 2: Older Desktop (Windows 10 Base)
* **Hardware:** HP ProDesk 400 G4 (Intel i5-7500 CPU @ 3.40GHz, 8 GB RAM)
* **Virtual Software:** Oracle VirtualBox running Rocky Linux 9
* **Assigned Resources:** 2 vCPUs, 2.0 GB RAM, 40 GB Storage (Traditional Hard Drive)

### Node 3: Newer Desktop (Windows 11 Base)
* **Hardware:** HP ProDesk 400 G5 (Intel i5-8500 CPU @ 3.00GHz, 8 GB RAM)
* **Virtual Software:** Oracle VirtualBox running Rocky Linux 9
* **Assigned Resources:** 2 vCPUs, 2.0 GB RAM, 40 GB Storage (Fast SSD Drive)

## How to Run the Tool

### Local Mode (No Cloud Setup Needed)
To test the tool and see security alerts on the local screen without setting up AWS cloud access:
```bash
sudo python3 aegis_track.py --local-only


Cloud Mode (Production Setup)
Make sure your computer has the correct AWS permission settings (s3:PutObject) before running the production tool:

### Local Mode (No Cloud Setup Needed)
To test the tool and see security alerts on the local screen without setting up AWS cloud access:
```bash
sudo python3 aegis_track.py --local-only
```

---

* Developer: Nicholas Robertson
* Professional Credentials: CompTIA CySA+ | CompTIA Linux+ | CompTIA Security+ | CompTIA Network+ | CompTIA A+
* Framework Mappings: NIST SP 800-30 Risk Assessment, MITRE ATT&CK Framework
[CRITICAL INTERVENTION] [2026-05-16 00:55:23] Target: 192.168.40.25 flagged for SSH Brute Force.
[CRITICAL INTERVENTION] [2026-05-16 01:00:14] Target: 192.168.40.25 flagged for SSH Brute Force.
<img width="1280" height="800" alt="Image" src="https://github.com/user-attachments/assets/fe6eb814-787d-4eb7-a242-ca8eae854733" />
<img width="720" height="399" alt="Image" src="https://github.com/user-attachments/assets/c6230b6c-c242-48e8-9a3d-44dac9c575f5" />
<img width="859" height="800" alt="Image" src="https://github.com/user-attachments/assets/ce0c076d-c80f-4b7d-814d-4f79e5abd643" />


import streamlit as st
import random

# --- QUESTION DATA (UNCHANGED) ---
malware_questions = [
    {
        "id": 101,
        "field": "Malware Analysis",
        "question": "What is a 'dropper' in malware terminology?",
        "options": ["A malware that deletes files", "A program that installs malware", "A tool for debugging", "A file encryptor"],
        "correct_answer": "A program that installs malware",
        "language_required": "C/C++"
    },
    {
        "id": 102,
        "field": "Malware Analysis",
        "question": "Which Windows tool is useful for monitoring system activity of malware?",
        "options": ["Task Manager", "Procmon", "Regedit", "Explorer"],
        "correct_answer": "Procmon",
        "language_required": "C/C++"
    },
    {
        "id": 103,
        "field": "Malware Analysis",
        "question": "What is the function of a sandbox in malware research?",
        "options": ["To encrypt data", "To run malware in isolation", "To hide IP", "To clean a system"],
        "correct_answer": "To run malware in isolation",
        "language_required": "Python"
    },
    {
        "id": 104,
        "field": "Malware Analysis",
        "question": "What does the tool IDA Pro help with?",
        "options": ["Network sniffing", "Static binary analysis", "File encryption", "Email phishing"],
        "correct_answer": "Static binary analysis",
        "language_required": "C/C++"
    },
    {
        "id": 105,
        "field": "Malware Analysis",
        "question": "What is 'polymorphic malware'?",
        "options": ["Uses a constant signature", "Avoids scanning", "Changes code to avoid detection", "Only affects Linux"],
        "correct_answer": "Changes code to avoid detection",
        "language_required": "C/C++"
    },
    {
        "id": 106,
        "field": "Malware Analysis",
        "question": "Which tool helps analyze malware memory usage?",
        "options": ["Wireshark", "Volatility", "Burp Suite", "sqlmap"],
        "correct_answer": "Volatility",
        "language_required": "Python"
    },
    {
        "id": 107,
        "field": "Malware Analysis",
        "question": "What does PE file stand for?",
        "options": ["Protected Execution", "Program Executable", "Portable Executable", "Platform Emulator"],
        "correct_answer": "Portable Executable",
        "language_required": "C/C++"
    },
    {
        "id": 108,
        "field": "Malware Analysis",
        "question": "Which of these is a behavior-based malware detection tool?",
        "options": ["YARA", "Procmon", "Cuckoo Sandbox", "Ghidra"],
        "correct_answer": "Cuckoo Sandbox",
        "language_required": "Python"
    },
    {
        "id": 109,
        "field": "Malware Analysis",
        "question": "What technique does malware use to prevent reverse engineering?",
        "options": ["Signature-based scanning", "Obfuscation", "Keylogging", "System call tracing"],
        "correct_answer": "Obfuscation",
        "language_required": "C/C++"
    },
    {
        "id": 110,
        "field": "Malware Analysis",
        "question": "Which of the following is used for dynamic malware analysis?",
        "options": ["IDA Pro", "OllyDbg", "Cuckoo", "Radare2"],
        "correct_answer": "Cuckoo",
        "language_required": "Python"
    }
]

pentest_questions = [
    {
        "id": 201,
        "field": "Penetration Testing",
        "question": "Which tool is commonly used for network scanning in penetration testing?",
        "options": ["Wireshark", "Nmap", "John the Ripper", "Snort"],
        "correct_answer": "Nmap",
        "language_required": "Python"
    },
    {
        "id": 202,
        "field": "Penetration Testing",
        "question": "What is the purpose of the Metasploit framework?",
        "options": ["Firewall testing", "Packet analysis", "Exploit development and execution", "Log aggregation"],
        "correct_answer": "Exploit development and execution",
        "language_required": "Ruby"
    },
    {
        "id": 203,
        "field": "Penetration Testing",
        "question": "Which type of testing simulates an attack with zero internal knowledge?",
        "options": ["Black Box", "White Box", "Gray Box", "Regression"],
        "correct_answer": "Black Box",
        "language_required": "N/A"
    },
    {
        "id": 204,
        "field": "Penetration Testing",
        "question": "Which tool is best for password cracking?",
        "options": ["Nikto", "Hydra", "Burp Suite", "Tcpdump"],
        "correct_answer": "Hydra",
        "language_required": "C/C++"
    },
    {
        "id": 205,
        "field": "Penetration Testing",
        "question": "What is the use of Burp Suite in penetration testing?",
        "options": ["Scanning ports", "Sniffing packets", "Intercepting web traffic", "Checking antivirus strength"],
        "correct_answer": "Intercepting web traffic",
        "language_required": "Java"
    },
    {
        "id": 206,
        "field": "Penetration Testing",
        "question": "Which protocol is commonly targeted during wireless penetration testing?",
        "options": ["HTTP", "SSH", "WPA2", "SNMP"],
        "correct_answer": "WPA2",
        "language_required": "Python"
    },
    {
        "id": 207,
        "field": "Penetration Testing",
        "question": "Which scripting language is often used for quick exploit development?",
        "options": ["Perl", "Python", "Bash", "Ruby"],
        "correct_answer": "Python",
        "language_required": "Python"
    },
    {
        "id": 208,
        "field": "Penetration Testing",
        "question": "What does SQL injection target?",
        "options": ["Filesystem", "Network routers", "Databases", "Memory buffers"],
        "correct_answer": "Databases",
        "language_required": "SQL"
    },
    {
        "id": 209,
        "field": "Penetration Testing",
        "question": "Nikto is primarily used for what purpose?",
        "options": ["Port scanning", "Web server vulnerability scanning", "Password cracking", "Network sniffing"],
        "correct_answer": "Web server vulnerability scanning",
        "language_required": "Perl"
    },
    {
        "id": 210,
        "field": "Penetration Testing",
        "question": "What is 'pivoting' in the context of a penetration test?",
        "options": ["Changing user agent", "Gaining root access", "Using one compromised host to attack others", "Logging out attackers"],
        "correct_answer": "Using one compromised host to attack others",
        "language_required": "Python"
    }
]

forensics_questions = [
    {
        "id": 301,
        "field": "Digital Forensics",
        "question": "What does 'chain of custody' refer to in digital forensics?",
        "options": ["User password recovery", "Evidence handling process", "Backup procedure", "Antivirus scan report"],
        "correct_answer": "Evidence handling process",
        "language_required": "N/A"
    },
    {
        "id": 302,
        "field": "Digital Forensics",
        "question": "Which tool is widely used to acquire disk images?",
        "options": ["EnCase", "Autopsy", "Wireshark", "Nmap"],
        "correct_answer": "EnCase",
        "language_required": "N/A"
    },
    {
        "id": 303,
        "field": "Digital Forensics",
        "question": "Which format is commonly used for forensic disk images?",
        "options": ["ISO", "EWF (Expert Witness Format)", "MP4", "PNG"],
        "correct_answer": "EWF (Expert Witness Format)",
        "language_required": "N/A"
    },
    {
        "id": 304,
        "field": "Digital Forensics",
        "question": "Volatility is primarily used to analyze which type of data?",
        "options": ["Logs", "Disk images", "Memory dumps", "Encrypted emails"],
        "correct_answer": "Memory dumps",
        "language_required": "Python"
    },
    {
        "id": 305,
        "field": "Digital Forensics",
        "question": "What does MAC in MAC times stand for?",
        "options": ["Modify, Access, Change", "Move, Alert, Cache", "Monitor, Analyze, Capture", "Memory, Access, Copy"],
        "correct_answer": "Modify, Access, Change",
        "language_required": "N/A"
    },
    {
        "id": 306,
        "field": "Digital Forensics",
        "question": "Which of the following tools is used for forensic analysis of mobile devices?",
        "options": ["FTK", "Oxygen Forensic Detective", "Wireshark", "Ettercap"],
        "correct_answer": "Oxygen Forensic Detective",
        "language_required": "N/A"
    },
    {
        "id": 307,
        "field": "Digital Forensics",
        "question": "What is the first step in a digital forensic investigation?",
        "options": ["Image acquisition", "Report writing", "Data recovery", "Evidence presentation"],
        "correct_answer": "Image acquisition",
        "language_required": "N/A"
    },
    {
        "id": 308,
        "field": "Digital Forensics",
        "question": "Autopsy is a GUI front end for which digital forensic tool?",
        "options": ["Volatility", "The Sleuth Kit", "FTK", "Metasploit"],
        "correct_answer": "The Sleuth Kit",
        "language_required": "Java"
    },
    {
        "id": 309,
        "field": "Digital Forensics",
        "question": "Which hash function is commonly used to verify integrity of evidence?",
        "options": ["MD5", "AES", "RSA", "SHA-1"],
        "correct_answer": "MD5",
        "language_required": "Python"
    },
    {
        "id": 310,
        "field": "Digital Forensics",
        "question": "Which layer of the OSI model does a forensic packet capture tool operate at?",
        "options": ["Layer 1", "Layer 3", "Layer 7", "Layer 2"],
        "correct_answer": "Layer 2",
        "language_required": "N/A"
    }
]

cloud_questions = [
    {
        "id": 401,
        "field": "Cloud Security",
        "question": "Which of the following is a major concern in cloud computing?",
        "options": ["Low storage", "Internet speed", "Data breaches", "File format issues"],
        "correct_answer": "Data breaches",
        "language_required": "N/A"
    },
    {
        "id": 402,
        "field": "Cloud Security",
        "question": "What does IAM stand for in cloud environments?",
        "options": ["Internet Access Manager", "Identity and Access Management", "Internal Account Monitor", "Instance Allocation Module"],
        "correct_answer": "Identity and Access Management",
        "language_required": "Python"
    },
    {
        "id": 403,
        "field": "Cloud Security",
        "question": "Which type of cloud offers the highest level of control and customization?",
        "options": ["Public cloud", "Private cloud", "Hybrid cloud", "Community cloud"],
        "correct_answer": "Private cloud",
        "language_required": "N/A"
    },
    {
        "id": 404,
        "field": "Cloud Security",
        "question": "Which of these cloud providers offers a shared responsibility model?",
        "options": ["AWS", "Google Drive", "Dropbox", "OneDrive"],
        "correct_answer": "AWS",
        "language_required": "Python"
    },
    {
        "id": 405,
        "field": "Cloud Security",
        "question": "What is the primary goal of encryption in cloud services?",
        "options": ["Reduce latency", "Enhance connectivity", "Protect data", "Create backups"],
        "correct_answer": "Protect data",
        "language_required": "Python"
    },
    {
        "id": 406,
        "field": "Cloud Security",
        "question": "Which protocol is commonly used for secure API access in cloud services?",
        "options": ["FTP", "SOAP", "OAuth", "SMTP"],
        "correct_answer": "OAuth",
        "language_required": "Python"
    },
    {
        "id": 407,
        "field": "Cloud Security",
        "question": "What is 'multi-tenancy' in cloud computing?",
        "options": ["Single-user VMs", "Multiple users sharing resources", "Dedicated hardware", "Offline computing"],
        "correct_answer": "Multiple users sharing resources",
        "language_required": "N/A"
    },
    {
        "id": 408,
        "field": "Cloud Security",
        "question": "Which of these helps monitor security compliance in cloud setups?",
        "options": ["AWS Config", "Google Docs", "Docker Hub", "Nmap"],
        "correct_answer": "AWS Config",
        "language_required": "Python"
    },
    {
        "id": 409,
        "field": "Cloud Security",
        "question": "What does a WAF protect in cloud environments?",
        "options": ["Storage services", "Virtual machines", "Web applications", "Network cables"],
        "correct_answer": "Web applications",
        "language_required": "Python"
    },
    {
        "id": 410,
        "field": "Cloud Security",
        "question": "Which of the following is a cloud security best practice?",
        "options": ["Using default passwords", "Disabling MFA", "Encrypting data in transit", "Exposing all ports"],
        "correct_answer": "Encrypting data in transit",
        "language_required": "Python"
    }
]

network_questions = [
    {
        "id": 501,
        "field": "Network Security",
        "question": "What is the main function of a firewall?",
        "options": ["Store data", "Filter network traffic", "Scan emails", "Encrypt hard drives"],
        "correct_answer": "Filter network traffic",
        "language_required": "N/A"
    },
    {
        "id": 502,
        "field": "Network Security",
        "question": "Which protocol is used to securely browse websites?",
        "options": ["HTTP", "FTP", "HTTPS", "SSH"],
        "correct_answer": "HTTPS",
        "language_required": "Python"
    },
    {
        "id": 503,
        "field": "Network Security",
        "question": "Which of the following tools is used for packet capturing?",
        "options": ["Wireshark", "Burp Suite", "Nessus", "Splunk"],
        "correct_answer": "Wireshark",
        "language_required": "C/C++"
    },
    {
        "id": 504,
        "field": "Network Security",
        "question": "What does DDoS stand for?",
        "options": ["Distributed Data of Service", "Dedicated Denial of Service", "Distributed Denial of Service", "Domain Denial of Security"],
        "correct_answer": "Distributed Denial of Service",
        "language_required": "N/A"
    },
    {
        "id": 505,
        "field": "Network Security",
        "question": "What kind of attack involves intercepting communication between two parties?",
        "options": ["Phishing", "DoS", "MITM", "SQL Injection"],
        "correct_answer": "MITM",
        "language_required": "Python"
    },
    {
        "id": 506,
        "field": "Network Security",
        "question": "Which device helps prevent unauthorized access to a network?",
        "options": ["Router", "Modem", "Firewall", "Switch"],
        "correct_answer": "Firewall",
        "language_required": "Python"
    },
    {
        "id": 507,
        "field": "Network Security",
        "question": "What is the purpose of port scanning?",
        "options": ["Email tracking", "Identifying open ports and services", "Data encryption", "Routing traffic"],
        "correct_answer": "Identifying open ports and services",
        "language_required": "Python"
    },
    {
        "id": 508,
        "field": "Network Security",
        "question": "Which command is used to test network connectivity?",
        "options": ["connect", "ping", "traceroute", "firewall-cmd"],
        "correct_answer": "ping",
        "language_required": "Shell"
    },
    {
        "id": 509,
        "field": "Network Security",
        "question": "What does IDS stand for?",
        "options": ["Internet Data System", "Intrusion Detection System", "Internal Device Security", "Information Decryption Server"],
        "correct_answer": "Intrusion Detection System",
        "language_required": "Python"
    },
    {
        "id": 510,
        "field": "Network Security",
        "question": "Which of the following is a commonly used IDS tool?",
        "options": ["Snort", "Git", "Slack", "Terraform"],
        "correct_answer": "Snort",
        "language_required": "C/C++"
    }
]

vmware_questions = [
    {
        "id": 601,
        "field": "VMware Security",
        "question": "What is the primary purpose of VMware Tools?",
        "options": ["Malware scanning", "Improve VM performance and functionality", "Patch VMware vulnerabilities", "Create firewall rules"],
        "correct_answer": "Improve VM performance and functionality",
        "language_required": "N/A"
    },
    {
        "id": 602,
        "field": "VMware Security",
        "question": "Which product allows centralized management of VMware environments?",
        "options": ["vSphere", "vCenter Server", "ESXi", "Workstation"],
        "correct_answer": "vCenter Server",
        "language_required": "N/A"
    },
    {
        "id": 603,
        "field": "VMware Security",
        "question": "Which VMware feature is used for fault tolerance?",
        "options": ["DRS", "vMotion", "HA", "Snapshots"],
        "correct_answer": "HA",
        "language_required": "N/A"
    },
    {
        "id": 604,
        "field": "VMware Security",
        "question": "Which protocol does VMware use for remote console access?",
        "options": ["SSH", "VNC", "VMRC", "RDP"],
        "correct_answer": "VMRC",
        "language_required": "N/A"
    },
    {
        "id": 605,
        "field": "VMware Security",
        "question": "What is a key security concern with VM snapshots?",
        "options": ["Automatic updates", "Large file sizes", "Snapshot sprawl and outdated data", "Script injection"],
        "correct_answer": "Snapshot sprawl and outdated data",
        "language_required": "N/A"
    },
    {
        "id": 606,
        "field": "VMware Security",
        "question": "Which component enforces security hardening on VMware ESXi?",
        "options": ["vShield", "vMotion", "VMTools", "vSAN"],
        "correct_answer": "vShield",
        "language_required": "N/A"
    },
    {
        "id": 607,
        "field": "VMware Security",
        "question": "Which language is typically used to automate VMware tasks via PowerCLI?",
        "options": ["Bash", "Python", "PowerShell", "Go"],
        "correct_answer": "PowerShell",
        "language_required": "PowerShell"
    },
    {
        "id": 608,
        "field": "VMware Security",
        "question": "What is the ESXi lockdown mode used for?",
        "options": ["Disable VMs", "Disable network access", "Restrict remote CLI access to host", "Increase storage"],
        "correct_answer": "Restrict remote CLI access to host",
        "language_required": "N/A"
    },
    {
        "id": 609,
        "field": "VMware Security",
        "question": "Which security measure prevents unauthorized USB device usage in a VM?",
        "options": ["Device Guard", "Virtual Machine Encryption", "USB arbitrator settings", "UAC"],
        "correct_answer": "USB arbitrator settings",
        "language_required": "N/A"
    },
    {
        "id": 610,
        "field": "VMware Security",
        "question": "Which command-line interface is used for direct ESXi management?",
        "options": ["esxcli", "vmcli", "vsh", "esxadmin"],
        "correct_answer": "esxcli",
        "language_required": "Shell"
    }
]

iot_questions = [
    {
        "id": 701,
        "field": "IoT Security",
        "question": "What is the biggest security concern in IoT devices?",
        "options": ["Battery life", "Physical size", "Lack of encryption", "Device branding"],
        "correct_answer": "Lack of encryption",
        "language_required": "Python"
    },
    {
        "id": 702,
        "field": "IoT Security",
        "question": "Which communication protocol is widely used in IoT and has lightweight characteristics?",
        "options": ["HTTP", "FTP", "MQTT", "SMTP"],
        "correct_answer": "MQTT",
        "language_required": "Python"
    },
    {
        "id": 703,
        "field": "IoT Security",
        "question": "Which term refers to updating IoT firmware remotely?",
        "options": ["RTOS", "OTA", "RAT", "MFA"],
        "correct_answer": "OTA",
        "language_required": "C/C++"
    },
    {
        "id": 704,
        "field": "IoT Security",
        "question": "Which of these is a security standard for IoT device authentication?",
        "options": ["WPA2", "TLS", "OAuth 2.0", "IEEE 802.1X"],
        "correct_answer": "IEEE 802.1X",
        "language_required": "C"
    },
    {
        "id": 705,
        "field": "IoT Security",
        "question": "Which attack targets unsecured IoT devices to create a botnet?",
        "options": ["Phishing", "Mirai", "MITM", "Brute force"],
        "correct_answer": "Mirai",
        "language_required": "Python"
    },
    {
        "id": 706,
        "field": "IoT Security",
        "question": "What does Zigbee refer to in IoT?",
        "options": ["Data encryption algorithm", "Wireless communication protocol", "Device ID standard", "Firmware update utility"],
        "correct_answer": "Wireless communication protocol",
        "language_required": "N/A"
    },
    {
        "id": 707,
        "field": "IoT Security",
        "question": "Which is a key security concern when devices are not regularly updated?",
        "options": ["Overheating", "Software bloat", "Vulnerabilities remain unpatched", "Battery issues"],
        "correct_answer": "Vulnerabilities remain unpatched",
        "language_required": "N/A"
    },
    {
        "id": 708,
        "field": "IoT Security",
        "question": "Which Python library is commonly used to communicate with IoT devices over MQTT?",
        "options": ["socket", "paho-mqtt", "mqttlib", "iotkit"],
        "correct_answer": "paho-mqtt",
        "language_required": "Python"
    },
    {
        "id": 709,
        "field": "IoT Security",
        "question": "What does device fingerprinting help with in IoT networks?",
        "options": ["Speed up internet", "User interface design", "Unique identification and access control", "Color calibration"],
        "correct_answer": "Unique identification and access control",
        "language_required": "N/A"
    },
    {
        "id": 710,
        "field": "IoT Security",
        "question": "Which security practice is essential in smart home IoT setups?",
        "options": ["Use default passwords", "Turn off all security protocols", "Enable two-factor authentication", "Always disable firmware updates"],
        "correct_answer": "Enable two-factor authentication",
        "language_required": "N/A"
    }
]

appsec_questions = [
    {
        "id": 801,
        "field": "Application Security",
        "question": "Which attack involves inserting malicious code into a web application via input fields?",
        "options": ["Brute Force", "XSS", "DDoS", "MITM"],
        "correct_answer": "XSS",
        "language_required": "JavaScript"
    },
    {
        "id": 802,
        "field": "Application Security",
        "question": "What is the primary goal of input validation?",
        "options": ["Optimize performance", "Prevent injection attacks", "Create better UI", "Enhance SEO"],
        "correct_answer": "Prevent injection attacks",
        "language_required": "Python"
    },
    {
        "id": 803,
        "field": "Application Security",
        "question": "Which type of injection exploits database queries?",
        "options": ["Shell Injection", "Command Injection", "SQL Injection", "HTML Injection"],
        "correct_answer": "SQL Injection",
        "language_required": "Python"
    },
    {
        "id": 804,
        "field": "Application Security",
        "question": "Which HTTP header is used to prevent clickjacking?",
        "options": ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"],
        "correct_answer": "X-Frame-Options",
        "language_required": "JavaScript"
    },
    {
        "id": 805,
        "field": "Application Security",
        "question": "Which practice ensures sensitive data is unreadable when intercepted?",
        "options": ["Caching", "Obfuscation", "Encryption", "Minification"],
        "correct_answer": "Encryption",
        "language_required": "Python"
    },
    {
        "id": 806,
        "field": "Application Security",
        "question": "Which tool is commonly used to test web applications for security flaws?",
        "options": ["Postman", "Burp Suite", "VS Code", "Fiddler"],
        "correct_answer": "Burp Suite",
        "language_required": "Python"
    },
    {
        "id": 807,
        "field": "Application Security",
        "question": "Which term describes automatic security checks during development?",
        "options": ["DevOps", "Code Analysis", "Static Application Security Testing (SAST)", "CI/CD"],
        "correct_answer": "Static Application Security Testing (SAST)",
        "language_required": "Python"
    },
    {
        "id": 808,
        "field": "Application Security",
        "question": "Which vulnerability allows attackers to execute scripts in another user’s browser?",
        "options": ["CSRF", "SQLi", "XSS", "RFI"],
        "correct_answer": "XSS",
        "language_required": "JavaScript"
    },
    {
        "id": 809,
        "field": "Application Security",
        "question": "Which HTTP method should be avoided for sensitive data in URLs?",
        "options": ["GET", "POST", "PUT", "DELETE"],
        "correct_answer": "GET",
        "language_required": "N/A"
    },
    {
        "id": 810,
        "field": "Application Security",
        "question": "Which OWASP project provides a list of top 10 web application vulnerabilities?",
        "options": ["MITRE", "CWE", "OWASP Top 10", "NIST CSF"],
        "correct_answer": "OWASP Top 10",
        "language_required": "N/A"
    }
]

reverse_engineering_questions = [
    {
        "id": 901,
        "field": "Reverse Engineering",
        "question": "Which tool is commonly used for analyzing binary executables?",
        "options": ["Wireshark", "Burp Suite", "IDA Pro", "Metasploit"],
        "correct_answer": "IDA Pro",
        "language_required": "Assembly"
    },
    {
        "id": 902,
        "field": "Reverse Engineering",
        "question": "What is the primary purpose of a disassembler?",
        "options": ["Obfuscate source code", "Convert source to binary", "Convert binary to assembly", "Patch applications"],
        "correct_answer": "Convert binary to assembly",
        "language_required": "Assembly"
    },
    {
        "id": 903,
        "field": "Reverse Engineering",
        "question": "Which file format is commonly used in Windows for executables?",
        "options": ["ELF", "EXE", "APK", "BIN"],
        "correct_answer": "EXE",
        "language_required": "C/C++"
    },
    {
        "id": 904,
        "field": "Reverse Engineering",
        "question": "Which tool is widely used for dynamic analysis of Windows binaries?",
        "options": ["OllyDbg", "Nmap", "tcpdump", "Nikto"],
        "correct_answer": "OllyDbg",
        "language_required": "C/C++"
    },
    {
        "id": 905,
        "field": "Reverse Engineering",
        "question": "What is the purpose of unpacking in reverse engineering?",
        "options": ["Speed up execution", "Restore obfuscated code", "Compile code", "Add encryption"],
        "correct_answer": "Restore obfuscated code",
        "language_required": "Assembly"
    },
    {
        "id": 906,
        "field": "Reverse Engineering",
        "question": "What is commonly used to inspect the behavior of a program at runtime?",
        "options": ["Debugger", "Decompiler", "Proxy", "Scanner"],
        "correct_answer": "Debugger",
        "language_required": "C"
    },
    {
        "id": 907,
        "field": "Reverse Engineering",
        "question": "Which technique converts compiled code back into a high-level approximation?",
        "options": ["Disassembly", "Linking", "Decompilation", "Encoding"],
        "correct_answer": "Decompilation",
        "language_required": "C/C++"
    },
    {
        "id": 908,
        "field": "Reverse Engineering",
        "question": "Which architecture is associated with x86 assembly?",
        "options": ["ARM", "RISC-V", "Intel", "SPARC"],
        "correct_answer": "Intel",
        "language_required": "Assembly"
    },
    {
        "id": 909,
        "field": "Reverse Engineering",
        "question": "Which of the following best describes a 'string reference' in RE?",
        "options": ["A breakpoint type", "A pointer to hardcoded text data", "A symbol table", "An opcode shortcut"],
        "correct_answer": "A pointer to hardcoded text data",
        "language_required": "Assembly"
    },
    {
        "id": 910,
        "field": "Reverse Engineering",
        "question": "Which open-source tool can be used as an alternative to IDA Pro?",
        "options": ["Wireshark", "Ghidra", "Netcat", "Ettercap"],
        "correct_answer": "Ghidra",
        "language_required": "Java"
    }
]

cryptography_questions = [
    {
        "id": 1001,
        "field": "Cryptography",
        "question": "What is the primary purpose of a cryptographic hash function?",
        "options": ["Encrypt data", "Authenticate users", "Ensure data integrity", "Generate keys"],
        "correct_answer": "Ensure data integrity",
        "language_required": "Python"
    },
    {
        "id": 1002,
        "field": "Cryptography",
        "question": "Which algorithm is asymmetric?",
        "options": ["AES", "RSA", "SHA-256", "MD5"],
        "correct_answer": "RSA",
        "language_required": "Python"
    },
    {
        "id": 1003,
        "field": "Cryptography",
        "question": "Which key length is considered secure for AES encryption?",
        "options": ["56 bits", "128 bits", "512 bits", "2048 bits"],
        "correct_answer": "128 bits",
        "language_required": "Python"
    },
    {
        "id": 1004,
        "field": "Cryptography",
        "question": "What does SSL/TLS primarily provide?",
        "options": ["Data compression", "Secure communication", "Virus scanning", "Network routing"],
        "correct_answer": "Secure communication",
        "language_required": "Python"
    },
    {
        "id": 1005,
        "field": "Cryptography",
        "question": "Which cryptographic method uses the same key for encryption and decryption?",
        "options": ["Asymmetric", "Symmetric", "Hashing", "Digital Signature"],
        "correct_answer": "Symmetric",
        "language_required": "Python"
    },
    {
        "id": 1006,
        "field": "Cryptography",
        "question": "What is a digital signature used for?",
        "options": ["Encrypt files", "Verify authenticity and integrity", "Speed up encryption", "Store keys"],
        "correct_answer": "Verify authenticity and integrity",
        "language_required": "Python"
    },
    {
        "id": 1007,
        "field": "Cryptography",
        "question": "Which library in Python is commonly used for cryptographic operations?",
        "options": ["pycrypto", "scikit-learn", "tensorflow", "requests"],
        "correct_answer": "pycrypto",
        "language_required": "Python"
    },
    {
        "id": 1008,
        "field": "Cryptography",
        "question": "What is a 'nonce' in cryptography?",
        "options": ["A random number used once", "A key generation method", "An encryption algorithm", "A decryption method"],
        "correct_answer": "A random number used once",
        "language_required": "Python"
    },
    {
        "id": 1009,
        "field": "Cryptography",
        "question": "Which of the following is NOT a hashing algorithm?",
        "options": ["SHA-256", "RSA", "MD5", "SHA-1"],
        "correct_answer": "RSA",
        "language_required": "Python"
    },
    {
        "id": 1010,
        "field": "Cryptography",
        "question": "What is the role of a Certificate Authority (CA)?",
        "options": ["Issue digital certificates", "Encrypt data", "Manage firewalls", "Scan for malware"],
        "correct_answer": "Issue digital certificates",
        "language_required": "N/A"
    }
]

# Combine all question lists into one for easier processing
all_questions = (
    malware_questions + pentest_questions + forensics_questions +
    cloud_questions + network_questions + vmware_questions +
    iot_questions + appsec_questions + reverse_engineering_questions +
    cryptography_questions
)

# Create a dictionary to group questions by field and language for efficient lookup
questions_by_field = {}
for q in all_questions:
    field = q["field"]
    if field not in questions_by_field:
        questions_by_field[field] = []
    questions_by_field[field].append(q)

questions_by_language = {}
for q in all_questions:
    lang = q.get("language_required")
    if lang and lang != "N/A":
        if lang not in questions_by_language:
            questions_by_language[lang] = []
        questions_by_language[lang].append(q)

# --- ML-INSPIRED RECOMMENDATION FUNCTION ---
# This function aims to filter questions first based on the user's profile
# and then samples from the *relevant* fields, prioritizing based on past performance.
def get_suggested_questions(user_profile, all_questions, user_performance_data=None, num_questions_to_suggest=10):
    eligible_questions = []
    seen_ids = set()

    course = user_profile.get("course")
    branch = user_profile.get("branch")
    known_languages = user_profile.get("known_languages", [])

    # 1. Determine relevant fields based on course and branch
    relevant_fields = set()

    if course in ["B.Tech", "MCA"]:
        if branch in ["CSE", "IT", "MCA"]:
            relevant_fields.update([
                "Malware Analysis",
                "Penetration Testing",
                "Digital Forensics",
                "Cloud Security",
                "Network Security",
                "Application Security",
                "Reverse Engineering",
                "Cryptography"
            ])
        elif branch in ["ECE", "EEE", "Other"]:
            relevant_fields.update([
                "IoT Security",
                "Network Security",
                # "Embedded Security", # Uncomment if you add Embedded Security questions
                "Malware Analysis"
            ])
    
    # Fallback: If no specific relevant fields are determined by course/branch, consider all fields
    # This ensures we still get questions if a new branch or course type is added without specific mapping.
    if not relevant_fields and (course or branch):
         st.sidebar.warning(f"No specific fields matched for {course} - {branch}. Selecting from all fields based on languages and overall performance.")
         relevant_fields = set(questions_by_field.keys())


    # 2. Prioritize fields based on user performance (if available)
    field_priorities = {} # Higher value means higher priority (e.g., lower performance)
    if user_performance_data and user_performance_data.get("field_total_questions_asked"):
        field_correct_answers = user_performance_data.get("field_correct_answers", {})
        field_total_asked = user_performance_data.get("field_total_questions_asked", {})

        for field in relevant_fields:
            correct = field_correct_answers.get(field, 0)
            total = field_total_asked.get(field, 0)
            if total > 0:
                performance_ratio = correct / total
                # Higher priority for fields with lower performance or fewer questions attempted
                field_priorities[field] = (1.0 - performance_ratio) + (1.0 / (total + 1)) # Add a bonus for less-attempted fields
            else:
                field_priorities[field] = 1.0 # High priority if no questions asked yet in this field
        
        # Sort fields by priority (descending, so higher priority comes first)
        relevant_fields_ordered = [item[0] for item in sorted(field_priorities.items(), key=lambda item: item[1], reverse=True)]
    else:
        # If no performance data, use a simple random ordering of relevant fields
        relevant_fields_ordered = list(relevant_fields)
        random.shuffle(relevant_fields_ordered)


    # 3. Select questions based on prioritized fields and languages
    # This aims to distribute num_questions_to_suggest across prioritized relevant fields.
    questions_per_field_target = max(1, num_questions_to_suggest // len(relevant_fields_ordered)) # Minimum 1 per field
    
    for field in relevant_fields_ordered:
        if len(eligible_questions) >= num_questions_to_suggest:
            break # Stop if we have enough questions

        if field in questions_by_field:
            field_questions = questions_by_field[field]
            
            lang_matched_questions = [q for q in field_questions if q.get("language_required") in known_languages and q["id"] not in seen_ids]
            other_field_questions = [q for q in field_questions if q.get("language_required") not in known_languages and q["id"] not in seen_ids]

            current_field_selections = []
            
            # Decide how many questions to pull from this field based on priority
            num_to_sample_from_field = questions_per_field_target
            if user_performance_data and field in field_priorities:
                if field_priorities[field] > 0.75: # If very high priority (poor performance)
                    num_to_sample_from_field = min(len(field_questions), num_to_sample_from_field + 2) # Get a few more
                elif field_priorities[field] < 0.25: # If very low priority (good performance)
                    num_to_sample_from_field = max(1, num_to_sample_from_field - 1) # Get slightly fewer
            
            # Ensure we don't sample more than available, prioritize language
            num_to_take_lang = min(len(lang_matched_questions), num_to_sample_from_field)
            current_field_selections.extend(random.sample(lang_matched_questions, num_to_take_lang))
            
            needed_from_other = num_to_sample_from_field - len(current_field_selections)
            if needed_from_other > 0:
                num_to_take_other = min(len(other_field_questions), needed_from_other)
                current_field_selections.extend(random.sample(other_field_questions, num_to_take_other))

            for q in current_field_selections:
                if q["id"] not in seen_ids:
                    eligible_questions.append(q)
                    seen_ids.add(q["id"])
    
    # 4. Add questions based *only* on known programming languages (if not already covered)
    # This acts as a secondary filter, picking questions purely based on language knowledge.
    for lang in known_languages:
        if lang in questions_by_language:
            for q in questions_by_language[lang]:
                if q["id"] not in seen_ids and len(eligible_questions) < num_questions_to_suggest:
                    eligible_questions.append(q)
                    seen_ids.add(q["id"])

    # 5. Fallback: If still not enough questions, fill with truly random questions from the entire pool
    if len(eligible_questions) < num_questions_to_suggest:
        remaining_questions = [q for q in all_questions if q["id"] not in seen_ids]
        random.shuffle(remaining_questions)
        needed = num_questions_to_suggest - len(eligible_questions)
        eligible_questions.extend(remaining_questions[:needed])
        for q in remaining_questions[:needed]:
            seen_ids.add(q["id"])

    # Final shuffle to mix questions from different categories/languages for varied presentation
    random.shuffle(eligible_questions)
    return eligible_questions[:num_questions_to_suggest] # Ensure we return exactly the requested number

# Function to score the quiz - now returns total questions asked per field
def score_quiz(questions, user_answers):
    score = 0
    field_scores = {}
    field_total_questions_asked = {} # New: Track total questions asked per field in this quiz

    for q in questions:
        field_total_questions_asked[q["field"]] = field_total_questions_asked.get(q["field"], 0) + 1
        correct = q["correct_answer"]
        user = user_answers.get(q["id"])
        if user == correct:
            score += 1
            field_scores[q["field"]] = field_scores.get(q["field"], 0) + 1
    return score, field_scores, field_total_questions_asked


# Function to recommend a field (unchanged)
def recommend_field(field_scores):
    if not field_scores:
        return "No strong recommendation (not enough answers to specific fields)."
    max_score = max(field_scores.values())
    top_fields = [field for field, score in field_scores.items() if score == max_score]
    return ", ".join(top_fields)


# --- Streamlit App Layout ---

st.set_page_config(page_title="Cybersecurity Quiz", layout="centered")

st.title("Cybersecurity Quiz")
st.write("Welcome to the Cybersecurity Quiz! Please provide some basic details to help us customize your experience.")

# Initialize session state variables
if 'quiz_started' not in st.session_state:
    st.session_state.quiz_started = False
if 'current_question_index' not in st.session_state:
    st.session_state.current_question_index = 0
if 'user_profile' not in st.session_state:
    st.session_state.user_profile = {}
if 'suggested_questions' not in st.session_state:
    st.session_state.suggested_questions = []
if 'user_answers' not in st.session_state:
    st.session_state.user_answers = {}
if 'quiz_finished' not in st.session_state:
    st.session_state.quiz_finished = False
# NEW: Store user's aggregated performance data for ML-inspired recommendations
if 'user_performance_data' not in st.session_state:
    st.session_state.user_performance_data = {
        "field_correct_answers": {},
        "field_total_questions_asked": {}
    }

# Sidebar for user profile input
st.sidebar.header("Your Profile")

courses = ["B.Tech", "MCA"]
user_course = st.sidebar.selectbox("Which course are you pursuing?", courses, key="course_select")

user_branch = "N/A"
if user_course == "B.Tech":
    branches = ["CSE", "IT", "ECE", "EEE", "Other"]
    user_branch = st.sidebar.selectbox("Which branch are you in (for B.Tech)?", branches, key="branch_select")
elif user_course == "MCA":
    user_branch = "MCA" # Treat MCA as a branch for question logic

all_available_languages = sorted(list(set(q["language_required"] for q in all_questions if q.get("language_required") and q["language_required"] != "N/A")))
user_known_languages_selected = st.sidebar.multiselect(
    "Which programming languages do you know?",
    all_available_languages,
    key="languages_multiselect"
)
user_known_languages = user_known_languages_selected # Directly use selected languages

# Adjustable number of questions for the quiz
quiz_total_questions = st.sidebar.slider("Number of questions in this quiz:", min_value=10, max_value=len(all_questions), value=20, step=5)


# Store profile in session state when button is clicked
if st.sidebar.button("Save Profile and Start Quiz"):
    st.session_state.user_profile = {
        "course": user_course,
        "branch": user_branch,
        "known_languages": user_known_languages
    }
    # Pass user_performance_data to influence question selection for this quiz
    st.session_state.suggested_questions = get_suggested_questions(
        st.session_state.user_profile,
        all_questions,
        user_performance_data=st.session_state.user_performance_data, # Pass existing performance
        num_questions_to_suggest=quiz_total_questions # Use adjustable total questions
    )
    st.session_state.user_answers = {}
    st.session_state.current_question_index = 0 # Reset index
    st.session_state.quiz_started = True
    st.session_state.quiz_finished = False
    st.rerun()

if st.session_state.quiz_started and not st.session_state.quiz_finished:
    if not st.session_state.suggested_questions:
        st.warning("No questions could be suggested based on your profile and language selections. Please adjust your profile or try again.")
        if st.button("Back to Profile Setup"):
            st.session_state.quiz_started = False
            st.rerun()
    else:
        current_question = st.session_state.suggested_questions[st.session_state.current_question_index]
        
        st.header(f"Question {st.session_state.current_question_index + 1}/{len(st.session_state.suggested_questions)}")
        st.write(f"**Field:** {current_question['field']}")

        with st.form(key=f'question_form_{current_question["id"]}'):
            st.markdown(f"**Question:** {current_question['question']}")
            
            current_answer = st.session_state.user_answers.get(current_question["id"])
            current_index = None
            if current_answer in current_question["options"]:
                current_index = current_question["options"].index(current_answer)

            user_choice = st.radio(
                "Select your answer:",
                current_question["options"],
                key=f"radio_{current_question['id']}",
                index=current_index
            )
            
            if user_choice:
                st.session_state.user_answers[current_question["id"]] = user_choice

            col1, col2 = st.columns(2)
            with col1:
                if st.form_submit_button(label='Next Question'):
                    if current_question["id"] in st.session_state.user_answers:
                        st.session_state.current_question_index += 1
                        if st.session_state.current_question_index >= len(st.session_state.suggested_questions):
                            st.session_state.quiz_finished = True
                        st.rerun()
                    else:
                        st.warning("Please select an answer before proceeding.")

            with col2:
                if st.session_state.current_question_index == len(st.session_state.suggested_questions) - 1:
                    if st.form_submit_button(label='Finish Quiz'):
                         if current_question["id"] in st.session_state.user_answers:
                            st.session_state.quiz_finished = True
                            st.rerun()
                         else:
                            st.warning("Please select an answer for the last question before finishing.")

elif st.session_state.quiz_finished:
    st.header("Quiz Results")
    total_score, field_scores, field_total_questions_asked = score_quiz(st.session_state.suggested_questions, st.session_state.user_answers)

    st.success(f"Your Total Score: {total_score}/{len(st.session_state.suggested_questions)}")

    st.subheader("Field-wise Scores:")
    if field_scores:
        # Update user_performance_data with results from the just-completed quiz
        # This is the "learning" part: updating historical performance
        for field, score in field_scores.items():
            st.session_state.user_performance_data["field_correct_answers"][field] = \
                st.session_state.user_performance_data["field_correct_answers"].get(field, 0) + score
        
        for field, total_asked in field_total_questions_asked.items():
            st.session_state.user_performance_data["field_total_questions_asked"][field] = \
                st.session_state.user_performance_data["field_total_questions_asked"].get(field, 0) + total_asked

        # Display performance for the current quiz
        for field, score in field_scores.items():
            max_for_field = field_total_questions_asked.get(field, 0)
            if max_for_field > 0:
                st.write(f" - {field}: {score}/{max_for_field} correct")
            else:
                st.write(f" - {field}: {score} correct (No questions from this field in this quiz)")
        
        st.subheader("Aggregated Performance Across Quizzes:")
        if st.session_state.user_performance_data["field_total_questions_asked"]:
            for field, total_asked in st.session_state.user_performance_data["field_total_questions_asked"].items():
                correct = st.session_state.user_performance_data["field_correct_answers"].get(field, 0)
                if total_asked > 0:
                    st.write(f" - {field}: {correct}/{total_asked} correct (Overall)")
        else:
            st.write("No aggregated performance data yet.")

    else:
        st.write("No field-specific scores to display for this quiz.")


    recommended = recommend_field(field_scores) # Still recommends based on current quiz
    st.markdown(f"**Based on your answers in this quiz, we recommend: {recommended}**")

    # Option to restart the quiz
    if st.button("Start New Quiz"):
        st.session_state.quiz_started = False
        st.session_state.quiz_finished = False
        st.session_state.user_profile = {} # Consider if you want to keep profile for new quiz or re-ask
        st.session_state.suggested_questions = []
        st.session_state.user_answers = {}
        st.session_state.current_question_index = 0
        # user_performance_data is RETAINED here, so the "model" uses it for next quiz
        st.rerun()
elif not st.session_state.quiz_started:
    st.info("Please fill your profile details in the sidebar and click 'Save Profile and Start Quiz' to begin.")
---
title: "CyberDefenders: Sysinternals Write-up"
date: 2025-09-20 22:42:00
categories: [CyberDefenders, Disk Forensics]
tag: [Endpoint Forensics]
author: Aisha
---

## Introduction

**Challenge Link:** [Sysinternals](https://cyberdefenders.org/blueteam-ctf-challenges/sysinternals/)

Conduct endpoint forensic analysis to detect, analyze, and understand malware infections using disk images, registry artifacts, and threat intelligence. **Tool used:**

- [FTK Imager](https://www.exterro.com/ftk-product-downloads/ftk-imager-4-7-3-81) or Autopsy: To analyze the disk image (.`E01`)
- [AmcacheParser](https://ericzimmerman.github.io/#!index.md): To parse Amcache.hve file.
- [Timeline Explorer](https://ericzimmerman.github.io/#!index.md): To view CSV files.

## Q&A

**Q1. What was the malicious executable file name that the user downloaded?**

Upon inspecting the Downloads folder under the Public user, we found two files

- desktop.ini: This file is a Windows system file that stores configuration settings for the folder in which it is located, such as custom icons, view options, and display names.
- SysInternals.exe: This one is suspicious.

![Alt](/images/Sysinternals/1.webp)

The real [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) is a suite developed by Microsoft that contains a collection of technical utilities and resources used to diagnose, troubleshoot, and monitor Windows system environments, not a single executable file.

---

**Q2. When was the last time the malicious executable file was modified?**

The time the suspicious executable was modified is `November 15, 2022, at 9:18:51 PM`.

![Alt](/images/Sysinternals/2.webp)

The question expects the date to be in 24-hour format `2022-11-15 21:18`

---

**Q3. What is the SHA1 hash value of the malware?**

You can export the file hash from the FTK Imager by right-clicking on the file, but as you can see in the hex viewer of the `sysInternals.exe`file, all the content contains zeros. This indicates that the file may have been tampered with or deleted before the disk capture, rendering direct hashing ineffective.

![Alt](/images/Sysinternals/3.webp)

Thus, we will use an alternative tool, **AmchacheParser**. This tool parses the `Amchache.hive` file, which is a registry file that stores the metadata information of executed applications that have been executed on the system. 

```powershell
PS C:\Users\aisha\AmcacheParser> .\AmcacheParser.exe -f ..\..\Defenders\Amcache.hve --csv 'C:\Users\aisha\Defenders'
AmcacheParser version 1.5.2.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/AmcacheParser

Command line: -f ..\..\Defenders\Amcache.hve --csv C:\Users\aisha\Defenders

Warning: Administrator privileges not found!

C:\Users\aisha\Defenders\Amcache.hve is in new format!

Total file entries found: 36
Total device containers found: 4
Total device PnPs found: 83

Found 36 unassociated file entry

Results saved to: C:\Users\aisha\Defenders

Total parsing time: 0.318 seconds
```

To view the CSV file, open **TimeExplorer** and open the file called `Amcache_UnassociatedFileEntries.csv` Then look for the suspicious binary we found in the Downloads folder. 

![Alt](/images/Sysinternals/3-2.webp)

SHA1 hash:

```powershell
fa1002b02fc5551e075ec44bb4ff9cc13d563dcf
```

---

**Q4. Based on the Alibaba vendor, what is the malware's family?**

Perform a hash lookup in Virustotal using the hash we identified from the previous task. 

![Alt](/images/Sysinternals/4.webp)

The suspicious executable is flagged as malicious malware, categorized as Trojan, and the family label assigned is **Rozena.** According to this [source](https://know.netenrich.com/threatintel/malware/Rozena), **Rozena's** family is a Trojan that opens a back door on the compromised computer to download and install additional malware.

---

**Q5. What is the first mapped domain's Fully Qualified Domain Name (FQDN)?**

We can find this in the Relations tab

![Alt](/images/Sysinternals/5.webp)

The first mapped domain is 

```
www[.]malware430[.]com
```

---

**Q6. The mapped domain is linked to an IP address. What is that IP address?**

Investigate the PowerShell logs to view if any unauthorized activities were executed to alter the network configuration or redirect traffic.  The PowerShell command history file is located under this directory: 

`Users\IEUser\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine`

![Alt](/images/Sysinternals/6.webp)

These two commands were used to modify the `hosts`file configuration to redirect requests sent from these two domains to the same IP address “192.168.15.10”

```powershell
Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`n192.168.15.10`twww.malware430.com" -Force
Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`n192.168.15.10`twww.sysinternals.com" -Forc
```

This is a common technique used by the attacker to reroute legitimate traffic to malicious servers. 

---

**Q7. What is the name of the executable dropped by the first-stage executable?**

To identify the executable dropped by the first-stage malware, view the Behaviour tab in Virustotal 

![Alt](/images/Sysinternals/7.webp)

Under the Process and service actions, we can see that upon the execution of the malware `SysInternals.exe` It spawns a command prompt that installs a secondary executable named `vmtoolsIO.exe` and configure a new service called `VMwareIOHelperService`  that will be started automatically. 

---

**Q8. What is the name of the service installed by 2nd stage executable?**

Based on this command, we found from the previous task

```powershell
"C:\Windows\System32\cmd.exe" /C c:\Windows\vmtoolsIO.exe -install && net start VMwareIOHelperService && sc config VMwareIOHelperService start= auto
```

The next service installed and configured to start automatically is →  `VMwareIOHelperService`

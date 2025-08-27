---
title: "TryHackMe: Atomic Bird Goes Purple #1 Writeup"
date: 2025-08-27 12:11:00
categories: [TryHackMe, SOC Level 2]
tag: [Threat Emulation, Purple Teaming, Atomic Red Team]
author: Aisha
---

## Introduction

Challenge Link: 
[Atomic Bird Goes Purple #1](https://tryhackme.com/room/atomicbirdone)

This room enhances Purple Team exercises by moving beyond basic/default approaches through real-life threat emulation and detection engineering scenarios.

**Key Focus:**

- Practical application of threat emulation skills in realistic scenarios
- Hands-on purple teaming exercises blending attack (Red) and defense (Blue) perspectives
- Hunting adversarial tactics using real-world tools (Aurora EDR, Sysmon, Security)

**Approach:**

- Execute tests and immediately investigate logs, system changes, and artifacts
- Analyze directories, registries, and event logs for detection opportunities
- Experimental testing to overcome lack of available malicious source code

**Technique Emulation :**

- **Task-1:** Execution, Discovery, Collection ([T1056.002](https://attack.mitre.org/techniques/T1056/002/), [T1059](https://attack.mitre.org/techniques/T1059/), [T1082](https://attack.mitre.org/techniques/T1082/))
- **Task-2:**  Lateral Movement ([T1091](https://attack.mitre.org/techniques/T1091/))
- **Task-3:** Collection ([T1115](https://attack.mitre.org/techniques/T1115/))

## Tools and Hints

**Toolset and Hints**

- Windows Event Viewer
- Windows Registry Editor
- Custom Atomic Red Team Module
- "THM-Utils" Powershell module
- PowerShell
- [sys-field-filter](https://github.com/aisha-x/Windows-Event-Parser/tree/main/sys-field-filter), [sec-field-filter module](https://github.com/aisha-x/Windows-Event-Parser/tree/main/sec-field-filter) → This is optional; it assists in parsing Windows events.

### THM Usage:

TryHackMe provided a wonderful module that summarizes the logs, saving significant time during investigations. I've uploaded the module [here](https://github.com/aisha-x/THM/tree/main/Rooms/SOC%20Level%202/Threat-Emulation/THM-Utils) for reference.

```powershell
 _____________________________________________________________________________________________
|        THM-Utils Commands                 |                     Result                      |
|___________________________________________|_________________________________________________|
|   THM-LogClear-All  ---------------------> Clears all logs in the system.                   |
|   THM-LogStats-All  ---------------------> Application, Security, System, PowerShell,       |
|                   |contd   --------------> PowerShell Operational and Sysmon logs stats     |
|   THM-LogStats-Application --------------> Summary of Application logs. (NO Aurora!)        |
|   THM-LogStats-Aurora -------------------> Summary of Aurora agent logs.                    |
|   THM-LogStats-Flag  --------------------> Gives the flag for the question.                 |
|   THM-LogStats-PowerShell  --------------> Summary of PowerShell logs.                      |
|   THM-LogStats-Powershell-Operational ---> Summary of PowerShell Operational logs.          |
|   THM-LogStats-Security -----------------> Summary of Security logs.                        |
|   THM-LogStats-Sysmon -------------------> Summary of Sysmon logs.                          |
|   THM-LogStats-System -------------------> Summary of System logs.    
```

THM-Utils location in the virtual machine:

```powershell
PS C:\Users\Administrator> (Get-Command THM-LogStats-PowerShell).Source
THM-Utils
PS C:\Users\Administrator> (Get-Module THM-Utils).path
C:\Windows\system32\WindowsPowerShell\v1.0\Modules\THM-Utils\THM-Utils.psm1
```

However, while THM-Utils provides excellent summaries, it doesn't show detailed log entries. This requires writing complex filter commands each time you need to parse specific logs. To address this, I created a PowerShell module that selects relevant fields of interest and allows built-in filtering for more efficient log analysis. Check the modules [here](https://github.com/aisha-x/Windows-Event-Parser/tree/main),

### sys-field-filter, sec-field-filter Usage

Again, this is optional, but if you want to use it, create two folders for `sec-field-filter` and `sys-field-filter` module under this location  `C:\Users\Administrator\Documents\WindowsPowerShell\Modules\` . Since there is no internet connection on the provided machine, you will have to copy the script and paste it into Windows PowerShell ISE, and save it as `.psm1`.

![Alt](/images/Atomic-1/upload-module.webp)

Then import the modules.

```powershell
# Security
import-module sec-field-filter -Force

# Sysmon
import-module sys-field-filter -Force
```

All the functions support one parameter `-FilterMessage` which is a message-based filtering.

Check the supported functions and usage [here](https://github.com/aisha-x/Windows-Event-Parser/tree/main)

### Atomic Red Team Usage

```powershell
 _______________________________________________________________________________________________________________________
|        Atomic Red Team Command                 |                Result                                                |
|________________________________________________|______________________________________________________________________|
|   help Invoke-AtomicTest   ------------------------> Shows the default help page.                                     |
|   Invoke-AtomicTest All -ShowDetailsBrief ---------> Lists all tests.                                                 |
|   Invoke-AtomicTest T0000-1  ----------------------> Executes 1st test case of the T0000-1 technique.                 |
|   Invoke-AtomicTest T0000-1 -Cleanup --------------> Removes the artefacts and restores the modified files (if any!). |        
|_______________________________________________________________________________________________________________________|
```

### AuroraAgent Service

Before going through the tasks, ensure the Aurora service is running. 

```powershell
PS C:\Users\Administrator> aurora-agent-64.exe --status
could not query aurora agent status: could not connect to aurora agent, please verify that it is running and that your --agent-name setting is correct
If you installed Aurora previously, but the service stopped, you can start it using sc.exe start aurora-agent
PS C:\Users\Administrator> sc.exe start aurora-agent

SERVICE_NAME: aurora-agent
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 4724
        FLAGS              :
        
        
PS C:\Users\Administrator> sc.exe qc "aurora-agent"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: aurora-agent
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : "C:\Program Files\Aurora-Agent\aurora-agent-64.exe" --service --config "C:\Program Files\Aurora-Agent\agent-config.yml"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Aurora Agent
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem       
```

In my case, the service wasn’t running. I solved this by changing the path pointing to the licence from `agent-config.yml` file, and I also changed the machine time to Dec 18, 2023. Then started the service from **services.msc.**

![Alt](/images/Atomic-1/lic.webp)

## Task-1: Execute, Investigate, Detect

### Attacker Simulation:

The exercise simulates an attacker who:

- **Discovers:** Performs initial system reconnaissance to gather information about the environment, inspired by technique [**T1082**](https://attack.mitre.org/techniques/T1082/) (System Information Discovery).
- **Captures:** Attempts to steal credentials through GUI input prompts, inspired by technique [**T1056.002**](https://attack.mitre.org/techniques/T1056/002/) (Input Capture: GUI Input Capture).
- **Executes:** Runs commands on the system, including failed execution attempts to test detection capabilities.
- The goal is to evaluate artifacts generated from system discovery, credential prompts, and command execution activities.

### Test T0004-1: Initial Enumeration Emulation

Run the test 

```powershell
Invoke-AtomicTest T0004-1
```

Check Sysmon:

```powershell
PS C:\Program Files\Aurora-Agent> THM-LogStats-Sysmon

|#|#|#|#|#| SYSMON Log Statistics |#|#|#|#|#|

Count Sysmon ID Task Category
----- --------- -------------
    9         1 Process Create (rule: ProcessCreate)
    4        11 File created (rule: FileCreate)

```

```powershell
PS C:\Program Files\Aurora-Agent> sys-processCreation -FilterMessage "systeminfo"
=== Sysmon Event ID 1: Process creation ===

UtcTime           : 2023-12-26 10:19:34.883
Image             : C:\Windows\System32\findstr.exe
ProcessId         : 2372
CommandLine       : "C:\Windows\system32\findstr.exe" /B "/C:Host Name" "/C:OS Name" "/C:OS Version" "/C:System Type"
                    /C:Hotfix(s)
ParentProcessId   : 3944
ParentCommandLine : "powershell.exe" & {systeminfo | findstr /B /C:\""Host Name\"" /C:\""OS Name\"" /C:\""OS
                    Version\"" /C:\""System Type\"" /C:\""Hotfix(s)\"" >
                    C:\Users\Administrator\Desktop\Task-Result.txt}

UtcTime           : 2023-12-26 10:19:28.707
Image             : C:\Windows\System32\systeminfo.exe
ProcessId         : 4568
CommandLine       : "C:\Windows\system32\systeminfo.exe"
ParentProcessId   : 3944
ParentCommandLine : "powershell.exe" & {systeminfo | findstr /B /C:\""Host Name\"" /C:\""OS Name\"" /C:\""OS
                    Version\"" /C:\""System Type\"" /C:\""Hotfix(s)\"" >
                    C:\Users\Administrator\Desktop\Task-Result.txt}

UtcTime           : 2023-12-26 10:19:28.184
Image             : C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
ProcessId         : 4400
CommandLine       : "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths
                    @"C:\Users\Administrator\AppData\Local\Temp\2\np4p3ca0\np4p3ca0.cmdline"
ParentProcessId   : 3944
ParentCommandLine : "powershell.exe" & {systeminfo | findstr /B /C:\""Host Name\"" /C:\""OS Name\"" /C:\""OS
                    Version\"" /C:\""System Type\"" /C:\""Hotfix(s)\"" >
                    C:\Users\Administrator\Desktop\Task-Result.txt}

UtcTime           : 2023-12-26 10:19:27.347
Image             : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ProcessId         : 3944
CommandLine       : "powershell.exe" & {systeminfo | findstr /B /C:\""Host Name\"" /C:\""OS Name\"" /C:\""OS
                    Version\"" /C:\""System Type\"" /C:\""Hotfix(s)\"" >
                    C:\Users\Administrator\Desktop\Task-Result.txt}
ParentProcessId   : 4032
ParentCommandLine : -
```

The script enumerated system information and saved the output to the desktop folder. 

```powershell
PS C:\Users\Administrator> type C:\Users\Administrator\Desktop\Task-Result.txt
Host Name:                 ATOMICBIRD
OS Name:                   Microsoft Windows Server 2019 Datacenter
OS Version:                10.0.17763 N/A Build 17763
System Type:               x64-based PC
Hotfix(s):                 27 Hotfix(s) Installed.
PS C:\Users\Administrator>
```

### Test 10004-2: Credential Prompt Emulation

This test simulates the User Account Control (UAC) prompt that appears when a program requires elevated privileges. This type of prompt can be used to collect credentials

![Alt](/images/Atomic-1/UAC.webp)

```powershell
PS C:\Program Files\Aurora-Agent> sys-processCreation -FilterMessage "src.ps1"
=== Sysmon Event ID 1: Process creation ===

UtcTime           : 2023-12-26 10:24:32.971
Image             : C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
ProcessId         : 3948
CommandLine       : "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths
                    @"C:\Users\Administrator\AppData\Local\Temp\2\bqewnhcw\bqewnhcw.cmdline"
ParentProcessId   : 3048
ParentCommandLine : "powershell.exe" & {C:\AtomicRedTeam\atomics\T0004\src.ps1}

UtcTime           : 2023-12-26 10:24:32.303
Image             : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ProcessId         : 3048
CommandLine       : "powershell.exe" & {C:\AtomicRedTeam\atomics\T0004\src.ps1}
ParentProcessId   : 4032
ParentCommandLine : -
```

### Test T0004-3: Failed command emulation

Test the detection capabilities of failed command execution.

```powershell
PS C:\Users\Administrator> Invoke-AtomicTest T0004-3
..
PS C:\Users\Administrator> THM-LogStats-Sysmon

|#|#|#|#|#| SYSMON Log Statistics |#|#|#|#|#|

Count Sysmon ID Task Category
----- --------- -------------
  270         1 Process Create (rule: ProcessCreate)
   12        11 File created (rule: FileCreate)
```

Check the process creation

```powershell
PS C:\> sys-processCreation | Sort-Object UtcTime -Descending
=== Sysmon Event ID 1: Process creation ===

UtcTime           : 2023-12-26 13:20:43.050
Image             : C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe
ProcessId         : 2204
CommandLine       : C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86
                    "/OUT:C:\Users\ADMINI~1\AppData\Local\Temp\2\RESFFE1.tmp"
                    "c:\Users\Administrator\AppData\Local\Temp\2\gza5431k\CSCFF84DF2B292844F2A7281341F1F9A4DB.TMP"
ParentProcessId   : 4456
ParentCommandLine : "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths
                    @"C:\Users\Administrator\AppData\Local\Temp\2\gza5431k\gza5431k.cmdline"

UtcTime           : 2023-12-26 13:20:42.960
Image             : C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
ProcessId         : 4456
CommandLine       : "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths
                    @"C:\Users\Administrator\AppData\Local\Temp\2\gza5431k\gza5431k.cmdline"
ParentProcessId   : 620
ParentCommandLine : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden -Command
                    "<!bin/bash>"

UtcTime           : 2023-12-26 13:20:42.096
Image             : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ProcessId         : 620
CommandLine       : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden -Command
                    "<!bin/bash>"
ParentProcessId   : 908
ParentCommandLine : "powershell.exe" & {Start-Process powershell.exe -ArgumentList \""-WindowStyle Hidden -Command
                    `\""<!bin/bash>`\""\""}
```

## Task-2: Universal Suspicious Share

### Attacker Simulation:

The exercise simulates an attacker who:

- **Spreads Malware:** Uses removable media or network shares to replicate and distribute malicious files across systems, inspired by technique [**T1091**](https://attack.mitre.org/techniques/T1091/) (Replication Through Removable Media).
- **Manipulates Files:** Modifies, copies, or creates files on shared drives to establish persistence, exfiltrate data, or move laterally.
- The goal is to mimic common ransomware or worm behaviors that leverage shared resources to propagate across a network.

### Test T0005-1: Universal Suspicious Share

To test the manipulation of files, we first need to save the hash value of the target file

```powershell
PS C:\Users\Administrator> ls S:\

    Directory: S:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/24/2023  11:39 AM          78422 Company certificate.docx
-a----        4/20/2023   1:25 PM            880 Donation_call.txt
-a----        4/24/2023  11:36 AM         286589 Invoice with finance charge.xlsx
-a----        4/24/2023  11:32 AM         530681 Minimum Hardware Requirements for Windows 11.pdf
-a----        4/24/2023  11:35 AM          20458 Online Sales Tracker.xlsx
-a----        4/24/2023  11:32 AM         279342 Windows_Server_2019_Feature_Comparison_Guide_EN_US.pdf

PS C:\Users\Administrator> Get-FileHash S:\Donation_call.txt

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          3CA9FB42ACF0A347BDFDC78E0435331BC458194E4BC7FBFFB255BC4CF02CDC1A       S:\Donation_call.txt

PS C:\Users\Administrator>
```

Now run the test

```powershell
Invoke-AtomicTest T0005 -TestNumbers 1 
```

The Security log will log file access attempts.

```powershell
PS C:\> THM-LogStats-Security

|#|#|#|#|#| SECURITY Log Statistics |#|#|#|#|#|

Count Event ID Task Category
----- -------- -------------
    7     4663 File System
    6     4688 Process Creation
    1     1102 Log clear
```

Filtering for security event ID 4663 → An attempt was made to access an object

```powershell
PS C:\> sec-FileAccess
=== Security Event ID 4663: An attempt was made to access an object ===

TimeCreated    : 12/26/2023 1:27:54 PM
SubjectAccount : Administrator
SubjectDomain  : ATOMICBIRD
ObjectType     : File
ObjectName     : S:\Donation_call.txt
ProcessID      : 256
ProcessName    : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
AccessesMask   : 4048
AccessRights   : FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES

TimeCreated    : 12/26/2023 1:27:54 PM
SubjectAccount : Administrator
SubjectDomain  : ATOMICBIRD
ObjectType     : File
ObjectName     : S:\Donation_call.txt
ProcessID      : 4
ProcessName    : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
AccessesMask   : 4048
AccessRights   : FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES

TimeCreated    : 12/26/2023 1:27:54 PM
SubjectAccount : Administrator
SubjectDomain  : ATOMICBIRD
ObjectType     : File
ObjectName     : S:\Donation_call.txt
ProcessID      : 2
ProcessName    : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
AccessesMask   : 4048
AccessRights   : FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES

TimeCreated    : 12/26/2023 1:27:54 PM
SubjectAccount : Administrator
SubjectDomain  : ATOMICBIRD
ObjectType     : File
ObjectName     : S:\Donation_call.txt
ProcessID      : 128
ProcessName    : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
AccessesMask   : 4048
AccessRights   : FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES

TimeCreated    : 12/26/2023 1:27:54 PM
SubjectAccount : Administrator
SubjectDomain  : ATOMICBIRD
ObjectType     : File
ObjectName     : S:\Donation_call.txt
ProcessID      : 65536
ProcessName    : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
AccessesMask   : 4048
AccessRights   : FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES
```

The process PowerShell.exe accessed the file `S:\Donation_call.txt`  with access rights Read and Write. Now, check if the file has been modified by recalculating the hash value of the target file. 

```powershell
PS C:\Users\Administrator> Get-FileHash S:\Donation_call.txt

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          626DBB861DCFF600DABEFCE7BF93F2C72C0F6462CC5729B963FC8242D7D43990       S:\Donation_call.txt
```

Compared to the first hash value, it is clear that the file has been tampered with.

## Task-3: Dump and Go

### Attacker Simulation:

The exercise simulates an attacker who:

- **Steals Data:** Captures sensitive information from clipboard history, inspired by technique [**T1115**](https://attack.mitre.org/techniques/T1115/) (Clipboard Data).
- **Hijacks System Files:** Modifies critical system files to enable Man-in-the-Middle (MITM) attacks, data exfiltration, and evasion of security products.
- The goal is to demonstrate how attackers can abuse legitimate system functions and file operations to steal data and bypass defenses.

### Test T0006-1:  History dump

This test simulates clipboard and command-line data theft

```powershell
PS C:\Users\Administrator> Invoke-AtomicTest T0006 -TestNumbers 1 -ShowDetails
PathToAtomicsFolder = C:\AtomicRedTeam\atomics

[********BEGIN TEST*******]
Technique: TEST T0006
Atomic Test Name: TASK-6.1 History dump
Atomic Test Number: 1
Atomic Test GUID: 9c8d5a72-9c98-48d3-b9bf-da2cc43bdf52
Description: Data dump for exfiltration

Attack Commands:
Executor: powershell
ElevationRequired: False
Command:
C:\AtomicRedTeam\atomics\T0006\dmp.ps1

Cleanup Commands:
Command:
C:\AtomicRedTeam\atomics\T0006\restore-hst.ps1
[!!!!!!!!END TEST!!!!!!!]

```

Run the test and check the Security logs

```powershell
PS C:\> THM-LogStats-Security

|#|#|#|#|#| SECURITY Log Statistics |#|#|#|#|#|

Count Event ID Task Category
----- -------- -------------
    6     4688 Process Creation
    5     4663 File System
    1     1102 Log clear
```

Viewing security events 4663 showed that a file had been written to `C:\Users\Administrator\AppData\SpcTmp\analytics.txt` 

```powershell
PS C:\> sec-FileAccess
=== Security Event ID 4663: An attempt was made to access an object ===

TimeCreated    : 12/26/2023 1:36:18 PM
SubjectAccount : Administrator
SubjectDomain  : ATOMICBIRD
ObjectType     : File
ObjectName     : C:\Users\Administrator\AppData\SpcTmp\analytics.txt
ProcessID      : 6
ProcessName    : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
AccessesMask   : 3400
AccessRights   : FILE_WRITE_ATTRIBUTES
```

This file contains the PowerShell history commands I have run so far.

![Alt](/images/Atomic-1/history-cmd.webp)

### Test T0006-2: SystemFile modification for exfiltration

This test simulates a system file hijack attempt where an attacker modifies the hosts file to redirect network traffic for exfiltration or MITM attacks 

```powershell
PS C:\Users\Administrator> Invoke-AtomicTest T0006 -ShowDetails -TestNumbers 2
PathToAtomicsFolder = C:\AtomicRedTeam\atomics

[********BEGIN TEST*******]
Technique: TEST T0006
Atomic Test Name: TASK-6.2 SystemFile modification for exfiltration
Atomic Test Number: 2
Atomic Test GUID: d6dc21af-bec9-4152-be86-326b6babd416
Description: Systemfile modification for exfiltration

Attack Commands:
Executor: powershell
ElevationRequired: False
Command:
C:\AtomicRedTeam\atomics\T0006\srvc.ps1

Cleanup Commands:
Command:
C:\AtomicRedTeam\atomics\T0006\restore.ps1
[!!!!!!!!END TEST!!!!!!!]

PS C:\Users\Administrator> Invoke-AtomicTest T0006 -TestNumbers 2
```

Check the Security logs related to the file access attempt

```powershell
PS C:\> THM-LogStats-Security

|#|#|#|#|#| SECURITY Log Statistics |#|#|#|#|#|

Count Event ID Task Category
----- -------- -------------
    6     4688 Process Creation
    2     4663 File System
    1     1102 Log clear
```

The process **`powershell.exe`**accessed the hosts file with the access right **`FILE_READ_ATTRIBUTES | FILE_EXECUTE`**

```powershell
PS C:\> sec-FileAccess
=== Security Event ID 4663: An attempt was made to access an object ===

TimeCreated    : 12/26/2023 1:43:09 PM
SubjectAccount : Administrator
SubjectDomain  : ATOMICBIRD
ObjectType     : File
ObjectName     : C:\Windows\System32\drivers\etc\hosts
ProcessID      : 6
ProcessName    : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
AccessesMask   : 2792
AccessRights   : FILE_READ_ATTRIBUTES | FILE_EXECUTE

TimeCreated    : 12/26/2023 1:43:09 PM
SubjectAccount : Administrator
SubjectDomain  : ATOMICBIRD
ObjectType     : File
ObjectName     : C:\Windows\System32\drivers\etc\hosts
ProcessID      : 1
ProcessName    : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
AccessesMask   : 2792
AccessRights   : FILE_READ_ATTRIBUTES | FILE_EXECUTE
```

![Alt](/images/Atomic-1/hosts.webp)


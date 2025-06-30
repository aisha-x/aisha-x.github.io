---
title: "Masterminds Challenge"
date: 2025-04-10 14:00:00
categories: [Tryhackme, Challenges]
tag: [pcap analysis, brim]
---

# TryHackMe: Masterminds Challenge

Room URL: https://tryhackme.com/room/mastermindsxlq

---
# Detect the compromise using Brim

Three machines in the Finance department at Pfeffer PLC were compromised. We suspect the initial source of the compromise happened through a phishing attempt and by an infected USB drive. The Incident Response team managed to pull the network traffic logs from the endpoints. Use Brim to investigate the network traffic for any indicators of an attack and determine who stands behind the attacks. 

> NOTE: DO NOT directly interact with any domains and IP addresses in this challenge.
> For security purposes, all URLs and IP addresses have been defanged. To complete the tasks in the tryhackme room, you will need to remove the defanging. 

---
# [Infection 1]
Start by loading the Infection1 packet capture in Brim to investigate the compromise event for the first machine.


### Q1. Provide the victim's IP address.

![Screenshot 2025-05-05 142459](https://github.com/user-attachments/assets/038fad7a-3e3f-4c99-bb79-8150d4202b76)

- `_path=="conn" | cut id, service | sort | uniq -c`
![Screenshot 2025-05-05 140847](https://github.com/user-attachments/assets/33a2dcb3-a53f-41d0-a925-3338a186ed50)

Ans: ***192.168.75.249***


### Q2. The victim attempted to make HTTP connections to two suspicious domains with the status '404 Not Found'. Provide the hosts/domains requested. 
- `method=="GET" | 404 | cut ts, uid, id, method, host ,uri, status_code`

![Screenshot 2025-05-05 140655](https://github.com/user-attachments/assets/a467d3f2-4185-4dcf-afb9-c7f8ec4d84fa)

Ans: ***cambiasuhistoria[.]growlab[.]es,www[.]letscompareonline[.]com***


### Q3. The victim made a successful HTTP connection to one of the domains and received the response_body_len of 1,309 (uncompressed content size of the data transferred from the server). Provide the domain and the destination IP address.

- `method=="GET" | 200 | cut ts, uid, id, method, host, uri, status_code, response_body_len`

![Screenshot 2025-05-05 140510](https://github.com/user-attachments/assets/fe66164d-8e87-4ef4-a1e0-2587bb6500f6)

Ans: ***ww25[.]gocphongthe[.]com,199.59.242.153***


### Q4. How many unique DNS requests were made to cab[.]myfkn[.]com domain (including the capitalized domain)? 

- `_path=="dns" | count() by query | sort -r`
- ![Screenshot 2025-05-05 140415](https://github.com/user-attachments/assets/4c44eae8-f52d-4d58-9dc6-53c6ec8ae617)

Ans: ***7***


### Q5. Provide the URI of the domain bhaktivrind[.]com that the victim reached out over HTTP. 

- `_path=="http" | bhaktivrind.com |cut host, uri`
![Screenshot 2025-05-05 140317](https://github.com/user-attachments/assets/f41c3959-553c-4c69-a85c-309498efdbc9)


Ans: ***/cgi-bin/JBbb8/***


### Q6. Provide the IP address of the malicious server and the executable that the victim downloaded from the server. 

- `_path=="http" | cut id, method, host, uri, status_code`
![Screenshot 2025-05-05 141508](https://github.com/user-attachments/assets/829a0d82-cff8-477d-88b0-0fd265dad8e7)

Ans: ***185[.]239[.]243[.]112,catzx.exe***


### Q7. Based on the information gathered from the second question, provide the name of the malware using VirusTotal. 

- search for `cambiasuhistoria[.]growlab[.]es` in VirusTotal and check the community tab
![Screenshot 2025-05-05 141902](https://github.com/user-attachments/assets/f0ebda95-dab0-4809-b1ea-abb23dbb7172)


Ans: ***emotet***


---
# [Infection 2]


navigate to the Infection2 packet capture in Brim to investigate the compromise event for the second machine.

### Q1.Provide the IP address of the victim machine. 

![Screenshot 2025-05-05 142514](https://github.com/user-attachments/assets/3f9eaf65-255e-4aae-87ed-4ffbcf034b3f)

- `_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h, service | sort | uniq -c`
- This shows a frequency count of unique network connections showing who connected to whom (IP addresses), on which port, and what service was used.

![Screenshot 2025-05-05 143123](https://github.com/user-attachments/assets/ed0d4f4f-67a3-4821-8fc3-c7241c73a481)

Ans: ***192[.]168[.]75[.]146***

### Q2.Provide the IP address the victim made the POST connections to. 

- `method=="POST" | cut id, method,host, uri, status_code`

![Screenshot 2025-05-05 143645](https://github.com/user-attachments/assets/36debeff-844e-4c8e-8fd0-fd7cbe38fe2d)

Ans: ***5[.]181.156.252***


### Q3.How many POST connections were made to the IP address in the previous question?

- `method=="POST" | 5.181.156.252 | cut id.resp_h,method | uniq -c`

![Screenshot 2025-05-05 144225](https://github.com/user-attachments/assets/ad066fcd-7afb-4a40-9d4e-c08151705b50)


Ans: ***3***


### Q4.Provide the domain where the binary was downloaded from. 

- `_path=="http" | cut host, uri`

![Screenshot 2025-05-05 144448](https://github.com/user-attachments/assets/c4412f79-13f6-41a9-bf1b-830ec61b2fa9)

Ans: ***hypercustom[.]top***



### Q5.Provide the name of the binary including the full URI.

Ans: ***/jollion/apines.exe***

### Q6.Provide the IP address of the domain that hosts the binary.

- `_path=="http" | cut id,host, uri`

![Screenshot 2025-05-05 144448](https://github.com/user-attachments/assets/896506f4-62e4-4178-b4c9-4bc4fdd7ba35)


Ans: ***45[.]95.203.28***


### Q7.There were 2 Suricata "A Network Trojan was detected" alerts. What were the source and destination IP addresses? 

- `event_type=="alert" | alerts := union(alert.category) by src_ip, dest_ip`


Ans: ***192[.]168.75.146,45.95.203.28***

### Q8.Taking a look at .top domain in HTTP requests, provide the name of the stealer (Trojan that gathers information from a system) involved in this packet capture using [URLhaus Database.](https://urlhaus.abuse.ch/)

- search for `hypercustom.top` in the URLhaus database, you will find the name in the tags

![Screenshot 2025-05-05 145412](https://github.com/user-attachments/assets/2da065fd-abd4-418e-b576-ae04035cd50e)

 

Ans: ***Redline Stealer***


---
# [Infection 3]

Load the Infection3 packet capture in Brim to investigate the compromise event for the third machine.

### Q1.Provide the IP address of the victim machine.

- first look how many logs do we have
-  `count() by _path | sort -r`

![Screenshot 2025-05-05 145959](https://github.com/user-attachments/assets/e19f406c-b8bd-47c4-9bfb-3ce675e8b4a0)

- second, show the network connectivity overview
- `_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h, service | sort | uniq -c`

![Screenshot 2025-05-05 150559](https://github.com/user-attachments/assets/7d64a25c-64a4-4df3-8281-9f6ab70e56e5)


Ans: ***192[.]168.75.232***


### Q2.Provide three C2 domains from which the binaries were downloaded (starting from the earliest to the latest in the timestamp)

-` _path=="http" | cut ts, id, host, uri | sort ts `

![Screenshot 2025-05-05 154625](https://github.com/user-attachments/assets/f63f7769-27aa-4839-b58c-09b312ee07b2)

- look for suspicious file type in URIs
- domain `efhoahegue.ru` was used to download .exe files via two ip address
- the third is `xfhoahegue.ru`


Ans: ***efhoahegue[.]ru,afhoahegue[.]ru,xfhoahegue[.]ru***

### Q3.Provide the IP addresses for all three domains in the previous question.

Ans: ***162.217.98.146,199.21.76.77,63.251.106.25***

### Q4.How many unique DNS queries were made to the domain associated from the first IP address from the previous answer? 

- `_path=="dns" |162.217.98.146 | count() by query`

![Screenshot 2025-05-05 155336](https://github.com/user-attachments/assets/63432c90-6de6-4d13-97b0-93aecad7939b)


Ans: ***2***

### Q5.How many binaries were downloaded from the above domain in total? 

- `_path=="http" | 162.217.98.146| cut id.resp_h, host, uri `

![Screenshot 2025-05-05 160555](https://github.com/user-attachments/assets/8c08e79a-8dc3-4074-9faf-fa31d64abfcf)



Ans: ***5***


### Q6.Provided the user-agent listed to download the binaries. 

- `_path=="http" | 162.217.98.146| cut id.resp_h, host, uri ,user_agent`

![Screenshot 2025-05-05 160658](https://github.com/user-attachments/assets/f42f8c4e-0e12-4045-bf80-6b6302d7f8ab)


Ans: ***Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0***

### Q7.Provide the amount of DNS connections made in total for this packet capture.

- `_path=="dns" | count() by query | sort -r | sum(count)`

![Screenshot 2025-05-05 162427](https://github.com/user-attachments/assets/08ab3bef-752e-479e-b4a7-8a9d8ae2ebb3)


Ans: ***986***

### Q8.With some OSINT skills, provide the name of the worm using the first domain you have managed to collect from Question 2. (Please use quotation marks for Google searches, don't use .ru in your search, and DO NOT interact with the domain directly).

- Search for the domain in VirusTotal, check the community tab

![Screenshot 2025-05-05 164053](https://github.com/user-attachments/assets/bb60df6b-dc58-4511-88a3-94f8c50d52f7)


Ans: ***Phorphiex***

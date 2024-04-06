# Active Directory Methodology

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Grundlegende Übersicht

**Active Directory** dient als grundlegende Technologie, die es **Netzwerkadministratoren** ermöglicht, effizient **Domains**, **Benutzer** und **Objekte** in einem Netzwerk zu erstellen und zu verwalten. Es ist darauf ausgelegt, skalierbar zu sein und die Organisation einer großen Anzahl von Benutzern in verwaltbare **Gruppen** und **Untergruppen** zu ermöglichen, während gleichzeitig **Zugriffsrechte** auf verschiedenen Ebenen kontrolliert werden.

Die Struktur von **Active Directory** besteht aus drei Hauptebenen: **Domains**, **Trees** und **Forests**. Eine **Domain** umfasst eine Sammlung von Objekten wie **Benutzer** oder **Geräte**, die eine gemeinsame Datenbank teilen. **Trees** sind Gruppen dieser Domains, die durch eine gemeinsame Struktur verbunden sind, und ein **Forest** repräsentiert die Sammlung mehrerer Trees, die durch **Trust Relationships** miteinander verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Spezifische **Zugriffs-** und **Kommunikationsrechte** können auf jeder dieser Ebenen festgelegt werden.

Zu den Schlüsselkonzepten in **Active Directory** gehören:

1. **Directory** - Enthält alle Informationen zu Active Directory-Objekten.
2. **Objekt** - Bezeichnet Entitäten im Verzeichnis, einschließlich **Benutzer**, **Gruppen** oder **gemeinsam genutzte Ordner**.
3. **Domain** - Dient als Container für Verzeichnisobjekte, wobei mehrere Domains innerhalb eines **Forest** koexistieren können, wobei jede ihre eigene Objektsammlung verwaltet.
4. **Tree** - Eine Gruppierung von Domains, die eine gemeinsame Stamm-Domain teilen.
5. **Forest** - Die Spitze der Organisationsstruktur in Active Directory, bestehend aus mehreren Trees mit **Trust Relationships** zwischen ihnen.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für das zentrale Management und die Kommunikation in einem Netzwerk von entscheidender Bedeutung sind. Diese Dienste umfassen:

1. **Domain Services** - Zentralisiert die Datenspeicherung und verwaltet die Interaktionen zwischen **Benutzern** und **Domains**, einschließlich **Authentifizierung** und **Suchfunktionen**.
2. **Certificate Services** - Überwacht die Erstellung, Verteilung und Verwaltung sicherer **digitaler Zertifikate**.
3. **Lightweight Directory Services** - Unterstützt verzeichnisfähige Anwendungen über das **LDAP-Protokoll**.
4. **Directory Federation Services** - Bietet **Single-Sign-On**-Fähigkeiten zur Authentifizierung von Benutzern über mehrere Webanwendungen in einer einzigen Sitzung.
5. **Rights Management** - Hilft beim Schutz von urheberrechtlich geschütztem Material, indem es dessen unbefugte Verteilung und Nutzung regelt.
6. **DNS-Dienst** - Wesentlich für die Auflösung von **Domainnamen**.

Für eine ausführlichere Erklärung siehe: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active\_directory)

### **Kerberos-Authentifizierung**

Um zu lernen, wie man ein AD **angreift**, müssen Sie den **Kerberos-Authentifizierungsprozess** wirklich gut verstehen.\
[**Lesen Sie diese Seite, wenn Sie immer noch nicht wissen, wie es funktioniert.**](kerberos-authentication.md)

## Spickzettel

Sie können [https://wadcoms.github.io/](https://wadcoms.github.io) besuchen, um eine schnelle Übersicht über die Befehle zu erhalten, die Sie zur Enumeration/Exploitation eines AD ausführen können.

## Recon Active Directory (Keine Anmeldeinformationen/Sitzungen)

Wenn Sie nur Zugriff auf eine AD-Umgebung haben, aber keine Anmeldeinformationen/Sitzungen haben, können Sie Folgendes tun:

* **Pentest des Netzwerks:**
* Scannen Sie das Netzwerk, finden Sie Maschinen und offene Ports und versuchen Sie, **Sicherheitslücken** auszunutzen oder von ihnen **Anmeldeinformationen** zu extrahieren (zum Beispiel könnten [Drucker sehr interessante Ziele sein](ad-information-in-printers.md)).
* Die Enumeration von DNS kann Informationen über wichtige Server in der Domäne wie Web, Drucker, Freigaben, VPN, Medien usw. liefern.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Werfen Sie einen Blick auf die allgemeine [**Pentesting-Methodik**](../../generic-methodologies-and-resources/pentesting-methodology.md), um weitere Informationen dazu zu finden, wie dies durchgeführt werden kann.
* **Überprüfen Sie null- und Gastzugriff auf SMB-Dienste** (dies funktioniert nicht bei modernen Windows-Versionen):
* `enum4linux -a -u "" -p "" <DC-IP> && enum4linux -a -u "guest" -p "" <DC-IP>`
* `smbmap -u "" -p "" -P 445 -H <DC-IP> && smbmap -u "guest" -p "" -P 445 -H <DC-IP>`
* `smbclient -U '%' -L //<DC-IP> && smbclient -U 'guest%' -L //`
* Eine ausführlichere Anleitung zur Enumeration eines SMB-Servers finden Sie hier:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Ldap enumerieren**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC-IP>`
* Eine ausführlichere Anleitung zur Enumeration von LDAP finden Sie hier (achten Sie **besonders auf den anonymen Zugriff**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Vergiften Sie das Netzwerk**
* Sammeln Sie Anmeldeinformationen, indem Sie [**Dienste mit Responder vortäuschen**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Greifen Sie auf Hosts zu, indem Sie [**den Relay-Angriff missbrauchen**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Sammeln Sie Anmeldeinformationen, indem Sie **gefälschte UPnP-Dienste mit evil-S** [**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) **exponieren**
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Extrahieren Sie Benutzernamen/Namen aus internen Dokumenten,

### Benutzeraufzählung

* **Anonyme SMB/LDAP-Aufzählung:** Überprüfen Sie die Seiten [**Pentesting SMB**](../../network-services-pentesting/pentesting-smb/) und [**Pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Kerbrute-Aufzählung**: Wenn ein **ungültiger Benutzername angefordert wird**, antwortet der Server mit dem **Kerberos-Fehlercode** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, was uns ermöglicht festzustellen, dass der Benutzername ungültig war. **Gültige Benutzernamen** lösen entweder die **TGT in einer AS-REP-Antwort** oder den Fehler _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_ aus, was darauf hinweist, dass der Benutzer eine Vorauthentifizierung durchführen muss.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```

* **OWA (Outlook Web Access) Server**

Wenn Sie einen dieser Server im Netzwerk gefunden haben, können Sie auch eine **Benutzerenumeration dagegen durchführen**. Sie könnten zum Beispiel das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:

```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```

{% hint style="warning" %}
Sie können Listen von Benutzernamen in [**diesem GitHub-Repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* und diesem ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) finden.

Sie sollten jedoch den **Namen der Personen, die in der Firma arbeiten**, aus dem Recon-Schritt haben, den Sie zuvor durchgeführt haben. Mit Vor- und Nachnamen können Sie das Skript [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um potenziell gültige Benutzernamen zu generieren.
{% endhint %}

### Kenntnis von einem oder mehreren Benutzernamen

Ok, Sie wissen, dass Sie bereits einen gültigen Benutzernamen haben, aber keine Passwörter... Dann versuchen Sie es mit:

* [**ASREPRoast**](asreproast.md): Wenn ein Benutzer das Attribut _DONT\_REQ\_PREAUTH_ **nicht hat**, können Sie eine AS\_REP-Nachricht für diesen Benutzer anfordern, die einige Daten enthält, die mit einer Ableitung des Benutzerpassworts verschlüsselt sind.
* [**Password Spraying**](password-spraying.md): Versuchen Sie die **häufigsten Passwörter** mit jedem der entdeckten Benutzer, vielleicht verwendet ein Benutzer ein schlechtes Passwort (beachten Sie die Passwortrichtlinie!).
* Beachten Sie, dass Sie auch **OWA-Server** besprühen können, um Zugriff auf die E-Mail-Server der Benutzer zu erhalten.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS-Vergiftung

Sie könnten in der Lage sein, einige Herausforderungs-**Hashes** zu erhalten, um sie zu knacken, indem Sie einige Protokolle des Netzwerks **vergiften**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML-Relais

Wenn es Ihnen gelungen ist, das Active Directory aufzulisten, haben Sie **mehr E-Mails und ein besseres Verständnis des Netzwerks**. Sie könnten in der Lage sein, **NTML-Relaisangriffe** durchzuführen, um Zugriff auf die AD-Umgebung zu erhalten.

### NTLM-Anmeldeinformationen stehlen

Wenn Sie auf andere PCs oder Freigaben mit dem **null- oder Gastbenutzer** zugreifen können, könnten Sie **Dateien platzieren** (wie eine SCF-Datei), die bei einem Zugriff eine NTML-Authentifizierung gegen Sie auslösen, damit Sie die NTLM-Herausforderung stehlen können, um sie zu knacken:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Active Directory mit Anmeldeinformationen/Sitzung aufzählen

Für diese Phase müssen Sie **Anmeldeinformationen oder eine Sitzung eines gültigen Domänenkontos kompromittiert haben**. Wenn Sie gültige Anmeldeinformationen oder eine Shell als Domänenbenutzer haben, **sollten Sie bedenken, dass die zuvor gegebenen Optionen immer noch Optionen sind, um andere Benutzer zu kompromittieren**.

Bevor Sie mit der authentifizierten Aufzählung beginnen, sollten Sie wissen, was das **Kerberos-Doppelhop-Problem** ist.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Aufzählung

Das Kompromittieren eines Kontos ist ein **großer Schritt, um die gesamte Domäne zu kompromittieren**, da Sie in der Lage sein werden, mit der **Active Directory-Aufzählung zu beginnen**:

In Bezug auf [**ASREPRoast**](asreproast.md) können Sie nun jeden möglichen gefährdeten Benutzer finden, und in Bezug auf [**Password Spraying**](password-spraying.md) können Sie eine **Liste aller Benutzernamen** erhalten und das Passwort des kompromittierten Kontos, leere Passwörter und neue vielversprechende Passwörter ausprobieren.

* Sie könnten das [**CMD zur Durchführung einer grundlegenden Aufklärung**](../basic-cmd-for-pentesters.md#domain-info) verwenden.
* Sie können auch [**PowerShell für Aufklärungszwecke**](../basic-powershell-for-pentesters/) verwenden, was unauffälliger sein wird.
* Sie können auch [**Powerview verwenden**](../basic-powershell-for-pentesters/powerview.md), um detailliertere Informationen zu extrahieren.
* Ein weiteres erstaunliches Tool für die Aufklärung in einer Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht sehr unauffällig** (abhängig von den verwendeten Sammlungsmethoden), aber **wenn es Ihnen nichts ausmacht**, sollten Sie es unbedingt ausprobieren. Finden Sie heraus, wo Benutzer RDP können, finden Sie den Pfad zu anderen Gruppen usw.
* **Andere automatisierte AD-Aufzählungstools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**DNS-Einträge des AD**](ad-dns-records.md), da sie möglicherweise interessante Informationen enthalten.
* Ein **Tool mit GUI**, das Sie zur Aufzählung des Verzeichnisses verwenden können, ist **AdExplorer.exe** aus der **SysInternal** Suite.
* Sie können auch in der LDAP-Datenbank mit **ldapsearch** nach Anmeldeinformationen in den Feldern _userPassword_ & _unixUserPassword_ oder sogar nach _Description_ suchen. Siehe [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für andere Methoden.
* Wenn Sie **Linux** verwenden, können Sie die Domäne auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) aufzählen.
* Sie könnten auch automatisierte Tools wie verwenden:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
* **Extrahieren aller Domänenbenutzer**

Es ist sehr einfach, alle Domänennamen von Windows (`net user /domain`, `Get-DomainUser` oder `wmic useraccount get name,sid`) zu erhalten. In Linux können Sie Folgendes verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Abschnitt zur Aufzählung klein aussieht, ist dies der wichtigste Teil von allen. Greifen Sie auf die Links zu (hauptsächlich auf den Link zu cmd, powershell, powerview und BloodHound) zu, lernen Sie, wie man eine Domäne aufzählt, und üben Sie, bis Sie sich wohl fühlen. Während einer Bewertung wird dies der entscheidende Moment sein, um Ihren Weg zu DA zu finden oder zu entscheiden, dass nichts getan werden kann.

### Kerberoast

Beim Kerberoasting geht es darum, **TGS-Tickets** zu erhalten, die von Diensten verwendet werden, die an Benutzerkonten gebunden sind, und ihre Verschlüsselung zu knacken - die auf Benutzerpasswörtern basiert - **offline**.

Mehr dazu in:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Remote-Verbindung (RDP, SSH, FTP, Win-RM, usw.)

Sobald Sie einige Anmeldeinformationen erhalten haben, können Sie überprüfen, ob Sie Zugriff auf eine beliebige **Maschine** haben. Hierfür können Sie **CrackMapExec** verwenden, um mit verschiedenen Protokollen auf mehreren Servern eine Verbindung herzustellen, entsprechend Ihren Portscans.

### Lokale Privilege-Eskalation

Wenn Sie kompromittierte Anmeldeinformationen oder eine Sitzung als regulärer Domänenbenutzer haben und mit diesem Benutzer Zugriff auf **eine beliebige Maschine in der Domäne** haben, sollten Sie versuchen, Ihren Weg zur **lokalen Privilege-Eskalation und zum Ausspähen von Anmeldeinformationen** zu finden. Dies liegt daran, dass Sie nur mit lokalen Administratorrechten in der Lage sein werden, Hashes anderer Benutzer im Speicher (LSASS) und lokal (SAM) abzurufen.

In diesem Buch gibt es eine ausführliche Seite zur [**lokalen Privilege-Eskalation in Windows**](../windows-local-privilege-escalation/) und eine [**Checkliste**](../checklist-windows-privilege-escalation.md). Vergessen Sie außerdem nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Aktuelle Sitzungstickets

Es ist sehr **unwahrscheinlich**, dass Sie in der aktuellen Benutzersitzung **Tickets** finden, die Ihnen Zugriff auf unerwartete Ressourcen gewähren. Sie können jedoch Folgendes überprüfen:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTML Relay

Wenn es Ihnen gelungen ist, das Active Directory aufzulisten, haben Sie **mehr E-Mails und ein besseres Verständnis des Netzwerks**. Möglicherweise können Sie **NTML-Weiterleitungsangriffe** erzwingen.

### Suchen Sie nach Anmeldeinformationen in freigegebenen Computern

Jetzt, da Sie einige grundlegende Anmeldeinformationen haben, sollten Sie überprüfen, ob Sie **interessante Dateien finden, die im AD freigegeben sind**. Sie könnten dies manuell tun, aber es ist eine sehr langweilige und repetitive Aufgabe (insbesondere wenn Sie Hunderte von Dokumenten überprüfen müssen).

[**Folgen Sie diesem Link, um mehr über Tools zu erfahren, die Sie verwenden könnten.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### NTLM-Anmeldeinformationen stehlen

Wenn Sie auf andere PCs oder Freigaben zugreifen können, könnten Sie **Dateien platzieren** (wie eine SCF-Datei), die, wenn sie auf irgendeine Weise zugegriffen werden, eine **NTML-Authentifizierung gegen Sie auslösen**, damit Sie die **NTLM-Herausforderung** stehlen können, um sie zu knacken:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle ermöglichte es jedem authentifizierten Benutzer, den Domänencontroller zu **kompromittieren**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Privilege Escalation in Active Directory MIT privilegierten Anmeldeinformationen/Sitzung

**Für die folgenden Techniken reicht ein regulärer Domänenbenutzer nicht aus, Sie benötigen spezielle Privilegien/Anmeldeinformationen, um diese Angriffe durchzuführen.**

### Hash-Extraktion

Hoffentlich ist es Ihnen gelungen, ein lokales Administrator-Konto mit [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich Weiterleitung, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [lokale Privileg Eskalation](../windows-local-privilege-escalation/) zu kompromittieren.\
Dann ist es an der Zeit, alle Hashes im Speicher und lokal abzulegen.\
[**Lesen Sie diese Seite über verschiedene Möglichkeiten, um die Hashes zu erhalten.**](https://github.com/carlospolop/hacktricks/blob/de/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

Sobald Sie den Hash eines Benutzers haben, können Sie ihn verwenden, um sich als dieser Benutzer auszugeben.\
Sie müssen ein **Tool** verwenden, das die **NTLM-Authentifizierung mit diesem Hash durchführt**, oder Sie könnten eine neue **Sessionlogon** erstellen und diesen Hash in den **LSASS** injizieren, damit dieser Hash verwendet wird, wenn eine **NTLM-Authentifizierung durchgeführt wird**. Die letzte Option ist das, was mimikatz tut.\
[**Lesen Sie diese Seite für weitere Informationen.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, den NTLM-Hash des Benutzers zu verwenden, um Kerberos-Tickets anzufordern, als Alternative zum gängigen Pass The Hash über das NTLM-Protokoll. Daher könnte dies besonders **nützlich in Netzwerken sein, in denen das NTLM-Protokoll deaktiviert ist** und nur **Kerberos als Authentifizierungsprotokoll zugelassen ist**.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

Bei der Methode des **Pass The Ticket (PTT)** stehlen Angreifer ein **Authentifizierungsticket des Benutzers**, anstatt deren Passwort oder Hash-Werte. Dieses gestohlene Ticket wird dann verwendet, um sich als Benutzer auszugeben und unbefugten Zugriff auf Ressourcen und Dienste in einem Netzwerk zu erlangen.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Anmeldeinformationen wiederverwenden

Wenn Sie den **Hash** oder das **Passwort** eines **lokalen Administrators** haben, sollten Sie versuchen, sich lokal bei anderen **PCs** damit anzumelden.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

{% hint style="warning" %}
Beachten Sie, dass dies ziemlich **laut** ist und **LAPS** dies **mildern** würde.
{% endhint %}

### MSSQL-Missbrauch & Vertrauenswürdige Links

Wenn ein Benutzer Berechtigungen zum **Zugriff auf MSSQL-Instanzen** hat, könnte er es verwenden, um Befehle auf dem MSSQL-Host auszuführen (wenn er als SA ausgeführt wird), den NetNTLM-**Hash** zu **stehlen** oder sogar einen **Relay-Angriff** durchzuführen.\
Außerdem, wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz vertraut wird (Datenbanklink). Wenn der Benutzer Berechtigungen für die vertrauenswürdige Datenbank hat, kann er auch in der anderen Instanz Abfragen ausführen. Diese Vertrauensbeziehungen können verkettet werden und der Benutzer kann möglicherweise eine falsch konfigurierte Datenbank finden, in der er Befehle ausführen kann.\
**Die Verbindungen zwischen Datenbanken funktionieren sogar über Forest-Vertrauensstellungen hinweg.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Unbeschränkte Weiterleitung

Wenn Sie ein Computerobjekt mit dem Attribut [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) finden und über Domänenberechtigungen auf den Computer zugreifen können, können Sie TGTs aus dem Speicher aller Benutzer abrufen, die sich auf dem Computer anmelden.\
Wenn sich also ein **Domänenadministrator auf dem Computer anmeldet**, können Sie seinen TGT abrufen und sich mit [Pass the Ticket](pass-the-ticket.md) als er ausgeben.\
Dank der eingeschränkten Weiterleitung können Sie sogar **automatisch einen Druckserver kompromittieren** (hoffentlich handelt es sich um einen DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Eingeschränkte Weiterleitung

Wenn einem Benutzer oder Computer "Eingeschränkte Weiterleitung" erlaubt ist, kann er sich als beliebiger Benutzer ausgeben, um auf einige Dienste auf einem Computer zuzugreifen.\
Wenn Sie dann den Hash dieses Benutzers/Computers **kompromittieren**, können Sie sich als beliebiger Benutzer (auch Domänenadministratoren) ausgeben, um auf einige Dienste zuzugreifen.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Ressourcenbasierte eingeschränkte Weiterleitung

Wenn Sie das **SCHREIBEN**-Recht auf ein Active Directory-Objekt eines Remote-Computers haben, können Sie Codeausführung mit **erhöhten Berechtigungen** erreichen:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Missbrauch von ACLs

Der kompromittierte Benutzer könnte einige **interessante Berechtigungen für bestimmte Domänenobjekte** haben, die es Ihnen ermöglichen, seitwärts zu **bewegen** oder Berechtigungen zu **erhöhen**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Missbrauch des Druckwarteschlangendienstes

Das Entdecken eines **Spool-Dienstes**, der in der Domäne lauscht, kann dazu missbraucht werden, um neue Anmeldeinformationen zu **erlangen** und Berechtigungen zu **erhöhen**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Missbrauch von Sitzungen Dritter

Wenn **andere Benutzer** auf den **kompromittierten** Computer zugreifen, ist es möglich, Anmeldeinformationen aus dem Speicher zu **sammeln** und sogar **Beacons in ihre Prozesse einzufügen**, um sich als sie auszugeben.\
Normalerweise greifen Benutzer über RDP auf das System zu. Hier finden Sie einige Angriffe auf RDP-Sitzungen von Dritten:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** bietet ein System zur Verwaltung des **lokalen Administratorpassworts** auf domänenbeigetretenen Computern, um sicherzustellen, dass es **zufällig**, eindeutig und häufig **geändert** wird. Diese Passwörter werden im Active Directory gespeichert und der Zugriff wird nur autorisierten Benutzern über ACLs gesteuert. Mit ausreichenden Berechtigungen zum Zugriff auf diese Passwörter ist es möglich, auf andere Computer umzusteigen.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Zertifikatdiebstahl

Das **Sammeln von Zertifikaten** von der kompromittierten Maschine könnte ein Weg sein, um Berechtigungen in der Umgebung zu erhöhen:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Missbrauch von Zertifikatvorlagen

Wenn **verwundbare Vorlagen** konfiguriert sind, ist es möglich, sie zu missbrauchen, um Berechtigungen zu erhöhen:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Nach-Exploitation mit einem Konto mit hohen Berechtigungen

### Dumping von Domänenanmeldeinformationen

Sobald Sie **Domänenadministrator** oder noch besser **Enterprise Administrator**-Berechtigungen erhalten, können Sie die **Domänen-Datenbank**: _ntds.dit_ **dumpen**.

[**Weitere Informationen zum DCSync-Angriff finden Sie hier**](dcsync.md).

[**Weitere Informationen zum Stehlen der NTDS.dit finden Sie hier**](https://github.com/carlospolop/hacktricks/blob/de/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privilege Escalation als Persistence

Einige der zuvor diskutierten Techniken können für die Persistenz verwendet werden.\
Zum Beispiel könnten Sie:

* Benutzer anfällig für [**Kerberoast**](kerberoast.md) machen

```powershell
Set-DomainObject -Identity <Benutzername> -Set @{serviceprincipalname="fake/NOTHING"}r
```

* Benutzer anfällig für [**ASREPRoast**](asreproast.md) machen

```powershell
Set-DomainObject -Identity <Benutzername> -XOR @{UserAccountControl=4194304}
```

* Einem Benutzer [**DCSync**](./#dcsync)-Berechtigungen gewähren

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Der **Silver Ticket-Angriff** erstellt ein **legitimes Ticket Granting Service (TGS)-Ticket** für einen bestimmten Dienst, indem der **NTLM-Hash** (z. B. der Hash des PC-Kontos) verwendet wird. Diese Methode wird verwendet, um auf die Dienstberechtigungen zuzugreifen.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Golden Ticket

Ein **Golden Ticket-Angriff** beinhaltet, dass ein Angreifer Zugriff auf den **NTLM-Hash des krbtgt-Kontos** in einer Active Directory (AD)-Umgebung erhält. Dieses Konto ist besonders, da es zum Signieren aller **Ticket Granting Tickets (TGTs)** verwendet wird, die für die Authentifizierung im AD-Netzwerk unerlässlich sind.

Sobald der Angreifer diesen Hash erhält, kann er TGTs für jedes Konto erstellen, das er wählt (Silver Ticket-Angriff).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamond Ticket

Diese sind wie Golden Tickets, die auf eine Weise gefälscht sind, die **gewöhnliche Erkennungsmechanismen für Golden Tickets umgeht**.

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Zertifikatskontopersistenz**

**Das Vorhandensein von Zertifikaten eines Kontos oder die Möglichkeit, sie anzufordern**, ist ein sehr guter Weg, um in den Benutzerkonten zu bestehen (auch wenn er das Passwort ändert):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Zertifikatsdomänenpersistenz**

**Mit Zertifikaten ist es auch möglich, mit hohen Berechtigungen in der Domäne fortzubestehen:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolder-Gruppe

Das Objekt **AdminSDHolder** in Active Directory gewährleistet die Sicherheit von **privilegierten Gruppen** (wie Domänenadministratoren und Unternehmensadministratoren), indem es eine standardmäßige **Zugriffssteuerungsliste (ACL)** auf diese Gruppen anwendet, um unbefugte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden. Wenn ein Angreifer die ACL von AdminSDHolder ändert, um einem normalen Benutzer vollständigen Zugriff zu gewähren, erhält dieser Benutzer umfassende Kontrolle über alle privilegierten Gruppen. Diese Sicherheitsmaßnahme, die zum Schutz gedacht ist, kann sich also negativ auswirken und unberechtigten Zugriff ermöglichen, es sei denn, sie wird genau überwacht.

[**Weitere Informationen zur AdminSDHolder-Gruppe finden Sie hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM-Anmeldeinformationen

In jedem **Domänencontroller (DC)** gibt es ein **lokales Administrator**-Konto. Durch Erlangen von Administratorrechten auf einer solchen Maschine kann der lokale Administrator-Hash mithilfe von **mimikatz** extrahiert werden. Anschließend ist eine Registrierungsänderung erforderlich, um die Verwendung dieses Passworts zu **aktivieren**, was den Remotezugriff auf das lokale Administrator-Konto ermöglicht.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL-Persistenz

Sie können einem **Benutzer** über bestimmte Domänenobjekte **besondere Berechtigungen** geben, die es dem Benutzer ermöglichen, in Zukunft **Berechtigungen zu eskalieren**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Sicherheitsdeskriptoren

Die **Sicherheitsdeskriptoren** werden verwendet, um die **Berechtigungen** eines **Objekts** über ein **Objekt** zu **speichern**. Wenn Sie nur eine **kleine Änderung** am Sicherheitsdeskriptor eines Objekts vornehmen können, können Sie sehr interessante Berechtigungen für dieses Objekt erhalten, ohne Mitglied einer privilegierten Gruppe zu sein.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

Ändern Sie **LSASS** im Speicher, um ein **Universalkennwort** festzulegen, das Zugriff auf alle Domänenkonten gewährt.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### Benutzerdefinierter SSP

[Erfahren Sie hier, was ein SSP (Security Support Provider) ist.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Sie können Ihren **eigenen SSP** erstellen, um die zum Zugriff auf die Maschine verwendeten **Anmeldeinformationen** im **Klartext** zu **erfassen**.

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Es registriert einen **neuen Domänencontroller** in der AD und verwendet ihn, um Attribute (SIDHistory, SPNs...) auf angegebenen Objekten **ohne** Protokollierung der **Änderungen** zu **übertragen**. Sie benötigen DA-Berechtigungen und müssen sich in der **Stamm-Domäne** befinden.\
Beachten Sie, dass bei Verwendung falscher Daten ziemlich unschöne Protokolle angezeigt werden.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS-Persistenz

Zuvor haben wir besprochen, wie Berechtigungen eskaliert werden können, wenn Sie **ausreichende Berechtigungen zum Lesen von LAPS-Passwörtern** haben. Diese Passwörter können jedoch auch zur **Aufrechterhaltung der Persistenz** verwendet werden.\
Siehe:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Forest-Berechtigungserhöhung - Domänenvertrauen

Microsoft betrachtet den **Forest** als Sicherheitsgrenze. Dies bedeutet, dass das **Kompromittieren einer einzelnen Domäne potenziell dazu führen kann, dass der gesamte Forest kompromittiert wird**.

### Grundlegende Informationen

Ein [**Domänenvertrauen**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) ist ein Sicherheitsmechanismus, der einem Benutzer aus einer **Domäne** den Zugriff auf Ressourcen in einer anderen **Domäne** ermöglicht. Es erstellt im Wesentlichen eine Verbindung zwischen den Authentifizierungssystemen der beiden Domänen, sodass Authentifizierungsüberprüfungen nahtlos durchgeführt werden können. Wenn Domänen ein Vertrauen einrichten, tauschen sie spezifische **Schlüssel** zwischen ihren **Domänencontrollern (DCs)** aus, die für die Integrität des Vertrauens entscheidend sind.

In einem typischen Szenario muss ein Benutzer, der auf eine **vertrauenswürdige Domäne** zugreifen möchte, zunächst ein spezielles Ticket namens **inter-realm TGT** von seinem eigenen Domänen-DC anfordern. Dieses TGT ist mit einem gemeinsamen **Schlüssel** verschlüsselt, auf den sich beide Domänen geeinigt haben. Der Benutzer legt dann dieses TGT dem **DC der vertrauenswürdigen Domäne** vor, um ein Dienstticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des inter-realm TGT durch den DC der vertrauenswürdigen Domäne wird ein TGS ausgestellt, das dem Benutzer Zugriff auf den Dienst gewährt.

**Schritte**:

1. Ein **Clientcomputer** in **Domäne 1** startet den Prozess, indem er seinen **NTLM-Hash** verwendet, um ein **Ticket Granting Ticket (TGT)** von seinem **Domänencontroller (DC1)** anzufordern.
2. DC1 gibt ein neues TGT aus, wenn der Client erfolgreich authentifiziert ist.
3. Der Client fordert dann ein **inter-realm TGT** von DC1 an, das zum Zugriff auf Ressourcen in **Domäne 2** erforderlich ist.
4. Das inter-realm TGT ist mit einem **Vertrauensschlüssel** verschlüsselt, der zwischen DC1 und DC2 im Rahmen des beidseitigen Domänenvertrauens vereinbart wurde.
5. Der Client bringt das inter-realm TGT zum **Domänencontroller (DC2) von Domäne 2**.
6. DC2 überprüft das inter-realm TGT mithilfe seines gemeinsamen Vertrauensschlüssels und gibt bei erfolgreicher Validierung ein **Ticket Granting Service (TGS)** für den Server in Domäne 2 aus, auf den der Client zugreifen möchte.
7. Schließlich legt der Client dieses TGS dem Server vor, das mit dem Kontohash des Servers verschlüsselt ist, um Zugriff auf den Dienst in Domäne 2 zu erhalten.

### Unterschiedliche Vertrauensbeziehungen

Es ist wichtig zu beachten, dass **ein Vertrauen einseitig oder beidseitig sein kann**. Bei den beidseitigen Optionen vertrauen sich beide Domänen gegenseitig, aber in der **einseitigen Vertrauensbeziehung** ist eine der Domänen die **vertrauende** und die andere die **vertraute** Domäne. In letzterem Fall können Sie **nur auf Ressourcen innerhalb der vertrauenden Domäne von der vertrauten Domäne aus zugreifen**.

Wenn Domäne A Domäne B vertraut, ist A die vertrauende Domäne und B die vertraute Domäne. Darüber hinaus handelt es sich in **Domäne A** um ein **ausgehendes Vertrauen** und in **Domäne B** um ein **eingehendes Vertrauen**.

**Unterschiedliche Vertrauensbeziehungen**

* **Eltern-Kind-Vertrauen**: Dies ist eine hä

#### Weitere Unterschiede in **Vertrauensbeziehungen**

* Eine Vertrauensbeziehung kann auch **transitiv** sein (A vertraut B, B vertraut C, dann vertraut A auch C) oder **nicht-transitiv**.
* Eine Vertrauensbeziehung kann als **bidirektionales Vertrauen** (beide vertrauen sich gegenseitig) oder als **einseitiges Vertrauen** (nur einer von ihnen vertraut dem anderen) eingerichtet werden.

### Angriffspfad

1. **Ermitteln** Sie die Vertrauensbeziehungen.
2. Überprüfen Sie, ob ein **Sicherheitsprinzipal** (Benutzer/Gruppe/Computer) Zugriff auf Ressourcen der **anderen Domäne** hat, möglicherweise durch ACE-Einträge oder durch Zugehörigkeit zu Gruppen der anderen Domäne. Suchen Sie nach **Beziehungen zwischen Domänen** (das Vertrauen wurde wahrscheinlich für diesen Zweck erstellt).
3. In diesem Fall könnte auch Kerberoasting eine Option sein.
4. **Kompromittieren** Sie die **Konten**, die durch Domänen pivoten können.

Angreifer können über drei Hauptmechanismen auf Ressourcen in einer anderen Domäne zugreifen:

* **Lokale Gruppenmitgliedschaft**: Prinzipale können zu lokalen Gruppen auf Maschinen hinzugefügt werden, z. B. zur Gruppe "Administratoren" auf einem Server, was ihnen erhebliche Kontrolle über diese Maschine gibt.
* **Mitgliedschaft in einer fremden Domänengruppe**: Prinzipale können auch Mitglieder von Gruppen in der fremden Domäne sein. Die Effektivität dieser Methode hängt jedoch von der Art des Vertrauens und dem Umfang der Gruppe ab.
* **Zugriffssteuerungslisten (ACLs)**: Prinzipale können in einer ACL angegeben werden, insbesondere als Entitäten in ACEs innerhalb einer DACL, die ihnen Zugriff auf bestimmte Ressourcen gewähren. Für diejenigen, die tiefer in die Mechanik von ACLs, DACLs und ACEs eintauchen möchten, ist das Whitepaper mit dem Titel "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)" eine unschätzbare Ressource.

### Privilegieneskalation im Kind-zu-Eltern-Forest

```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```

{% hint style="warning" %}
Es gibt **2 vertrauenswürdige Schlüssel**, einen für _Kind --> Eltern_ und einen anderen für _Eltern_ --> _Kind_.\
Sie können denjenigen, der von der aktuellen Domäne verwendet wird, mit folgendem Befehl anzeigen:

```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History-Injektion

Skalieren Sie als Enterprise-Administrator zum Kind-/Elterndomäne, indem Sie das Vertrauen mit der SID-History-Injektion missbrauchen:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Ausnutzen der beschreibbaren Konfigurations-NC

Es ist entscheidend zu verstehen, wie der Konfigurations-Namenskontext (NC) ausgenutzt werden kann. Der Konfigurations-NC dient als zentrales Repository für Konfigurationsdaten in Active Directory (AD)-Umgebungen. Diese Daten werden auf jeden Domänencontroller (DC) innerhalb des Forest repliziert, wobei beschreibbare DCs eine beschreibbare Kopie des Konfigurations-NCs pflegen. Um dies auszunutzen, muss man **SYSTEM-Berechtigungen auf einem DC** haben, vorzugsweise auf einem Kind-DC.

**GPO mit Root-DC-Site verknüpfen**

Der Konfigurations-NC enthält im Sites-Container Informationen über alle Sites der domänenverbundenen Computer innerhalb des AD-Forest. Indem Angreifer mit SYSTEM-Berechtigungen auf einem beliebigen DC arbeiten, können sie GPOs mit den Root-DC-Sites verknüpfen. Dadurch können die Richtlinien, die auf diese Sites angewendet werden, manipuliert werden und potenziell die Root-Domäne kompromittiert werden.

Für detaillierte Informationen kann man die Forschung zu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) erkunden.

**Kompromittierung einer gMSA in dem Forest**

Ein Angriffsvektor besteht darin, privilegierte gMSAs in der Domäne anzugreifen. Der KDS-Root-Schlüssel, der für die Berechnung der Passwörter von gMSAs erforderlich ist, wird im Konfigurations-NC gespeichert. Mit SYSTEM-Berechtigungen auf einem beliebigen DC ist es möglich, auf den KDS-Root-Schlüssel zuzugreifen und die Passwörter für beliebige gMSAs im gesamten Forest zu berechnen.

Eine detaillierte Analyse findet sich in der Diskussion über [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema-Änderungsangriff**

Diese Methode erfordert Geduld und das Warten auf die Erstellung neuer privilegierter AD-Objekte. Mit SYSTEM-Berechtigungen kann ein Angreifer das AD-Schema ändern, um einem beliebigen Benutzer die vollständige Kontrolle über alle Klassen zu gewähren. Dadurch könnte unbefugter Zugriff und Kontrolle über neu erstellte AD-Objekte ermöglicht werden.

Weitere Informationen finden Sie unter [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Von DA zu EA mit ADCS ESC5**

Die ADCS ESC5-Schwachstelle zielt darauf ab, die Kontrolle über Public Key Infrastructure (PKI)-Objekte zu erlangen, um eine Zertifikatvorlage zu erstellen, die die Authentifizierung als beliebiger Benutzer im Forest ermöglicht. Da PKI-Objekte im Konfigurations-NC liegen, ermöglicht die Kompromittierung eines beschreibbaren Kind-DCs die Durchführung von ESC5-Angriffen.

Weitere Details dazu finden Sie in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In Szenarien ohne ADCS hat der Angreifer die Möglichkeit, die erforderlichen Komponenten einzurichten, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) diskutiert.

### Externe Forest-Domäne - Einweg (eingehend) oder bidirektional

```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```

In diesem Szenario **wird Ihre Domäne von einer externen Domäne vertraut**, was Ihnen **unbestimmte Berechtigungen** darüber gibt. Sie müssen herausfinden, **welche Prinzipale Ihrer Domäne Zugriff auf die externe Domäne haben** und dann versuchen, sie auszunutzen:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Externe Forest-Domäne - Einweg (Ausgehend)

```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```

In diesem Szenario **vertraut Ihre Domäne** bestimmten **Berechtigungen** einem Prinzipal aus einer **anderen Domäne**.

Wenn jedoch eine **Domäne vertraut** wird, erstellt die vertrauende Domäne einen Benutzer mit einem **vorhersehbaren Namen**, der als **Passwort das vertraute Passwort** verwendet. Das bedeutet, dass es möglich ist, auf einen Benutzer aus der vertrauenden Domäne zuzugreifen, um in die vertraute Domäne einzudringen, um sie aufzulisten und weitere Berechtigungen zu eskalieren:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Eine andere Möglichkeit, die vertraute Domäne zu kompromittieren, besteht darin, einen [**SQL-Vertrauenslink**](abusing-ad-mssql.md#mssql-trusted-links) in die **gegenläufige Richtung** des Domänenvertrauens zu finden (was nicht sehr häufig vorkommt).

Eine weitere Möglichkeit, die vertraute Domäne zu kompromittieren, besteht darin, auf einer Maschine zu warten, auf der ein **Benutzer aus der vertrauten Domäne zugreifen kann**, um sich über **RDP** anzumelden. Dann könnte der Angreifer Code in den RDP-Sitzungsprozess einschleusen und von dort aus auf die Ursprungsdomäne des Opfers zugreifen.\
Darüber hinaus könnte der Angreifer, wenn das **Opfer seine Festplatte eingebunden hat**, aus dem RDP-Sitzungsprozess heraus **Hintertüren** im **Startordner der Festplatte** speichern. Diese Technik wird als **RDPInception** bezeichnet.

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Missbrauch von Domänenvertrauen verhindern

### **SID-Filterung:**

* Das Risiko von Angriffen, die den SID-History-Attribut über Forstvertrauen ausnutzen, wird durch die SID-Filterung gemindert, die standardmäßig für alle Forstvertrauen aktiviert ist. Dies beruht auf der Annahme, dass Intra-Forstvertrauen sicher sind und der Forst anstelle der Domäne als Sicherheitsgrenze betrachtet wird, gemäß der Position von Microsoft.
* Es gibt jedoch einen Haken: Die SID-Filterung kann Anwendungen und den Benutzerzugriff beeinträchtigen, was zu ihrer gelegentlichen Deaktivierung führt.

### **Selektive Authentifizierung:**

* Bei Forstvertrauen stellt die selektive Authentifizierung sicher, dass Benutzer aus den beiden Forsten nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domänen und Server in der vertrauenden Domäne oder im Forst zugreifen können.
* Es ist wichtig zu beachten, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder Angriffen auf das Vertrauenskonto schützen.

[**Weitere Informationen zu Domänenvertrauen auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Einige allgemeine Verteidigungsmaßnahmen

[**Erfahren Sie hier mehr darüber, wie Sie Anmeldeinformationen schützen können.**](../stealing-credentials/credentials-protections.md)\\

### **Verteidigungsmaßnahmen zum Schutz von Anmeldeinformationen**

* **Einschränkungen für Domänenadministratoren**: Es wird empfohlen, dass Domänenadministratoren nur auf Domänencontrollern angemeldet werden dürfen und nicht auf anderen Hosts.
* **Berechtigungen für Dienstkonten**: Dienste sollten nicht mit Domänenadministrator (DA)-Berechtigungen ausgeführt werden, um die Sicherheit zu gewährleisten.
* **Zeitliche Begrenzung von Berechtigungen**: Für Aufgaben, die DA-Berechtigungen erfordern, sollte ihre Dauer begrenzt sein. Dies kann durch `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)` erreicht werden.

### **Implementierung von Täuschungstechniken**

* Die Implementierung von Täuschung beinhaltet das Aufstellen von Fallen, wie z.B. Lockvogel-Benutzern oder -Computern, mit Funktionen wie Passwörtern, die nicht ablaufen oder als vertrauenswürdig für Delegation markiert sind. Ein detaillierter Ansatz umfasst das Erstellen von Benutzern mit bestimmten Rechten oder das Hinzufügen zu Gruppen mit hohen Privilegien.
* Ein praktisches Beispiel besteht darin, Tools wie `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose` zu verwenden.
* Weitere Informationen zur Implementierung von Täuschungstechniken finden Sie unter [Deploy-Deception auf GitHub](https://github.com/samratashok/Deploy-Deception).

### **Erkennung von Täuschung**

* **Für Benutzerobjekte**: Verdächtige Indikatoren sind untypische ObjectSID, seltene Anmeldungen, Erstellungsdaten und niedrige Anzahl fehlerhafter Kennwörter.
* **Allgemeine Indikatoren**: Durch den Vergleich von Attributen potenzieller Lockvogelobjekte mit denen echter Objekte können Inkonsistenzen aufgedeckt werden. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können bei der Identifizierung solcher Täuschungen helfen.

### **Umgehung von Erkennungssystemen**

* **Microsoft ATA-Erkennung umgehen**:
* **Benutzerenumeration**: Vermeiden Sie die Sitzungszählung auf Domänencontrollern, um die ATA-Erkennung zu verhindern.
* **Ticket-Imitation**: Die Verwendung von **aes**-Schlüsseln zur Ticketerstellung hilft dabei, die Erkennung zu umgehen, indem keine Herabstufung auf NTLM erfolgt.
* **DCSync-Angriffe**: Es wird empfohlen, die Ausführung von einem Nicht-Domänencontroller auszuführen, um die ATA-Erkennung zu umgehen, da die direkte Ausführung von einem Domänencontroller Alarme auslöst.

## Referenzen

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden**.

</details>

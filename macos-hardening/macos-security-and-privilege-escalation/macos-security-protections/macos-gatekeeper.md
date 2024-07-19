# macOS Gatekeeper / Quarantine / XProtect

<details>

<summary><strong>Lerne AWS-Hacking von Null bis Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeitest du in einem **Cybersecurity-Unternehmen**? Möchtest du, dass dein **Unternehmen in HackTricks beworben wird**? Oder möchtest du Zugang zur **neueste Version der PEASS oder HackTricks im PDF-Format herunterladen**? Überprüfe die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecke [**Die PEASS-Familie**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Erhalte die [**offiziellen PEASS & HackTricks Merchandise**](https://peass.creator-spring.com)
* **Tritt der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teile deine Hacking-Tricks, indem du PRs an das** [**hacktricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **einreichst.**

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Gatekeeper

**Gatekeeper** ist eine Sicherheitsfunktion, die für Mac-Betriebssysteme entwickelt wurde, um sicherzustellen, dass Benutzer **nur vertrauenswürdige Software** auf ihren Systemen ausführen. Es funktioniert, indem es die **Software validiert**, die ein Benutzer herunterlädt und versucht zu öffnen, aus **Quellen außerhalb des App Store**, wie einer App, einem Plug-in oder einem Installationspaket.

Der Schlüsselmechanismus von Gatekeeper liegt in seinem **Überprüfungsprozess**. Es wird überprüft, ob die heruntergeladene Software **von einem anerkannten Entwickler signiert** ist, um die Authentizität der Software sicherzustellen. Darüber hinaus wird festgestellt, ob die Software **von Apple notariell beglaubigt** wurde, was bestätigt, dass sie frei von bekanntem schädlichem Inhalt ist und nach der Notarisierung nicht manipuliert wurde.

Zusätzlich verstärkt Gatekeeper die Benutzerkontrolle und Sicherheit, indem es **Benutzer auffordert, das Öffnen** der heruntergeladenen Software zum ersten Mal zu genehmigen. Diese Sicherheitsmaßnahme hilft, zu verhindern, dass Benutzer versehentlich potenziell schädlichen ausführbaren Code ausführen, den sie möglicherweise fälschlicherweise für eine harmlose Datendatei gehalten haben.

### Anwendungssignaturen

Anwendungssignaturen, auch bekannt als Codesignaturen, sind ein kritischer Bestandteil der Sicherheitsinfrastruktur von Apple. Sie werden verwendet, um **die Identität des Softwareautors** (des Entwicklers) zu überprüfen und sicherzustellen, dass der Code seit der letzten Signierung nicht manipuliert wurde.

So funktioniert es:

1. **Signieren der Anwendung:** Wenn ein Entwickler bereit ist, seine Anwendung zu verteilen, **signiert er die Anwendung mit einem privaten Schlüssel**. Dieser private Schlüssel ist mit einem **Zertifikat verbunden, das Apple dem Entwickler ausstellt**, wenn er sich im Apple Developer Program anmeldet. Der Signierungsprozess umfasst die Erstellung eines kryptografischen Hashs aller Teile der App und die Verschlüsselung dieses Hashs mit dem privaten Schlüssel des Entwicklers.
2. **Verteilen der Anwendung:** Die signierte Anwendung wird dann zusammen mit dem Zertifikat des Entwicklers verteilt, das den entsprechenden öffentlichen Schlüssel enthält.
3. **Überprüfen der Anwendung:** Wenn ein Benutzer die Anwendung herunterlädt und versucht, sie auszuführen, verwendet das Mac-Betriebssystem den öffentlichen Schlüssel aus dem Zertifikat des Entwicklers, um den Hash zu entschlüsseln. Es berechnet dann den Hash basierend auf dem aktuellen Zustand der Anwendung neu und vergleicht diesen mit dem entschlüsselten Hash. Wenn sie übereinstimmen, bedeutet dies, dass **die Anwendung seit der Signierung durch den Entwickler nicht verändert wurde**, und das System erlaubt es, die Anwendung auszuführen.

Anwendungssignaturen sind ein wesentlicher Bestandteil der Gatekeeper-Technologie von Apple. Wenn ein Benutzer versucht, **eine Anwendung zu öffnen, die aus dem Internet heruntergeladen wurde**, überprüft Gatekeeper die Anwendungssignatur. Wenn sie mit einem von Apple an einen bekannten Entwickler ausgestellten Zertifikat signiert ist und der Code nicht manipuliert wurde, erlaubt Gatekeeper die Ausführung der Anwendung. Andernfalls blockiert es die Anwendung und warnt den Benutzer.

Seit macOS Catalina **überprüft Gatekeeper auch, ob die Anwendung von Apple notariell beglaubigt wurde**, was eine zusätzliche Sicherheitsebene hinzufügt. Der Notarisierungsprozess überprüft die Anwendung auf bekannte Sicherheitsprobleme und schädlichen Code, und wenn diese Überprüfungen bestanden werden, fügt Apple der Anwendung ein Ticket hinzu, das Gatekeeper überprüfen kann.

#### Überprüfen von Signaturen

Beim Überprüfen einer **Malwareprobe** solltest du immer die **Signatur** der Binärdatei überprüfen, da der **Entwickler**, der sie signiert hat, möglicherweise bereits mit **Malware** in Verbindung steht.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarization

Apples Notarisierungsprozess dient als zusätzliche Sicherheitsmaßnahme, um Benutzer vor potenziell schädlicher Software zu schützen. Er umfasst das **Einreichen der Anwendung durch den Entwickler zur Prüfung** durch **Apples Notarservice**, der nicht mit der App-Überprüfung verwechselt werden sollte. Dieser Service ist ein **automatisiertes System**, das die eingereichte Software auf das Vorhandensein von **schädlichem Inhalt** und mögliche Probleme mit der Code-Signierung überprüft.

Wenn die Software diese Inspektion ohne Bedenken **besteht**, generiert der Notarservice ein Notarisierungsticket. Der Entwickler ist dann verpflichtet, **dieses Ticket an seiner Software anzuhängen**, ein Prozess, der als 'Stapeln' bekannt ist. Darüber hinaus wird das Notarisierungsticket auch online veröffentlicht, wo Gatekeeper, Apples Sicherheitstechnologie, darauf zugreifen kann.

Bei der ersten Installation oder Ausführung der Software des Benutzers informiert die Existenz des Notarisierungstickets - ob an die ausführbare Datei angeheftet oder online gefunden - **Gatekeeper darüber, dass die Software von Apple notariell beglaubigt wurde**. Infolgedessen zeigt Gatekeeper eine beschreibende Nachricht im ersten Startdialog an, die darauf hinweist, dass die Software von Apple auf schädlichen Inhalt überprüft wurde. Dieser Prozess erhöht somit das Vertrauen der Benutzer in die Sicherheit der Software, die sie auf ihren Systemen installieren oder ausführen.

### Enumerating GateKeeper

GateKeeper ist sowohl **mehrere Sicherheitskomponenten**, die verhindern, dass nicht vertrauenswürdige Apps ausgeführt werden, als auch **eine der Komponenten**.

Es ist möglich, den **Status** von GateKeeper mit:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Beachten Sie, dass die GateKeeper-Signaturprüfungen nur für **Dateien mit dem Quarantäneattribut** durchgeführt werden, nicht für jede Datei.
{% endhint %}

GateKeeper überprüft, ob ein Binärprogramm gemäß den **Einstellungen und der Signatur** ausgeführt werden kann:

<figure><img src="../../../.gitbook/assets/image (1150).png" alt=""><figcaption></figcaption></figure>

Die Datenbank, die diese Konfiguration speichert, befindet sich in **`/var/db/SystemPolicy`**. Sie können diese Datenbank als Root mit folgendem Befehl überprüfen:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
Beachten Sie, wie die erste Regel mit "**App Store**" endete und die zweite mit "**Developer ID**" und dass im vorherigen Bild **aktiviert war, Apps aus dem App Store und von identifizierten Entwicklern auszuführen**.\
Wenn Sie diese Einstellung auf den App Store **ändern**, werden die "**Notarized Developer ID"-Regeln verschwinden**.

Es gibt auch Tausende von Regeln des **Typs GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Dies sind Hashes, die aus **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** und **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`** stammen.

Oder Sie könnten die vorherigen Informationen mit:
```bash
sudo spctl --list
```
Die Optionen **`--master-disable`** und **`--global-disable`** von **`spctl`** werden diese Signaturprüfungen vollständig **deaktivieren**:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Wenn vollständig aktiviert, wird eine neue Option erscheinen:

<figure><img src="../../../.gitbook/assets/image (1151).png" alt=""><figcaption></figcaption></figure>

Es ist möglich zu **überprüfen, ob eine App von GateKeeper erlaubt wird** mit:
```bash
spctl --assess -v /Applications/App.app
```
Es ist möglich, neue Regeln in GateKeeper hinzuzufügen, um die Ausführung bestimmter Apps zu erlauben mit:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
### Quarantäne-Dateien

Beim **Herunterladen** einer Anwendung oder Datei fügen bestimmte macOS **Anwendungen** wie Webbrowser oder E-Mail-Clients dem heruntergeladenen Datei ein erweitertes Dateiattribut hinzu, das allgemein als "**Quarantäne-Flag**" bekannt ist. Dieses Attribut dient als Sicherheitsmaßnahme, um die Datei als von einer nicht vertrauenswürdigen Quelle (dem Internet) stammend zu kennzeichnen und potenziell Risiken zu tragen. Allerdings fügen nicht alle Anwendungen dieses Attribut hinzu; gängige BitTorrent-Client-Software umgeht diesen Prozess normalerweise.

**Das Vorhandensein eines Quarantäne-Flags signalisiert die Gatekeeper-Sicherheitsfunktion von macOS, wenn ein Benutzer versucht, die Datei auszuführen.**

Im Fall, dass das **Quarantäne-Flag nicht vorhanden ist** (wie bei Dateien, die über einige BitTorrent-Clients heruntergeladen wurden), können die **Überprüfungen von Gatekeeper möglicherweise nicht durchgeführt werden**. Daher sollten Benutzer vorsichtig sein, wenn sie Dateien öffnen, die aus weniger sicheren oder unbekannten Quellen heruntergeladen wurden.

{% hint style="info" %}
**Die Überprüfung** der **Gültigkeit** von Codesignaturen ist ein **ressourcenintensiver** Prozess, der das Generieren kryptografischer **Hashes** des Codes und aller seiner gebündelten Ressourcen umfasst. Darüber hinaus beinhaltet die Überprüfung der Zertifikatsgültigkeit eine **Online-Überprüfung** bei den Apple-Servern, um zu sehen, ob es nach der Ausstellung widerrufen wurde. Aus diesen Gründen ist eine vollständige Überprüfung der Codesignatur und Notarisierung **unpraktisch, um sie jedes Mal auszuführen, wenn eine App gestartet wird**.

Daher werden diese Überprüfungen **nur bei der Ausführung von Apps mit dem Quarantäne-Attribut durchgeführt.**
{% endhint %}

{% hint style="warning" %}
Dieses Attribut muss von der Anwendung, die die Datei erstellt/herunterlädt, **gesetzt werden**.

Allerdings haben Dateien, die in einer Sandbox ausgeführt werden, dieses Attribut für jede Datei, die sie erstellen. Und nicht sandboxed Apps können es selbst setzen oder den [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) Schlüssel in der **Info.plist** angeben, was das System veranlasst, das `com.apple.quarantine` erweiterte Attribut auf den erstellten Dateien zu setzen,
{% endhint %}

Darüber hinaus sind alle Dateien, die von einem Prozess erstellt werden, der **`qtn_proc_apply_to_self`** aufruft, quarantiniert. Oder die API **`qtn_file_apply_to_path`** fügt dem angegebenen Dateipfad das Quarantäne-Attribut hinzu.

Es ist möglich, den **Status zu überprüfen und zu aktivieren/deaktivieren** (Root erforderlich) mit:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Du kannst auch **herausfinden, ob eine Datei das Quarantäne-Erweiterungsattribut hat** mit:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Überprüfen Sie den **Wert** der **erweiterten** **Attribute** und finden Sie die App, die das Quarantäneattribut mit:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Tatsächlich könnte ein Prozess "Quarantäne-Flags für die Dateien setzen, die er erstellt" (ich habe versucht, das USER_APPROVED-Flag in einer erstellten Datei anzuwenden, aber es wird nicht angewendet):

<details>

<summary>Quellcode Quarantäne-Flags anwenden</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

Und **entferne** dieses Attribut mit:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Und finden Sie alle quarantänisierten Dateien mit:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Quarantäneinformationen werden auch in einer zentralen Datenbank gespeichert, die von LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** verwaltet wird.

#### **Quarantine.kext**

Die Kernel-Erweiterung ist nur über den **Kernel-Cache des Systems** verfügbar; jedoch _kann_ man das **Kernel Debug Kit von https://developer.apple.com/** herunterladen, das eine symbolisierte Version der Erweiterung enthält.

### XProtect

XProtect ist eine integrierte **Anti-Malware**-Funktion in macOS. XProtect **überprüft jede Anwendung, wenn sie zum ersten Mal gestartet oder geändert wird, gegen seine Datenbank** bekannter Malware und unsicherer Dateitypen. Wenn Sie eine Datei über bestimmte Apps wie Safari, Mail oder Nachrichten herunterladen, scannt XProtect die Datei automatisch. Wenn sie mit bekannter Malware in seiner Datenbank übereinstimmt, wird XProtect **verhindern, dass die Datei ausgeführt wird** und Sie auf die Bedrohung hinweisen.

Die XProtect-Datenbank wird **regelmäßig** von Apple mit neuen Malware-Definitionen aktualisiert, und diese Updates werden automatisch auf Ihrem Mac heruntergeladen und installiert. Dies stellt sicher, dass XProtect immer auf dem neuesten Stand der bekanntesten Bedrohungen ist.

Es ist jedoch erwähnenswert, dass **XProtect keine vollwertige Antivirus-Lösung ist**. Es überprüft nur eine spezifische Liste bekannter Bedrohungen und führt keine On-Access-Scans wie die meisten Antivirenprogramme durch.

Sie können Informationen über das neueste XProtect-Update abrufen, indem Sie: 

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect befindet sich an einem von SIP geschützten Ort unter **/Library/Apple/System/Library/CoreServices/XProtect.bundle** und im Inneren des Bundles finden Sie Informationen, die XProtect verwendet:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Erlaubt Code mit diesen cdhashes, Legacy-Berechtigungen zu verwenden.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Liste von Plugins und Erweiterungen, die über BundleID und TeamID oder durch Angabe einer Mindestversion nicht geladen werden dürfen.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara-Regeln zur Erkennung von Malware.
* **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3-Datenbank mit Hashes blockierter Anwendungen und TeamIDs.

Beachten Sie, dass es eine weitere App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** gibt, die mit XProtect in Verbindung steht, aber nicht am Gatekeeper-Prozess beteiligt ist.

### Nicht Gatekeeper

{% hint style="danger" %}
Beachten Sie, dass Gatekeeper **nicht jedes Mal ausgeführt wird**, wenn Sie eine Anwendung ausführen, sondern nur _**AppleMobileFileIntegrity**_ (AMFI) **ausführbare Codesignaturen** überprüft, wenn Sie eine App ausführen, die bereits von Gatekeeper ausgeführt und überprüft wurde.
{% endhint %}

Daher war es zuvor möglich, eine App auszuführen, um sie mit Gatekeeper zu cachen, dann **nicht ausführbare Dateien der Anwendung zu modifizieren** (wie Electron asar oder NIB-Dateien) und wenn keine anderen Schutzmaßnahmen vorhanden waren, wurde die Anwendung mit den **bösartigen** Ergänzungen **ausgeführt**.

Jetzt ist dies jedoch nicht mehr möglich, da macOS **das Modifizieren von Dateien** innerhalb von Anwendungsbundles verhindert. Wenn Sie also den [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) Angriff versuchen, werden Sie feststellen, dass es nicht mehr möglich ist, ihn auszunutzen, da Sie nach dem Ausführen der App, um sie mit Gatekeeper zu cachen, das Bundle nicht mehr ändern können. Und wenn Sie beispielsweise den Namen des Contents-Verzeichnisses in NotCon ändern (wie im Exploit angegeben) und dann die Hauptbinärdatei der App ausführen, um sie mit Gatekeeper zu cachen, wird ein Fehler ausgelöst und sie wird nicht ausgeführt.

## Gatekeeper Umgehungen

Jede Möglichkeit, Gatekeeper zu umgehen (d.h. den Benutzer dazu zu bringen, etwas herunterzuladen und auszuführen, wenn Gatekeeper dies verhindern sollte), wird als Sicherheitsanfälligkeit in macOS betrachtet. Dies sind einige CVEs, die Techniken zugeordnet sind, die in der Vergangenheit ermöglichten, Gatekeeper zu umgehen:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Es wurde beobachtet, dass, wenn das **Archivierungsprogramm** zum Extrahieren verwendet wird, Dateien mit **Pfaden, die 886 Zeichen überschreiten**, das erweiterte Attribut com.apple.quarantine nicht erhalten. Diese Situation ermöglicht es versehentlich, dass diese Dateien **Gatekeepers** Sicherheitsüberprüfungen **umgehen**.

Überprüfen Sie den [**originalen Bericht**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) für weitere Informationen.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wenn eine Anwendung mit **Automator** erstellt wird, befinden sich die Informationen darüber, was sie benötigt, um ausgeführt zu werden, in `application.app/Contents/document.wflow`, nicht im ausführbaren Programm. Das ausführbare Programm ist nur ein generisches Automator-Binärprogramm namens **Automator Application Stub**.

Daher könnten Sie `application.app/Contents/MacOS/Automator\ Application\ Stub` **mit einem symbolischen Link auf einen anderen Automator Application Stub im System verweisen** und es wird das ausführen, was sich in `document.wflow` (Ihr Skript) befindet, **ohne Gatekeeper auszulösen**, da das tatsächliche ausführbare Programm nicht das Quarantäne-xattr hat.

Beispiel für den erwarteten Speicherort: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Überprüfen Sie den [**originalen Bericht**](https://ronmasas.com/posts/bypass-macos-gatekeeper) für weitere Informationen.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bei dieser Umgehung wurde eine Zip-Datei erstellt, die mit einer Anwendung begann, die von `application.app/Contents` anstelle von `application.app` komprimiert wurde. Daher wurde das **Quarantäne-Attribut** auf alle **Dateien von `application.app/Contents`** angewendet, aber **nicht auf `application.app`**, was Gatekeeper überprüfte, sodass Gatekeeper umgangen wurde, weil `application.app` ausgelöst wurde und **nicht das Quarantäneattribut hatte.**
```bash
zip -r test.app/Contents test.zip
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) für weitere Informationen.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Auch wenn die Komponenten unterschiedlich sind, ist die Ausnutzung dieser Schwachstelle sehr ähnlich zu der vorherigen. In diesem Fall werden wir ein Apple-Archiv aus **`application.app/Contents`** erstellen, sodass **`application.app` das Quarantäneattribut** nicht erhält, wenn es von **Archive Utility** dekomprimiert wird.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) für weitere Informationen.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kann verwendet werden, um zu verhindern, dass jemand ein Attribut in eine Datei schreibt:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Außerdem kopiert das **AppleDouble**-Dateiformat eine Datei einschließlich ihrer ACEs.

Im [**Quellcode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) ist zu sehen, dass die textuelle Darstellung der ACL, die im xattr mit dem Namen **`com.apple.acl.text`** gespeichert ist, als ACL in der dekomprimierten Datei gesetzt wird. Wenn Sie also eine Anwendung in eine Zip-Datei im **AppleDouble**-Dateiformat mit einer ACL komprimiert haben, die das Schreiben anderer xattrs verhindert... wurde das Quarantäne-xattr nicht in die Anwendung gesetzt:

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Überprüfen Sie den [**originalen Bericht**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) für weitere Informationen.

Bitte beachten Sie, dass dies auch mit AppleArchives ausgenutzt werden könnte:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Es wurde entdeckt, dass **Google Chrome das Quarantäneattribut** für heruntergeladene Dateien aufgrund einiger interner Probleme von macOS nicht gesetzt hat.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble-Dateiformate speichern die Attribute einer Datei in einer separaten Datei, die mit `._` beginnt, dies hilft, die Dateiattribute **zwischen macOS-Maschinen** zu kopieren. Es wurde jedoch festgestellt, dass nach dem Dekomprimieren einer AppleDouble-Datei die Datei, die mit `._` beginnt, **nicht das Quarantäneattribut** erhielt.

{% code overflow="wrap" %}
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

Die Möglichkeit, eine Datei zu erstellen, die nicht das Quarantäneattribut gesetzt hat, machte es **möglich, Gatekeeper zu umgehen.** Der Trick bestand darin, eine **DMG-Datei-Anwendung** unter Verwendung der AppleDouble-Namenskonvention (beginne mit `._`) zu erstellen und eine **sichtbare Datei als symbolischen Link zu dieser versteckten** Datei ohne das Quarantäneattribut zu erstellen.\
Wenn die **dmg-Datei ausgeführt wird**, wird sie, da sie kein Quarantäneattribut hat, **Gatekeeper umgehen.**
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### uchg (aus diesem [Vortrag](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

* Erstellen Sie ein Verzeichnis, das eine App enthält.
* Fügen Sie uchg zur App hinzu.
* Komprimieren Sie die App in eine tar.gz-Datei.
* Senden Sie die tar.gz-Datei an ein Opfer.
* Das Opfer öffnet die tar.gz-Datei und führt die App aus.
* Gatekeeper überprüft die App nicht.

### Quarantäne xattr verhindern

In einem ".app"-Bundle, wenn das Quarantäne-xattr nicht hinzugefügt wird, wird beim Ausführen **Gatekeeper nicht ausgelöst**.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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

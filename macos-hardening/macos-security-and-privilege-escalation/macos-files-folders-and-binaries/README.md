# macOS Dateien, Ordner, Binärdateien & Speicher

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Null auf Heldenniveau mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Dateihierarchie-Layout

* **/Applications**: Hier sollten die installierten Apps sein. Alle Benutzer können darauf zugreifen.
* **/bin**: Befehlszeilen-Binärdateien
* **/cores**: Wenn vorhanden, wird es zum Speichern von Core-Dumps verwendet
* **/dev**: Alles wird als Datei behandelt, daher können hier Hardwaregeräte gespeichert sein.
* **/etc**: Konfigurationsdateien
* **/Library**: Hier finden Sie viele Unterverzeichnisse und Dateien, die mit Einstellungen, Caches und Protokollen zusammenhängen. Ein Library-Ordner befindet sich im Stammverzeichnis und in jedem Benutzerverzeichnis.
* **/private**: Nicht dokumentiert, aber viele der genannten Ordner sind symbolische Links zum privaten Verzeichnis.
* **/sbin**: Wesentliche Systembinärdateien (im Zusammenhang mit der Verwaltung)
* **/System**: Datei zum Ausführen von OS X. Hier sollten hauptsächlich nur Apple-spezifische Dateien (nicht von Drittanbietern) zu finden sein.
* **/tmp**: Dateien werden nach 3 Tagen gelöscht (es handelt sich um einen symbolischen Link zu /private/tmp)
* **/Users**: Benutzerverzeichnis
* **/usr**: Konfigurations- und Systembinärdateien
* **/var**: Protokolldateien
* **/Volumes**: Die eingebundenen Laufwerke werden hier angezeigt.
* **/.vol**: Wenn Sie `stat a.txt` ausführen, erhalten Sie etwas wie `16777223 7545753 -rw-r--r-- 1 Benutzername wheel ...`, wobei die erste Zahl die ID-Nummer des Volumes ist, in dem sich die Datei befindet, und die zweite Zahl die Inode-Nummer ist. Sie können auf den Inhalt dieser Datei über /.vol/ mit diesen Informationen zugreifen, indem Sie `cat /.vol/16777223/7545753` ausführen.

### Anwendungsordner

* **Systemanwendungen** befinden sich unter `/System/Applications`
* **Installierte** Anwendungen werden normalerweise in `/Applications` oder in `~/Applications` installiert
* **Anwendungsdaten** finden Sie in `/Library/Application Support` für Anwendungen, die als Root ausgeführt werden, und in `~/Library/Application Support` für Anwendungen, die als Benutzer ausgeführt werden.
* Drittanbieter-Anwendungs-**Daemons**, die **als Root ausgeführt werden müssen**, befinden sich normalerweise in `/Library/PrivilegedHelperTools/`
* **Sandboxed**-Apps werden in den Ordner `~/Library/Containers` abgebildet. Jede App hat einen Ordner, der dem Bundle-ID der Anwendung entspricht (`com.apple.Safari`).
* Der **Kernel** befindet sich in `/System/Library/Kernels/kernel`
* **Apple Kernel-Erweiterungen** befinden sich in `/System/Library/Extensions`
* **Drittanbieter-Kernel-Erweiterungen** werden in `/Library/Extensions` gespeichert

### Dateien mit sensiblen Informationen

MacOS speichert Informationen wie Passwörter an verschiedenen Orten:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### Verwundbare pkg-Installationsprogramme

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X-spezifische Erweiterungen

* **`.dmg`**: Apple Disk Image-Dateien sind sehr häufig für Installationsprogramme.
* **`.kext`**: Es muss einer bestimmten Struktur folgen und ist die OS X-Version eines Treibers (es ist ein Bundle).
* **`.plist`**: Auch als Property List bekannt, speichert Informationen im XML- oder Binärformat.
* Kann XML oder binär sein. Binäre können mit folgenden Befehlen gelesen werden:
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Apple-Anwendungen, die der Verzeichnisstruktur folgen (es ist ein Bundle).
* **`.dylib`**: Dynamische Bibliotheken (ähnlich wie Windows DLL-Dateien)
* **`.pkg`**: Sind dasselbe wie xar (eXtensible Archive-Format). Der Befehl `installer` kann verwendet werden, um den Inhalt dieser Dateien zu installieren.
* **`.DS_Store`**: Diese Datei befindet sich in jedem Verzeichnis und speichert die Attribute und Anpassungen des Verzeichnisses.
* **`.Spotlight-V100`**: Dieser Ordner erscheint im Stammverzeichnis jedes Volumes im System.
* **`.metadata_never_index`**: Wenn sich diese Datei an der Wurzel eines Volumes befindet, wird dieses Volume nicht von Spotlight indiziert.
* **`.noindex`**: Dateien und Ordner mit dieser Erweiterung werden nicht von Spotlight indiziert.

### macOS-Bundles

Ein Bundle ist ein **Verzeichnis**, das im Finder wie ein Objekt aussieht (ein Beispiel für ein Bundle sind `*.app`-Dateien).

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Shared Cache

Auf macOS (und iOS) werden alle gemeinsam genutzten Systembibliotheken wie Frameworks und Dylibs in einer einzigen Datei namens **dyld Shared Cache** kombiniert. Dadurch wird die Leistung verbessert, da der Code schneller geladen werden kann.

Ähnlich wie der dyld Shared Cache werden der Kernel und die Kernel-Erweiterungen auch in einen Kernel-Cache kompiliert, der beim Booten geladen wird.

Um die Bibliotheken aus der einzelnen Datei dylib Shared Cache zu extrahieren, war es möglich, das Binärprogramm [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) zu verwenden, das möglicherweise heutzutage nicht mehr funktioniert, aber Sie können auch [**dyldextractor**](https://github.com/arandomdev/dyldextractor) verwenden:

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

In älteren Versionen können Sie den **Shared Cache** möglicherweise in **`/System/Library/dyld/`** finden.

In iOS finden Sie sie in **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Beachten Sie, dass Sie selbst dann, wenn das Tool `dyld_shared_cache_util` nicht funktioniert, das **gemeinsame dyld-Binary an Hopper übergeben** können und Hopper in der Lage sein wird, alle Bibliotheken zu identifizieren und Ihnen die **Auswahl** zu ermöglichen, welche Sie untersuchen möchten:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Besondere Dateiberechtigungen

### Ordnerberechtigungen

In einem **Ordner** erlaubt **Lesen**, ihn **aufzulisten**, **Schreiben**, Dateien darin zu **löschen** und **Schreiben**, Dateien darin zu **erstellen**, und **Ausführen**, das Verzeichnis zu **durchsuchen**. Wenn ein Benutzer beispielsweise **Leserechte für eine Datei** in einem Verzeichnis hat, in dem er **keine Ausführungsrechte** hat, **kann er die Datei nicht lesen**.

### Flag-Modifikatoren

Es gibt einige Flags, die in den Dateien gesetzt werden können und das Verhalten der Datei beeinflussen. Sie können die Flags der Dateien in einem Verzeichnis mit `ls -lO /Pfad/Verzeichnis` überprüfen.

* **`uchg`**: Bekannt als **uchange**-Flag verhindert jegliche Änderung oder Löschung der **Datei**. Um es zu setzen, verwenden Sie: `chflags uchg datei.txt`
* Der Root-Benutzer kann das Flag **entfernen** und die Datei ändern.
* **`restricted`**: Dieses Flag bewirkt, dass die Datei durch SIP geschützt wird (Sie können dieses Flag nicht zu einer Datei hinzufügen).
* **`Sticky-Bit`**: Wenn ein Verzeichnis das Sticky-Bit hat, können nur der **Besitzer des Verzeichnisses oder der Root** Dateien umbenennen oder löschen. Normalerweise wird dies auf das /tmp-Verzeichnis gesetzt, um zu verhindern, dass normale Benutzer Dateien anderer Benutzer löschen oder verschieben.

### **Datei-ACLs**

Datei-ACLs enthalten **ACE** (Access Control Entries), mit denen granularere Berechtigungen für verschiedene Benutzer zugewiesen werden können.

Es ist möglich, einem **Verzeichnis** diese Berechtigungen zu gewähren: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Und einer **Datei**: `read`, `write`, `append`, `execute`.

Wenn die Datei ACLs enthält, finden Sie beim Auflisten der Berechtigungen ein **"+" wie in**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Sie können die ACLs der Datei mit folgendem Befehl lesen:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Sie können **alle Dateien mit ACLs** mit (dies ist seeeehr langsam) finden:
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Resource Forks | macOS ADS

Dies ist eine Möglichkeit, **Alternate Data Streams in MacOS**-Maschinen zu erhalten. Sie können Inhalte in einem erweiterten Attribut namens **com.apple.ResourceFork** in einer Datei speichern, indem Sie sie in **file/..namedfork/rsrc** speichern.
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

## **Universelle Binärdateien &** Mach-o-Format

Mac OS-Binärdateien werden normalerweise als **universelle Binärdateien** kompiliert. Eine **universelle Binärdatei** kann **mehrere Architekturen in derselben Datei unterstützen**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS-Speicherauszug

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Risikokategoriedateien Mac OS

Das Verzeichnis `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` ist der Ort, an dem Informationen über das **mit verschiedenen Dateierweiterungen verbundene Risiko gespeichert** werden. In diesem Verzeichnis werden Dateien in verschiedene Risikostufen eingeteilt, die beeinflussen, wie Safari mit diesen Dateien nach dem Download umgeht. Die Kategorien sind wie folgt:

- **LSRiskCategorySafe**: Dateien in dieser Kategorie gelten als **vollständig sicher**. Safari öffnet diese Dateien automatisch nach dem Download.
- **LSRiskCategoryNeutral**: Diese Dateien werden ohne Warnungen geliefert und werden von Safari **nicht automatisch geöffnet**.
- **LSRiskCategoryUnsafeExecutable**: Dateien in dieser Kategorie lösen eine Warnung aus, die darauf hinweist, dass es sich um eine Anwendung handelt. Dies dient als Sicherheitsmaßnahme, um den Benutzer zu warnen.
- **LSRiskCategoryMayContainUnsafeExecutable**: Diese Kategorie ist für Dateien wie Archive vorgesehen, die eine ausführbare Datei enthalten könnten. Safari löst eine Warnung aus, es sei denn, es kann überprüft werden, dass alle Inhalte sicher oder neutral sind.

## Protokolldateien

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Enthält Informationen über heruntergeladene Dateien, wie z.B. die URL, von der sie heruntergeladen wurden.
* **`/var/log/system.log`**: Hauptprotokoll der OSX-Systeme. com.apple.syslogd.plist ist für die Ausführung des Syslog-Dienstes verantwortlich (Sie können überprüfen, ob er deaktiviert ist, indem Sie nach "com.apple.syslogd" in `launchctl list` suchen).
* **`/private/var/log/asl/*.asl`**: Dies sind die Apple System Logs, die interessante Informationen enthalten können.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Speichert kürzlich geöffnete Dateien und Anwendungen über "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Speichert Elemente, die beim Systemstart gestartet werden sollen.
* **`$HOME/Library/Logs/DiskUtility.log`**: Protokolldatei für die DiskUtility-App (Informationen über Laufwerke, einschließlich USB-Geräte)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Daten über drahtlose Zugangspunkte.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Liste der deaktivierten Daemons.

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

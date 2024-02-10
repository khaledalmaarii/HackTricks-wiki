# macOS SIP

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei oder folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>

## **Grundlegende Informationen**

**System Integrity Protection (SIP)** in macOS ist ein Mechanismus, der selbst den privilegiertesten Benutzern das unbefugte Ändern wichtiger Systemordner verhindern soll. Diese Funktion spielt eine entscheidende Rolle bei der Aufrechterhaltung der Integrität des Systems, indem Aktionen wie Hinzufügen, Ändern oder Löschen von Dateien in geschützten Bereichen eingeschränkt werden. Die Hauptordner, die durch SIP geschützt sind, umfassen:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Die Regeln, die das Verhalten von SIP steuern, sind in der Konfigurationsdatei unter **`/System/Library/Sandbox/rootless.conf`** definiert. In dieser Datei werden Pfade, die mit einem Asterisk (*) beginnen, als Ausnahmen von den ansonsten strengen SIP-Beschränkungen gekennzeichnet.

Betrachten Sie das folgende Beispiel:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Dieser Ausschnitt besagt, dass SIP normalerweise das Verzeichnis **`/usr`** sichert, es jedoch spezifische Unterverzeichnisse (`/usr/libexec/cups`, `/usr/local` und `/usr/share/man`) gibt, in denen Änderungen zulässig sind, wie durch den vorangestellten Asterisk (*) vor ihren Pfaden angegeben.

Um zu überprüfen, ob ein Verzeichnis oder eine Datei durch SIP geschützt ist, können Sie den Befehl **`ls -lOd`** verwenden, um nach dem Vorhandensein der Flags **`restricted`** oder **`sunlnk`** zu suchen. Zum Beispiel:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
In diesem Fall kennzeichnet das **`sunlnk`**-Flag, dass das Verzeichnis `/usr/libexec/cups` selbst **nicht gelöscht werden kann**, obwohl Dateien darin erstellt, geändert oder gelöscht werden können.

Auf der anderen Seite:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Hier gibt das **`restricted`** Flag an, dass das Verzeichnis `/usr/libexec` durch SIP geschützt ist. In einem SIP-geschützten Verzeichnis können keine Dateien erstellt, geändert oder gelöscht werden.

Darüber hinaus wird eine Datei, die das Attribut **`com.apple.rootless`** als erweitertes **Attribut** enthält, ebenfalls durch SIP geschützt.

**SIP beschränkt auch andere Root-Aktionen** wie:

* Laden von nicht vertrauenswürdigen Kernel-Erweiterungen
* Erhalten von Task-Ports für Apple-signierte Prozesse
* Ändern von NVRAM-Variablen
* Kernel-Debugging zulassen

Die Optionen werden als Bitflag in der nvram-Variablen gespeichert (`csr-active-config` auf Intel und `lp-sip0` wird aus dem gebooteten Device Tree für ARM gelesen). Die Flags finden Sie im XNU-Quellcode in `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

### SIP-Status

Sie können mit dem folgenden Befehl überprüfen, ob SIP auf Ihrem System aktiviert ist:
```bash
csrutil status
```
Wenn Sie SIP deaktivieren möchten, müssen Sie Ihren Computer im Wiederherstellungsmodus neu starten (indem Sie während des Startvorgangs Command+R drücken) und dann den folgenden Befehl ausführen:
```bash
csrutil disable
```
Wenn Sie SIP aktiviert lassen möchten, aber die Debugging-Schutzmaßnahmen entfernen möchten, können Sie dies mit folgendem Befehl tun:
```bash
csrutil enable --without debug
```
### Weitere Einschränkungen

- **Verhindert das Laden von nicht signierten Kernel-Erweiterungen** (kexts), um sicherzustellen, dass nur verifizierte Erweiterungen mit dem Systemkernel interagieren.
- **Verhindert das Debuggen** von macOS-Systemprozessen, um Kernkomponenten des Systems vor unbefugtem Zugriff und Änderungen zu schützen.
- **Verhindert das Inspektieren von Systemprozessen** durch Tools wie dtrace, um die Integrität des Systembetriebs weiter zu schützen.

**[Erfahren Sie mehr über SIP-Informationen in diesem Vortrag](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship).**

## SIP-Umgehungen

Das Umgehen von SIP ermöglicht einem Angreifer Folgendes:

- **Zugriff auf Benutzerdaten**: Lesen sensibler Benutzerdaten wie E-Mails, Nachrichten und Safari-Verlauf aus allen Benutzerkonten.
- **TCC-Umgehung**: Direktes Manipulieren der TCC (Transparenz, Zustimmung und Kontrolle) Datenbank, um unbefugten Zugriff auf die Webcam, das Mikrofon und andere Ressourcen zu gewähren.
- **Etablierung von Persistenz**: Platzieren von Malware an SIP-geschützten Orten, um sie selbst mit Root-Rechten schwer entfernen zu können. Dies beinhaltet auch die Möglichkeit, das Malware Removal Tool (MRT) zu manipulieren.
- **Laden von Kernel-Erweiterungen**: Obwohl zusätzliche Sicherheitsvorkehrungen vorhanden sind, vereinfacht das Umgehen von SIP den Prozess des Ladens nicht signierter Kernel-Erweiterungen.

### Installationspakete

**Installationspakete, die mit Apples Zertifikat signiert sind**, können die Schutzmechanismen umgehen. Dies bedeutet, dass selbst von Standardentwicklern signierte Pakete blockiert werden, wenn sie versuchen, SIP-geschützte Verzeichnisse zu ändern.

### Nicht vorhandene SIP-Datei

Ein potenzielles Schlupfloch besteht darin, dass wenn eine Datei in **`rootless.conf` angegeben ist, aber derzeit nicht vorhanden ist**, sie erstellt werden kann. Malware könnte dies ausnutzen, um **Persistenz** im System zu etablieren. Zum Beispiel könnte ein bösartiges Programm eine .plist-Datei in `/System/Library/LaunchDaemons` erstellen, wenn sie in `rootless.conf` aufgeführt ist, aber nicht vorhanden ist.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
Die Berechtigung **`com.apple.rootless.install.heritable`** ermöglicht das Umgehen von SIP.
{% endhint %}

#### Shrootless

[**Forscher in diesem Blog-Beitrag**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) haben eine Schwachstelle im System Integrity Protection (SIP)-Mechanismus von macOS entdeckt, die als 'Shrootless'-Schwachstelle bezeichnet wird. Diese Schwachstelle betrifft den **`system_installd`**-Daemon, der eine Berechtigung **`com.apple.rootless.install.heritable`** hat, die es seinen Kindprozessen ermöglicht, die Dateisystembeschränkungen von SIP zu umgehen.

Der **`system_installd`**-Daemon installiert Pakete, die von **Apple** signiert wurden.

Die Forscher stellten fest, dass während der Installation eines von Apple signierten Pakets (.pkg-Datei) **`system_installd`** alle im Paket enthaltenen **post-install**-Skripte ausführt. Diese Skripte werden von der Standard-Shell **`zsh`** ausgeführt, die automatisch Befehle aus der Datei **`/etc/zshenv`** ausführt, sofern sie existiert, auch im nicht-interaktiven Modus. Diese Verhaltensweise könnte von Angreifern ausgenutzt werden: Durch Erstellen einer bösartigen `/etc/zshenv`-Datei und Warten auf die Ausführung von `zsh` durch **`system_installd`** könnten sie beliebige Operationen auf dem Gerät durchführen.

Darüber hinaus wurde festgestellt, dass **`/etc/zshenv` als allgemeine Angriffstechnik** verwendet werden kann, nicht nur für eine SIP-Umgehung. Jedes Benutzerprofil verfügt über eine `~/.zshenv`-Datei, die sich genauso verhält wie `/etc/zshenv`, jedoch keine Root-Berechtigungen erfordert. Diese Datei könnte als Persistenzmechanismus verwendet werden, der jedes Mal ausgelöst wird, wenn `zsh` gestartet wird, oder als Mechanismus zur Erhöhung von Privilegien. Wenn ein Administrator-Benutzer mit `sudo -s` oder `sudo <Befehl>` zu Root-Benutzerrechten wechselt, wird die `~/.zshenv`-Datei ausgelöst und es erfolgt eine effektive Erhöhung zu Root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

In [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) wurde festgestellt, dass der gleiche **`system_installd`**-Prozess immer noch missbraucht werden konnte, da er das **post-install**-Skript in einem zufällig benannten Ordner innerhalb von SIP in `/tmp` platzierte. Das Problem ist, dass **`/tmp` selbst nicht von SIP geschützt ist**, sodass es möglich war, ein virtuelles Image darauf zu mounten. Anschließend würde der **Installer** das **post-install**-Skript dort platzieren, das virtuelle Image aushängen, alle Ordner neu erstellen und das **post-install**-Skript mit dem auszuführenden **Payload** hinzufügen.

#### [fsck\_cs-Dienstprogramm](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Es wurde eine Schwachstelle identifiziert, bei der **`fsck_cs`** durch die Möglichkeit, **symbolische Links** zu folgen, dazu verleitet wurde, eine wichtige Datei zu beschädigen. Konkret haben Angreifer einen Link von _`/dev/diskX`_ zur Datei `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` erstellt. Das Ausführen von **`fsck_cs`** auf _`/dev/diskX`_ führte zur Beschädigung von `Info.plist`. Die Integrität dieser Datei ist für die System Integrity Protection (SIP) des Betriebssystems, die das Laden von Kernel-Erweiterungen steuert, entscheidend. Sobald sie beschädigt ist, ist die Fähigkeit von SIP, Kernel-Ausschlüsse zu verwalten, beeinträchtigt.

Die Befehle zur Ausnutzung dieser Schwachstelle lauten:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Die Ausnutzung dieser Schwachstelle hat schwerwiegende Auswirkungen. Die `Info.plist`-Datei, die normalerweise für die Verwaltung von Berechtigungen für Kernel-Erweiterungen zuständig ist, wird unwirksam. Dies beinhaltet die Unfähigkeit, bestimmte Erweiterungen wie `AppleHWAccess.kext` auf die Blacklist zu setzen. Folglich kann mit dem außer Kraft gesetzten Kontrollmechanismus von SIP diese Erweiterung geladen werden, was unbefugten Lese- und Schreibzugriff auf den Arbeitsspeicher des Systems ermöglicht.


#### [Mounten über SIP-geschützte Ordner](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Es war möglich, ein neues Dateisystem über **SIP-geschützte Ordner zu mounten, um den Schutz zu umgehen**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader-Bypass (2016)](https://objective-see.org/blog/blog\_0x14.html)

Das System ist so eingestellt, dass es von einem eingebetteten Installations-Disk-Image innerhalb der `Install macOS Sierra.app` startet, um das Betriebssystem zu aktualisieren. Dabei wird das Dienstprogramm `bless` verwendet. Der verwendete Befehl lautet wie folgt:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Die Sicherheit dieses Prozesses kann beeinträchtigt werden, wenn ein Angreifer das Upgrade-Image (`InstallESD.dmg`) vor dem Booten ändert. Die Strategie besteht darin, einen dynamischen Loader (dyld) durch eine bösartige Version (`libBaseIA.dylib`) zu ersetzen. Diese Ersetzung führt zur Ausführung des Codes des Angreifers, wenn der Installer gestartet wird.

Der Code des Angreifers übernimmt während des Upgrade-Prozesses die Kontrolle und nutzt das Vertrauen des Systems in den Installer aus. Der Angriff erfolgt durch Änderung des `InstallESD.dmg`-Images über Method Swizzling, wobei insbesondere die Methode `extractBootBits` ins Visier genommen wird. Dadurch wird die Injektion von bösartigem Code vor der Verwendung des Disk-Images ermöglicht.

Darüber hinaus gibt es innerhalb des `InstallESD.dmg` ein `BaseSystem.dmg`, das als Wurzeldateisystem des Upgrade-Codes dient. Durch das Injizieren einer dynamischen Bibliothek in diese Datei kann der bösartige Code in einem Prozess ausgeführt werden, der in der Lage ist, OS-Level-Dateien zu ändern, was das Potenzial für eine Kompromittierung des Systems erheblich erhöht.


#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In diesem Vortrag von [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) wird gezeigt, wie **`systemmigrationd`** (das SIP umgehen kann) ein **bash**- und ein **perl**-Skript ausführt, die über Umgebungsvariablen **`BASH_ENV`** und **`PERL5OPT`** missbraucht werden können.

### **com.apple.rootless.install**

{% hint style="danger" %}
Die Berechtigung **`com.apple.rootless.install`** ermöglicht das Umgehen von SIP.
{% endhint %}

Die Berechtigung `com.apple.rootless.install` umgeht den System Integrity Protection (SIP) auf macOS. Dies wurde insbesondere im Zusammenhang mit [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) erwähnt.

In diesem speziellen Fall besitzt der System-XPC-Dienst unter `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` diese Berechtigung. Dadurch kann der zugehörige Prozess SIP-Beschränkungen umgehen. Darüber hinaus bietet dieser Dienst eine Methode, die den Dateiverschiebungsprozess ohne Anwendung von Sicherheitsmaßnahmen ermöglicht.


## Versiegelte System-Snapshots

Versiegelte System-Snapshots sind eine Funktion, die von Apple in **macOS Big Sur (macOS 11)** als Teil seines **System Integrity Protection (SIP)**-Mechanismus eingeführt wurde, um eine zusätzliche Sicherheitsschicht und Systemstabilität zu bieten. Sie sind im Wesentlichen schreibgeschützte Versionen des Systemvolumes.

Hier ist ein detaillierterer Blick darauf:

1. **Unveränderliches System**: Versiegelte System-Snapshots machen das macOS-Systemvolume "unveränderlich", was bedeutet, dass es nicht geändert werden kann. Dadurch wird verhindert, dass unbefugte oder versehentliche Änderungen am System vorgenommen werden, die die Sicherheit oder Systemstabilität gefährden könnten.
2. **Systemsoftware-Updates**: Wenn Sie macOS-Updates oder -Upgrades installieren, erstellt macOS einen neuen System-Snapshot. Das macOS-Startvolume verwendet dann **APFS (Apple File System)**, um zu diesem neuen Snapshot zu wechseln. Der gesamte Prozess der Anwendung von Updates wird sicherer und zuverlässiger, da das System immer auf den vorherigen Snapshot zurückgreifen kann, wenn während des Updates etwas schief geht.
3. **Daten-Trennung**: In Verbindung mit dem Konzept der Trennung von Daten- und Systemvolumes, das in macOS Catalina eingeführt wurde, stellt die Funktion "Versiegelte System-Snapshots" sicher, dass alle Ihre Daten und Einstellungen auf einem separaten "**Daten**"-Volume gespeichert werden. Diese Trennung macht Ihre Daten unabhängig vom System, was den Prozess der Systemupdates vereinfacht und die Systemsicherheit verbessert.

Bitte beachten Sie, dass diese Snapshots automatisch von macOS verwaltet werden und dank der Speicherfreigabefunktionen von APFS keinen zusätzlichen Speicherplatz auf Ihrer Festplatte belegen. Es ist auch wichtig zu beachten, dass diese Snapshots sich von **Time Machine-Snapshots** unterscheiden, die benutzerzugängliche Backups des gesamten Systems sind.

### Snapshots überprüfen

Der Befehl **`diskutil apfs list`** listet die **Details der APFS-Volumes** und deren Layout auf:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494,4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219,2 GB) (44,3% verwendet)
|   Capacity Not Allocated:       275170258944 B (275,2 GB) (55,7% frei)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494,4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Rolle):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Groß-/Kleinschreibung wird nicht beachtet)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12,8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Ja (Entsperrt)
|   |   Verschlüsselt:             Nein
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Ja
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Rolle):   disk3s5 (Daten)
|   Name:                      Macintosh HD - Daten (Groß-/Kleinschreibung wird nicht beachtet)
<strong>    |   Mount Point:               /System/Volumes/Daten
</strong><strong>    |   Capacity Consumed:         412071784448 B (412,1 GB)
</strong>    |   Versiegelt:                Nein
|   FileVault:                 Ja (Entsperrt)
</code></pre>

In der vorherigen Ausgabe ist zu sehen, dass **benutzerzugängliche Speicherorte** unter `/System/Volumes/Daten` eingebunden sind.

Darüber hinaus ist das **macOS-Systemvolumesnapshot** unter `/` eingebunden und es ist **versiegelt** (kryptografisch vom Betriebssystem signiert). Wenn SIP umgangen und modifiziert wird, startet das **Betriebssystem nicht mehr**.

Es ist auch möglich, **zu überprüfen, ob die Versiegelung aktiviert ist**, indem man Folgendes ausführt:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Darüber hinaus wird das Snapshot-Laufwerk auch als **schreibgeschützt** eingebunden:
```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

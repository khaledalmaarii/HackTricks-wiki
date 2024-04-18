# macOS SIP

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe zu bekämpfen, die aus informationsstehlender Malware resultieren.

Sie können ihre Website besuchen und ihren Motor **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

---

## **Grundlegende Informationen**

**System Integrity Protection (SIP)** in macOS ist ein Mechanismus, der selbst den privilegiertesten Benutzern verhindern soll, unbefugte Änderungen an wichtigen Systemordnern vorzunehmen. Diese Funktion spielt eine entscheidende Rolle bei der Aufrechterhaltung der Integrität des Systems, indem Aktionen wie Hinzufügen, Ändern oder Löschen von Dateien in geschützten Bereichen eingeschränkt werden. Die primären Ordner, die von SIP geschützt sind, umfassen:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Die Regeln, die das Verhalten von SIP steuern, sind in der Konfigurationsdatei definiert, die sich unter **`/System/Library/Sandbox/rootless.conf`** befindet. In dieser Datei werden Pfade, die mit einem Stern (\*) versehen sind, als Ausnahmen von den ansonsten strengen SIP-Beschränkungen gekennzeichnet.

Betrachten Sie das folgende Beispiel:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Dieser Ausschnitt deutet darauf hin, dass SIP im Allgemeinen das Verzeichnis **`/usr`** sichert, es jedoch spezifische Unterverzeichnisse (`/usr/libexec/cups`, `/usr/local` und `/usr/share/man`) gibt, in denen Änderungen zulässig sind, wie durch den vorangestellten Asterisk (\*) vor ihren Pfaden angezeigt.

Um zu überprüfen, ob ein Verzeichnis oder eine Datei durch SIP geschützt ist, können Sie den Befehl **`ls -lOd`** verwenden, um nach dem Vorhandensein des Flags **`restricted`** oder **`sunlnk`** zu überprüfen. Zum Beispiel:
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
Hier zeigt das **`restricted`**-Flag an, dass das Verzeichnis `/usr/libexec` durch SIP geschützt ist. In einem durch SIP geschützten Verzeichnis können keine Dateien erstellt, geändert oder gelöscht werden.

Darüber hinaus wird eine Datei auch durch SIP geschützt, wenn sie das Attribut **`com.apple.rootless`** als erweitertes **Attribut** enthält.

**SIP beschränkt auch andere Root-Aktionen** wie:

* Laden nicht vertrauenswürdiger Kernel-Erweiterungen
* Abrufen von Task-Ports für Apple-signierte Prozesse
* Ändern von NVRAM-Variablen
* Kernel-Debugging zulassen

Optionen werden in der nvram-Variablen als Bitflag (`csr-active-config` auf Intel und `lp-sip0` wird aus dem gebooteten Gerätebaum für ARM gelesen) beibehalten. Sie können die Flags im XNU-Quellcode in `csr.sh` finden:

<figure><img src="../../../.gitbook/assets/image (1189).png" alt=""><figcaption></figcaption></figure>

### SIP-Status

Sie können überprüfen, ob SIP auf Ihrem System aktiviert ist, mit dem folgenden Befehl:
```bash
csrutil status
```
Wenn Sie SIP deaktivieren müssen, müssen Sie Ihren Computer im Wiederherstellungsmodus neu starten (indem Sie während des Startvorgangs Befehl+R drücken) und dann den folgenden Befehl ausführen:
```bash
csrutil disable
```
Wenn Sie SIP aktiviert lassen, aber Debugging-Schutzmaßnahmen entfernen möchten, können Sie dies mit:
```bash
csrutil enable --without debug
```
### Weitere Einschränkungen

* **Verhindert das Laden von nicht signierten Kernelerweiterungen** (kexts), um sicherzustellen, dass nur überprüfte Erweiterungen mit dem Systemkernel interagieren.
* **Verhindert das Debuggen** von macOS-Systemprozessen, schützt Kernsystemkomponenten vor unbefugtem Zugriff und Änderungen.
* **Hemmt Tools** wie dtrace daran, Systemprozesse zu inspizieren, was die Integrität des Systembetriebs weiter schützt.

[**Erfahren Sie mehr über SIP-Informationen in diesem Vortrag**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

## SIP-Umgehungen

Das Umgehen von SIP ermöglicht einem Angreifer:

* **Zugriff auf Benutzerdaten**: Lesen sensibler Benutzerdaten wie E-Mails, Nachrichten und Safari-Verlauf aus allen Benutzerkonten.
* **TCC-Umgehung**: Direktes Manipulieren der TCC (Transparenz, Einwilligung und Kontrolle) Datenbank, um unbefugten Zugriff auf die Webcam, das Mikrofon und andere Ressourcen zu gewähren.
* **Etablierung von Persistenz**: Platzieren von Malware an SIP-geschützten Orten, was sie gegen Entfernung, selbst durch Root-Privilegien, widerstandsfähig macht. Dies beinhaltet auch das Potenzial, das Malware Removal Tool (MRT) zu manipulieren.
* **Laden von Kernelerweiterungen**: Obwohl es zusätzliche Sicherheitsvorkehrungen gibt, vereinfacht das Umgehen von SIP den Prozess des Ladens nicht signierter Kernelerweiterungen.

### Installationspakete

**Installationspakete, die mit Apples Zertifikat signiert sind**, können seine Schutzmechanismen umgehen. Das bedeutet, dass selbst Pakete, die von Standardentwicklern signiert sind, blockiert werden, wenn sie versuchen, SIP-geschützte Verzeichnisse zu ändern.

### Nicht vorhandene SIP-Datei

Ein potenzielles Schlupfloch besteht darin, dass, wenn eine Datei in **`rootless.conf` angegeben ist, aber derzeit nicht existiert**, sie erstellt werden kann. Malware könnte dies ausnutzen, um **Persistenz** im System zu etablieren. Zum Beispiel könnte ein bösartiges Programm eine .plist-Datei in `/System/Library/LaunchDaemons` erstellen, wenn sie in `rootless.conf` aufgeführt ist, aber nicht vorhanden ist.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
Die Berechtigung **`com.apple.rootless.install.heritable`** ermöglicht das Umgehen von SIP.
{% endhint%}

#### Shrootless

[**Forscher aus diesem Blog-Beitrag**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) entdeckten eine Schwachstelle im Mechanismus der Systemintegritätsschutz (SIP) von macOS, die als 'Shrootless'-Schwachstelle bezeichnet wird. Diese Schwachstelle konzentriert sich auf den **`system_installd`**-Daemon, der eine Berechtigung, **`com.apple.rootless.install.heritable`**, hat, die es einem seiner Kindprozesse ermöglicht, die Dateisystembeschränkungen von SIP zu umgehen.

Der **`system_installd`**-Daemon installiert Pakete, die von **Apple** signiert wurden.

Forscher fanden heraus, dass während der Installation eines von Apple signierten Pakets (.pkg-Datei) **`system_installd`** alle **post-install**-Skripte ausführt, die im Paket enthalten sind. Diese Skripte werden von der Standard-Shell, **`zsh`**, ausgeführt, die automatisch Befehle aus der Datei **`/etc/zshenv`** ausführt, wenn sie existiert, selbst im nicht-interaktiven Modus. Diese Verhaltensweise könnte von Angreifern ausgenutzt werden: Durch Erstellen einer bösartigen `/etc/zshenv`-Datei und Warten darauf, dass **`system_installd` `zsh` aufruft**, könnten sie beliebige Operationen auf dem Gerät durchführen.

Darüber hinaus wurde entdeckt, dass **`/etc/zshenv` als allgemeine Angriffstechnik verwendet werden konnte**, nicht nur für einen SIP-Umgehung. Jedes Benutzerprofil hat eine `~/.zshenv`-Datei, die sich genauso verhält wie `/etc/zshenv`, aber keine Root-Berechtigungen erfordert. Diese Datei könnte als Persistenzmechanismus verwendet werden, der jedes Mal ausgelöst wird, wenn `zsh` startet, oder als Mechanismus zur Erhöhung von Privilegien. Wenn ein Admin-Benutzer mit `sudo -s` oder `sudo <Befehl>` zu Root-Berechtigungen aufsteigt, würde die `~/.zshenv`-Datei ausgelöst, was effektiv zu Root-Berechtigungen führt.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

In [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) wurde entdeckt, dass derselbe **`system_installd`**-Prozess missbraucht werden konnte, da er das **post-install-Skript in einem zufällig benannten Ordner innerhalb von `/tmp`** platzierte, der von SIP geschützt war. Das Problem ist, dass **`/tmp` selbst nicht von SIP geschützt ist**, daher war es möglich, ein **virtuelles Image darauf zu mounten**, dann würde der **Installer** das **post-install-Skript** dort platzieren, das virtuelle Image **aushängen**, alle **Ordner neu erstellen** und das **Post-Installations**-Skript mit dem **Payload** zur Ausführung hinzufügen.

#### [fsck\_cs-Dienstprogramm](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Es wurde eine Schwachstelle identifiziert, bei der **`fsck_cs`** in die Irre geführt wurde, eine wichtige Datei zu beschädigen, aufgrund seiner Fähigkeit, **symbolische Links** zu folgen. Speziell haben Angreifer einen Link von _`/dev/diskX`_ zur Datei `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` erstellt. Das Ausführen von **`fsck_cs`** auf _`/dev/diskX`_ führte zur Beschädigung von `Info.plist`. Die Integrität dieser Datei ist für den Systemintegritätsschutz (SIP) des Betriebssystems entscheidend, der das Laden von Kernelerweiterungen steuert. Sobald sie beschädigt ist, ist die Fähigkeit von SIP, Kernelausschlüsse zu verwalten, beeinträchtigt.

Die Befehle zur Ausnutzung dieser Schwachstelle sind:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Die Ausnutzung dieser Schwachstelle hat schwerwiegende Auswirkungen. Die `Info.plist`-Datei, die normalerweise für die Verwaltung von Berechtigungen für Kernel-Erweiterungen zuständig ist, wird unwirksam. Dies beinhaltet die Unfähigkeit, bestimmte Erweiterungen wie `AppleHWAccess.kext` auf die Blacklist zu setzen. Folglich kann mit dem Kontrollmechanismus des SIP außer Kraft gesetzt diese Erweiterung geladen werden, was unbefugten Lese- und Schreibzugriff auf den RAM des Systems ermöglicht.

#### [Einbinden über SIP-geschützte Ordner](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Es war möglich, ein neues Dateisystem über **SIP-geschützten Ordnern einzubinden, um den Schutz zu umgehen**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader-Bypass (2016)](https://objective-see.org/blog/blog\_0x14.html)

Das System ist so eingestellt, dass es von einem eingebetteten Installationsdatenträger-Abbild innerhalb der `Install macOS Sierra.app` startet, um das Betriebssystem zu aktualisieren, unter Verwendung des `bless`-Dienstprogramms. Der verwendete Befehl lautet wie folgt:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Die Sicherheit dieses Prozesses kann kompromittiert werden, wenn ein Angreifer das Upgrade-Image (`InstallESD.dmg`) vor dem Booten ändert. Die Strategie beinhaltet den Austausch eines dynamischen Ladeprogramms (dyld) durch eine bösartige Version (`libBaseIA.dylib`). Diese Ersetzung führt zur Ausführung des Codes des Angreifers, wenn der Installer gestartet wird.

Der Code des Angreifers übernimmt während des Upgrade-Prozesses die Kontrolle, indem er das Vertrauen des Systems in den Installer ausnutzt. Der Angriff erfolgt durch die Änderung des `InstallESD.dmg`-Images mittels Method Swizzling, wobei insbesondere die Methode `extractBootBits` ins Visier genommen wird. Dies ermöglicht die Einschleusung von bösartigem Code, bevor das Disk-Image verwendet wird.

Darüber hinaus gibt es innerhalb des `InstallESD.dmg` ein `BaseSystem.dmg`, das als Wurzeldateisystem des Upgrade-Codes dient. Durch das Einschleusen einer dynamischen Bibliothek in diese Datei kann der bösartige Code in einem Prozess ausgeführt werden, der in der Lage ist, OS-Level-Dateien zu ändern, was das Potenzial für eine Systemkompromittierung erheblich erhöht.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In diesem Vortrag von [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) wird gezeigt, wie **`systemmigrationd`** (das SIP umgehen kann) ein **bash**- und ein **perl**-Skript ausführt, die über Umgebungsvariablen **`BASH_ENV`** und **`PERL5OPT`** missbraucht werden können.

### **com.apple.rootless.install**

{% hint style="danger" %}
Die Berechtigung **`com.apple.rootless.install`** ermöglicht das Umgehen von SIP
{% endhint %}

Die Berechtigung `com.apple.rootless.install` ist bekannt dafür, die System Integrity Protection (SIP) auf macOS zu umgehen. Dies wurde insbesondere im Zusammenhang mit [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) erwähnt.

In diesem speziellen Fall besitzt der System-XPC-Dienst unter `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` diese Berechtigung. Dies ermöglicht es dem zugehörigen Prozess, SIP-Beschränkungen zu umgehen. Darüber hinaus bietet dieser Dienst eine Methode, die das Verschieben von Dateien ohne Durchsetzung von Sicherheitsmaßnahmen ermöglicht.

## Versiegelte System-Snapshots

Versiegelte System-Snapshots sind eine Funktion, die von Apple in **macOS Big Sur (macOS 11)** als Teil ihres **System Integrity Protection (SIP)**-Mechanismus eingeführt wurde, um eine zusätzliche Sicherheitsebene und Systemstabilität zu bieten. Sie sind im Wesentlichen schreibgeschützte Versionen des Systemvolumens.

Hier ist ein detaillierterer Blick darauf:

1. **Unveränderliches System**: Versiegelte System-Snapshots machen das macOS-Systemvolumen "unveränderlich", was bedeutet, dass es nicht geändert werden kann. Dies verhindert unbefugte oder versehentliche Änderungen am System, die die Sicherheit oder Stabilität des Systems gefährden könnten.
2. **Systemsoftware-Updates**: Wenn Sie macOS-Updates oder -Upgrades installieren, erstellt macOS einen neuen System-Snapshot. Das macOS-Startvolumen verwendet dann **APFS (Apple File System)**, um zu diesem neuen Snapshot zu wechseln. Der gesamte Prozess der Anwendung von Updates wird sicherer und zuverlässiger, da das System immer zum vorherigen Snapshot zurückkehren kann, wenn während des Updates etwas schief geht.
3. **Daten-Trennung**: In Verbindung mit dem Konzept der Trennung von Daten- und Systemvolumen, das in macOS Catalina eingeführt wurde, stellt die Funktion der versiegelten System-Snapshots sicher, dass alle Ihre Daten und Einstellungen auf einem separaten "**Daten**"-Volumen gespeichert sind. Diese Trennung macht Ihre Daten unabhängig vom System, was den Prozess von Systemupdates vereinfacht und die Systemsicherheit verbessert.

Denken Sie daran, dass diese Snapshots automatisch von macOS verwaltet werden und dank der Speicherfreigabefunktionen von APFS keinen zusätzlichen Speicherplatz auf Ihrer Festplatte belegen. Es ist auch wichtig zu beachten, dass diese Snapshots sich von **Time Machine-Snapshots** unterscheiden, die benutzerzugängliche Backups des gesamten Systems sind.

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
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12,8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412,1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

In der vorherigen Ausgabe ist zu sehen, dass **benutzerzugängliche Standorte** unter `/System/Volumes/Data` eingehängt sind.

Darüber hinaus ist der **macOS-Systemvolumen-Snapshot** unter `/` eingehängt und er ist **versiegelt** (kryptografisch von macOS signiert). Wenn SIP umgangen und dieser geändert wird, wird das **Betriebssystem nicht mehr starten**.

Es ist auch möglich zu **überprüfen, ob die Versiegelung aktiviert ist**, indem man Folgendes ausführt:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Darüber hinaus wird das Snapshot-Laufwerk auch als **schreibgeschützt** eingebunden:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die kostenlose Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihre Suchmaschine **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** möchten oder **HackTricks im PDF-Format herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

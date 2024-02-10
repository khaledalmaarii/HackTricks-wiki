# macOS Memory Dumping

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Speicherartefakte

### Auslagerungsdateien

Auslagerungsdateien wie `/private/var/vm/swapfile0` dienen als **Caches, wenn der physische Speicher voll ist**. Wenn im physischen Speicher kein Platz mehr ist, wird seine Daten in eine Auslagerungsdatei übertragen und bei Bedarf wieder in den physischen Speicher zurückgebracht. Es können mehrere Auslagerungsdateien vorhanden sein, mit Namen wie swapfile0, swapfile1 usw.

### Ruhezustandsabbild

Die Datei `/private/var/vm/sleepimage`, die sich im Ruhezustand befindet, ist entscheidend. **Daten aus dem Speicher werden in dieser Datei gespeichert, wenn macOS in den Ruhezustand versetzt wird**. Beim Aufwecken des Computers ruft das System die Speicherdaten aus dieser Datei ab, sodass der Benutzer dort weitermachen kann, wo er aufgehört hat.

Es ist erwähnenswert, dass diese Datei auf modernen macOS-Systemen aus Sicherheitsgründen in der Regel verschlüsselt ist, was die Wiederherstellung erschwert.

* Um zu überprüfen, ob die Verschlüsselung für das Ruhezustandsabbild aktiviert ist, kann der Befehl `sysctl vm.swapusage` ausgeführt werden. Dadurch wird angezeigt, ob die Datei verschlüsselt ist.

### Speicherdruckprotokolle

Eine weitere wichtige speicherbezogene Datei in macOS-Systemen ist das **Speicherdruckprotokoll**. Diese Protokolle befinden sich in `/var/log` und enthalten detaillierte Informationen zur Speichernutzung und zu Speicherdruckereignissen des Systems. Sie können besonders nützlich sein, um speicherbezogene Probleme zu diagnostizieren oder zu verstehen, wie das System den Speicher im Laufe der Zeit verwaltet.

## Speicher dumpen mit osxpmem

Um den Speicher in einem macOS-Gerät zu dumpen, können Sie [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) verwenden.

**Hinweis**: Die folgenden Anweisungen funktionieren nur für Macs mit Intel-Architektur. Dieses Tool ist jetzt archiviert und die letzte Version wurde 2017 veröffentlicht. Die mit den folgenden Anweisungen heruntergeladene Binärdatei zielt auf Intel-Chips ab, da Apple Silicon im Jahr 2017 noch nicht verfügbar war. Es ist möglicherweise möglich, die Binärdatei für die arm64-Architektur zu kompilieren, aber Sie müssen es selbst ausprobieren.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Wenn Sie diesen Fehler finden: `osxpmem.app/MacPmem.kext konnte nicht geladen werden - (libkern/kext) Authentifizierungsfehler (Dateibesitz/Berechtigungen); überprüfen Sie die System-/Kernelprotokolle auf Fehler oder versuchen Sie es mit kextutil(8)` Sie können es beheben, indem Sie Folgendes tun:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Andere Fehler** können behoben werden, indem Sie das Laden des Kexts in "Sicherheit & Datenschutz --> Allgemein" **zulassen**, einfach erlauben.

Sie können auch diese **Oneliner** verwenden, um die Anwendung herunterzuladen, den Kext zu laden und den Speicher zu dumpen:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

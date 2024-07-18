# macOS Speicherauszug

{% hint style="success" %}
Lernen Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys einreichen.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihren Dienst **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

***

## Speicherartefakte

### Auslagerungsdateien

Auslagerungsdateien wie `/private/var/vm/swapfile0` dienen als **Zwischenspeicher, wenn der physische Speicher voll ist**. Wenn im physischen Speicher kein Platz mehr ist, werden die Daten in eine Auslagerungsdatei übertragen und bei Bedarf wieder in den physischen Speicher zurückgebracht. Es können mehrere Auslagerungsdateien vorhanden sein, mit Namen wie swapfile0, swapfile1 usw.

### Ruhezustandsabbild

Die Datei `/private/var/vm/sleepimage`, die sich im **Ruhezustand** befindet, ist entscheidend. **Daten aus dem Speicher werden in dieser Datei gespeichert, wenn macOS in den Ruhezustand versetzt wird**. Beim Aufwecken des Computers ruft das System die Speicherdaten aus dieser Datei ab, sodass der Benutzer dort weitermachen kann, wo er aufgehört hat.

Es ist erwähnenswert, dass diese Datei auf modernen MacOS-Systemen aus Sicherheitsgründen in der Regel verschlüsselt ist, was die Wiederherstellung erschwert.

* Um zu überprüfen, ob die Verschlüsselung für das sleepimage aktiviert ist, kann der Befehl `sysctl vm.swapusage` ausgeführt werden. Dies zeigt an, ob die Datei verschlüsselt ist.

### Speicherdruckprotokolle

Eine weitere wichtige speicherbezogene Datei in MacOS-Systemen sind die **Speicherdruckprotokolle**. Diese Protokolle befinden sich in `/var/log` und enthalten detaillierte Informationen zur Speicherauslastung des Systems und zu Druckereignissen. Sie können besonders nützlich sein, um speicherbezogene Probleme zu diagnostizieren oder zu verstehen, wie das System den Speicher im Laufe der Zeit verwaltet.

## Speicherauszug mit osxpmem

Um den Speicher in einem MacOS-Gerät auszulesen, können Sie [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) verwenden.

**Hinweis**: Die folgenden Anweisungen funktionieren nur für Macs mit Intel-Architektur. Dieses Tool ist jetzt archiviert und die letzte Version stammt aus dem Jahr 2017. Die mit den folgenden Anweisungen heruntergeladene Binärdatei zielt auf Intel-Chips ab, da Apple Silicon im Jahr 2017 noch nicht existierte. Es ist möglicherweise möglich, die Binärdatei für die arm64-Architektur zu kompilieren, aber Sie müssen es selbst versuchen.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Wenn Sie diesen Fehler finden: `osxpmem.app/MacPmem.kext konnte nicht geladen werden - (libkern/kext) Authentifizierungsfehler (Dateibesitz/Berechtigungen); überprüfen Sie die System-/Kernelprotokolle auf Fehler oder versuchen Sie kextutil(8)` Sie können es beheben, indem Sie:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Andere Fehler** können behoben werden, indem Sie das Laden des kext in "Sicherheit & Datenschutz --> Allgemein" **zulassen**, einfach **zulassen**.

Sie können auch diesen **Oneliner** verwenden, um die Anwendung herunterzuladen, den kext zu laden und den Speicher zu dumpen:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die kostenlose Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe zu bekämpfen, die durch informationsstehlende Malware verursacht werden.

Sie können ihre Website besuchen und ihre Suchmaschine **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
{% endhint %}

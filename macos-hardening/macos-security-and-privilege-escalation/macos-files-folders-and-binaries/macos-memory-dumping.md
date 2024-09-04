# macOS Memory Dumping

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


## Memory Artifacts

### Swap Files

Swap-Dateien, wie `/private/var/vm/swapfile0`, dienen als **Caches, wenn der physische Speicher voll ist**. Wenn im physischen Speicher kein Platz mehr ist, werden die Daten in eine Swap-Datei übertragen und bei Bedarf wieder in den physischen Speicher zurückgebracht. Es können mehrere Swap-Dateien vorhanden sein, mit Namen wie swapfile0, swapfile1 und so weiter.

### Hibernate Image

Die Datei, die sich unter `/private/var/vm/sleepimage` befindet, ist während des **Hibernate-Modus** entscheidend. **Daten aus dem Speicher werden in dieser Datei gespeichert, wenn OS X in den Ruhezustand wechselt**. Nach dem Aufwachen des Computers ruft das System die Speicher Daten aus dieser Datei ab, sodass der Benutzer dort weitermachen kann, wo er aufgehört hat.

Es ist erwähnenswert, dass diese Datei auf modernen MacOS-Systemen aus Sicherheitsgründen typischerweise verschlüsselt ist, was die Wiederherstellung erschwert.

* Um zu überprüfen, ob die Verschlüsselung für das sleepimage aktiviert ist, kann der Befehl `sysctl vm.swapusage` ausgeführt werden. Dies zeigt an, ob die Datei verschlüsselt ist.

### Memory Pressure Logs

Eine weitere wichtige speicherbezogene Datei in MacOS-Systemen ist das **Speicher-Druckprotokoll**. Diese Protokolle befinden sich in `/var/log` und enthalten detaillierte Informationen über die Speichernutzung und Druckereignisse des Systems. Sie können besonders nützlich sein, um speicherbezogene Probleme zu diagnostizieren oder zu verstehen, wie das System im Laufe der Zeit mit dem Speicher umgeht.

## Dumping memory with osxpmem

Um den Speicher auf einem MacOS-Gerät zu dumpen, können Sie [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) verwenden.

**Hinweis**: Die folgenden Anweisungen funktionieren nur für Macs mit Intel-Architektur. Dieses Tool ist jetzt archiviert und die letzte Version wurde 2017 veröffentlicht. Die mit den folgenden Anweisungen heruntergeladene Binärdatei richtet sich an Intel-Chips, da Apple Silicon 2017 noch nicht verfügbar war. Es kann möglich sein, die Binärdatei für die arm64-Architektur zu kompilieren, aber das müssen Sie selbst ausprobieren.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Wenn Sie diesen Fehler finden: `osxpmem.app/MacPmem.kext konnte nicht geladen werden - (libkern/kext) Authentifizierungsfehler (Dateibesitz/ Berechtigungen); überprüfen Sie die System-/Kernelprotokolle auf Fehler oder versuchen Sie kextutil(8)` können Sie ihn beheben, indem Sie:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Andere Fehler** könnten behoben werden, indem **das Laden des kext** in "Sicherheit & Datenschutz --> Allgemein" **erlaubt** wird, einfach **erlauben**.

Sie können auch diesen **Oneliner** verwenden, um die Anwendung herunterzuladen, den kext zu laden und den Speicher zu dumpen:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}


{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

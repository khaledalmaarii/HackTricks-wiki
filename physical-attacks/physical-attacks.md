# Physische Angriffe

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe zu bekämpfen, die aus informationsstehlender Malware resultieren.

Sie können ihre Website besuchen und ihren Dienst **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

---

## BIOS-Passwortwiederherstellung und Systemsicherheit

Das Zurücksetzen des BIOS kann auf verschiedene Arten erreicht werden. Die meisten Hauptplatinen enthalten eine **Batterie**, die, wenn sie für etwa **30 Minuten** entfernt wird, das BIOS zurücksetzt, einschließlich des Passworts. Alternativ kann ein **Jumper auf der Hauptplatine** angepasst werden, um diese Einstellungen zurückzusetzen, indem bestimmte Pins verbunden werden.

Für Situationen, in denen Hardwareanpassungen nicht möglich oder praktikabel sind, bieten **Softwaretools** eine Lösung. Das Ausführen eines Systems von einer **Live-CD/USB** mit Distributionen wie **Kali Linux** bietet Zugriff auf Tools wie **_killCmos_** und **_CmosPWD_**, die bei der BIOS-Passwortwiederherstellung helfen können.

In Fällen, in denen das BIOS-Passwort unbekannt ist, führt das dreimalige falsche Eingeben in der Regel zu einem Fehlercode. Dieser Code kann auf Websites wie [https://bios-pw.org](https://bios-pw.org) verwendet werden, um möglicherweise ein verwendbares Passwort abzurufen.

### UEFI-Sicherheit

Für moderne Systeme, die anstelle des traditionellen BIOS **UEFI** verwenden, kann das Tool **chipsec** verwendet werden, um UEFI-Einstellungen zu analysieren und zu ändern, einschließlich der Deaktivierung von **Secure Boot**. Dies kann mit dem folgenden Befehl erreicht werden:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM-Analyse und Cold-Boot-Angriffe

RAM behält Daten kurzzeitig nach dem Abschalten der Stromversorgung bei, normalerweise für **1 bis 2 Minuten**. Diese Persistenz kann auf **10 Minuten** verlängert werden, indem kalte Substanzen wie flüssiger Stickstoff aufgetragen werden. Während dieses erweiterten Zeitraums kann ein **Speicherabbild** mithilfe von Tools wie **dd.exe** und **Volatility** für die Analyse erstellt werden.

### Direct Memory Access (DMA)-Angriffe

**INCEPTION** ist ein Tool, das für die **physische Speicher-Manipulation** durch DMA entwickelt wurde und mit Schnittstellen wie **FireWire** und **Thunderbolt** kompatibel ist. Es ermöglicht das Umgehen von Anmeldeverfahren, indem der Speicher gepatcht wird, um jedes Passwort zu akzeptieren. Es ist jedoch gegen **Windows 10**-Systeme unwirksam.

### Live-CD/USB für Systemzugriff

Das Ändern von Systembinärdateien wie **_sethc.exe_** oder **_Utilman.exe_** durch eine Kopie von **_cmd.exe_** kann eine Eingabeaufforderung mit Systemrechten bereitstellen. Tools wie **chntpw** können verwendet werden, um die **SAM**-Datei einer Windows-Installation zu bearbeiten und Passwortänderungen zu ermöglichen.

**Kon-Boot** ist ein Tool, das das Anmelden bei Windows-Systemen ohne Kenntnis des Passworts erleichtert, indem vorübergehend der Windows-Kernel oder UEFI geändert wird. Weitere Informationen finden Sie unter [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Umgang mit Windows-Sicherheitsfunktionen

#### Boot- und Wiederherstellungsverknüpfungen

- **Supr**: Zugriff auf BIOS-Einstellungen.
- **F8**: Starten im Wiederherstellungsmodus.
- Das Drücken von **Shift** nach dem Windows-Banner kann das automatische Anmelden umgehen.

#### BAD USB-Geräte

Geräte wie **Rubber Ducky** und **Teensyduino** dienen als Plattformen zur Erstellung von **schlechten USB**-Geräten, die in der Lage sind, vordefinierte Nutzlasten auszuführen, wenn sie mit einem Zielcomputer verbunden sind.

#### Volume Shadow Copy

Administratorrechte ermöglichen das Erstellen von Kopien sensibler Dateien, einschließlich der **SAM**-Datei, über PowerShell.

### Umgehen der BitLocker-Verschlüsselung

Die BitLocker-Verschlüsselung kann möglicherweise umgangen werden, wenn das **Wiederherstellungspasswort** in einer Speicherabbilddatei (**MEMORY.DMP**) gefunden wird. Tools wie **Elcomsoft Forensic Disk Decryptor** oder **Passware Kit Forensic** können zu diesem Zweck verwendet werden.

### Social Engineering für die Hinzufügung eines Wiederherstellungsschlüssels

Ein neuer BitLocker-Wiederherstellungsschlüssel kann durch Social Engineering-Taktiken hinzugefügt werden, indem ein Benutzer überzeugt wird, einen Befehl auszuführen, der einen neuen Wiederherstellungsschlüssel aus Nullen hinzufügt und somit den Entschlüsselungsprozess vereinfacht.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe zu bekämpfen, die aus informationsstehlender Malware resultieren.

Sie können ihre Website besuchen und ihren Dienst **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

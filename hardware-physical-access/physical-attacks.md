# Physische Angriffe

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## BIOS-Passwortwiederherstellung und Systemsicherheit

Das Zurücksetzen des BIOS kann auf verschiedene Arten erfolgen. Die meisten Motherboards enthalten eine **Batterie**, die beim Entfernen für etwa **30 Minuten** das BIOS zurücksetzt, einschließlich des Passworts. Alternativ kann ein **Jumper auf dem Motherboard** eingestellt werden, um diese Einstellungen durch Verbindung bestimmter Pins zurückzusetzen.

Für Situationen, in denen Hardware-Anpassungen nicht möglich oder praktikabel sind, bieten **Software-Tools** eine Lösung. Das Ausführen eines Systems von einer **Live-CD/USB** mit Distributionen wie **Kali Linux** ermöglicht den Zugriff auf Tools wie **_killCmos_** und **_CmosPWD_**, die bei der Wiederherstellung von BIOS-Passwörtern helfen können.

Wenn das BIOS-Passwort unbekannt ist, führt das dreimalige Eingeben eines falschen Passworts in der Regel zu einem Fehlercode. Dieser Code kann auf Websites wie [https://bios-pw.org](https://bios-pw.org) verwendet werden, um möglicherweise ein verwendbares Passwort abzurufen.

### UEFI-Sicherheit

Für moderne Systeme, die anstelle des traditionellen BIOS **UEFI** verwenden, kann das Tool **chipsec** verwendet werden, um UEFI-Einstellungen zu analysieren und zu ändern, einschließlich der Deaktivierung von **Secure Boot**. Dies kann mit dem folgenden Befehl erreicht werden:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM-Analyse und Cold-Boot-Angriffe

Der RAM behält Daten kurzzeitig nach dem Ausschalten der Stromversorgung bei, normalerweise für **1 bis 2 Minuten**. Diese Persistenz kann durch Auftragen von kalten Substanzen wie flüssigem Stickstoff auf **10 Minuten** verlängert werden. Während dieses erweiterten Zeitraums kann ein **Memory Dump** mit Tools wie **dd.exe** und **volatility** zur Analyse erstellt werden.

### Direct Memory Access (DMA)-Angriffe

**INCEPTION** ist ein Tool, das für die **physische Manipulation des Speichers** durch DMA entwickelt wurde und mit Schnittstellen wie **FireWire** und **Thunderbolt** kompatibel ist. Es ermöglicht das Umgehen von Anmeldeverfahren durch Patchen des Speichers, um jedes Passwort zu akzeptieren. Es ist jedoch gegen **Windows 10**-Systeme unwirksam.

### Live-CD/USB für Systemzugriff

Das Ändern von Systembinärdateien wie **_sethc.exe_** oder **_Utilman.exe_** durch eine Kopie von **_cmd.exe_** kann eine Eingabeaufforderung mit Systemrechten bereitstellen. Tools wie **chntpw** können verwendet werden, um die **SAM**-Datei einer Windows-Installation zu bearbeiten und Passwortänderungen zu ermöglichen.

**Kon-Boot** ist ein Tool, das das Anmelden bei Windows-Systemen ohne Kenntnis des Passworts erleichtert, indem der Windows-Kernel oder UEFI vorübergehend modifiziert wird. Weitere Informationen finden Sie unter [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Umgang mit Windows-Sicherheitsfunktionen

#### Boot- und Wiederherstellungsverknüpfungen

- **Supr**: Zugriff auf BIOS-Einstellungen.
- **F8**: Betreten des Wiederherstellungsmodus.
- Durch Drücken von **Shift** nach dem Windows-Banner kann die automatische Anmeldung umgangen werden.

#### BAD USB-Geräte

Geräte wie **Rubber Ducky** und **Teensyduino** dienen als Plattformen zur Erstellung von **bad USB**-Geräten, die in der Lage sind, vordefinierte Payloads auszuführen, wenn sie mit einem Zielcomputer verbunden werden.

#### Volume Shadow Copy

Administratorrechte ermöglichen das Erstellen von Kopien sensibler Dateien, einschließlich der **SAM**-Datei, über PowerShell.

### Umgehen der BitLocker-Verschlüsselung

Die BitLocker-Verschlüsselung kann möglicherweise umgangen werden, wenn das **Wiederherstellungspasswort** in einer Speicherabbilddatei (**MEMORY.DMP**) gefunden wird. Tools wie **Elcomsoft Forensic Disk Decryptor** oder **Passware Kit Forensic** können zu diesem Zweck verwendet werden.

### Social Engineering zur Hinzufügung eines Wiederherstellungsschlüssels

Ein neuer BitLocker-Wiederherstellungsschlüssel kann durch Social Engineering-Taktiken hinzugefügt werden, indem ein Benutzer dazu überredet wird, einen Befehl auszuführen, der einen neuen Wiederherstellungsschlüssel aus Nullen hinzufügt und damit den Entschlüsselungsprozess vereinfacht.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

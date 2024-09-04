# Physische Angriffe

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

## BIOS-Passwort-Wiederherstellung und Systemsicherheit

**Zurücksetzen des BIOS** kann auf verschiedene Weise erreicht werden. Die meisten Motherboards enthalten eine **Batterie**, die, wenn sie etwa **30 Minuten** entfernt wird, die BIOS-Einstellungen, einschließlich des Passworts, zurücksetzt. Alternativ kann ein **Jumper auf dem Motherboard** angepasst werden, um diese Einstellungen zurückzusetzen, indem bestimmte Pins verbunden werden.

Für Situationen, in denen Hardwareanpassungen nicht möglich oder praktisch sind, bieten **Software-Tools** eine Lösung. Das Ausführen eines Systems von einer **Live-CD/USB** mit Distributionen wie **Kali Linux** ermöglicht den Zugriff auf Tools wie **_killCmos_** und **_CmosPWD_**, die bei der Wiederherstellung des BIOS-Passworts helfen können.

In Fällen, in denen das BIOS-Passwort unbekannt ist, führt das dreimalige falsche Eingeben normalerweise zu einem Fehlercode. Dieser Code kann auf Websites wie [https://bios-pw.org](https://bios-pw.org) verwendet werden, um möglicherweise ein verwendbares Passwort abzurufen.

### UEFI-Sicherheit

Für moderne Systeme, die **UEFI** anstelle des traditionellen BIOS verwenden, kann das Tool **chipsec** verwendet werden, um UEFI-Einstellungen zu analysieren und zu ändern, einschließlich der Deaktivierung von **Secure Boot**. Dies kann mit dem folgenden Befehl erreicht werden:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM-Analyse und Cold Boot-Angriffe

RAM speichert Daten kurzzeitig nach einem Stromausfall, normalerweise für **1 bis 2 Minuten**. Diese Persistenz kann auf **10 Minuten** verlängert werden, indem kalte Substanzen wie flüssiger Stickstoff angewendet werden. Während dieses verlängerten Zeitraums kann ein **Speicherabbild** mit Tools wie **dd.exe** und **volatility** zur Analyse erstellt werden.

### Direct Memory Access (DMA) Angriffe

**INCEPTION** ist ein Tool, das für die **physische Speicherbearbeitung** über DMA entwickelt wurde und mit Schnittstellen wie **FireWire** und **Thunderbolt** kompatibel ist. Es ermöglicht das Umgehen von Anmeldeverfahren, indem der Speicher so patcht wird, dass jedes Passwort akzeptiert wird. Es ist jedoch gegen **Windows 10**-Systeme unwirksam.

### Live-CD/USB für Systemzugriff

Das Ändern von System-Binärdateien wie **_sethc.exe_** oder **_Utilman.exe_** mit einer Kopie von **_cmd.exe_** kann eine Eingabeaufforderung mit Systemberechtigungen bereitstellen. Tools wie **chntpw** können verwendet werden, um die **SAM**-Datei einer Windows-Installation zu bearbeiten, was Passwortänderungen ermöglicht.

**Kon-Boot** ist ein Tool, das das Anmelden bei Windows-Systemen ohne Kenntnis des Passworts erleichtert, indem es den Windows-Kernel oder UEFI vorübergehend ändert. Weitere Informationen finden Sie unter [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Umgang mit Windows-Sicherheitsfunktionen

#### Boot- und Wiederherstellungstastenkombinationen

- **Supr**: Zugriff auf BIOS-Einstellungen.
- **F8**: Eingabe des Wiederherstellungsmodus.
- Drücken von **Shift** nach dem Windows-Banner kann die automatische Anmeldung umgehen.

#### BAD USB-Geräte

Geräte wie **Rubber Ducky** und **Teensyduino** dienen als Plattformen zur Erstellung von **bad USB**-Geräten, die in der Lage sind, vordefinierte Payloads auszuführen, wenn sie mit einem Zielcomputer verbunden werden.

#### Volume Shadow Copy

Administratorrechte ermöglichen die Erstellung von Kopien sensibler Dateien, einschließlich der **SAM**-Datei, über PowerShell.

### Umgehung der BitLocker-Verschlüsselung

Die BitLocker-Verschlüsselung kann möglicherweise umgangen werden, wenn das **Wiederherstellungspasswort** in einer Speicherabbilddatei (**MEMORY.DMP**) gefunden wird. Tools wie **Elcomsoft Forensic Disk Decryptor** oder **Passware Kit Forensic** können hierfür verwendet werden.

### Social Engineering zur Hinzufügung des Wiederherstellungsschlüssels

Ein neuer BitLocker-Wiederherstellungsschlüssel kann durch Social-Engineering-Taktiken hinzugefügt werden, indem ein Benutzer überzeugt wird, einen Befehl auszuführen, der einen neuen Wiederherstellungsschlüssel aus Nullen hinzufügt, wodurch der Entschlüsselungsprozess vereinfacht wird.

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

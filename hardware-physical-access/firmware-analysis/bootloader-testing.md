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
{% endhint %}

Die folgenden Schritte werden empfohlen, um die Startkonfigurationen und Bootloader wie U-boot zu ändern:

1. **Zugriff auf die Interpreter-Shell des Bootloaders**:
- Drücken Sie während des Bootvorgangs "0", Leertaste oder andere identifizierte "magische Codes", um auf die Interpreter-Shell des Bootloaders zuzugreifen.

2. **Boot-Argumente ändern**:
- Führen Sie die folgenden Befehle aus, um '`init=/bin/sh`' zu den Boot-Argumenten hinzuzufügen, was die Ausführung eines Shell-Befehls ermöglicht:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **TFTP-Server einrichten**:
- Konfigurieren Sie einen TFTP-Server, um Bilder über ein lokales Netzwerk zu laden:
%%%
#setenv ipaddr 192.168.2.2 #lokale IP des Geräts
#setenv serverip 192.168.2.1 #TFTP-Server-IP
#saveenv
#reset
#ping 192.168.2.1 #Netzwerkzugang überprüfen
#tftp ${loadaddr} uImage-3.6.35 #loadaddr nimmt die Adresse, um die Datei zu laden, und den Dateinamen des Bildes auf dem TFTP-Server
%%%

4. **`ubootwrite.py` verwenden**:
- Verwenden Sie `ubootwrite.py`, um das U-boot-Bild zu schreiben und eine modifizierte Firmware zu pushen, um Root-Zugriff zu erhalten.

5. **Debug-Funktionen überprüfen**:
- Überprüfen Sie, ob Debug-Funktionen wie ausführliches Protokollieren, Laden beliebiger Kernel oder Booten von nicht vertrauenswürdigen Quellen aktiviert sind.

6. **Vorsicht bei Hardware-Interferenzen**:
- Seien Sie vorsichtig, wenn Sie einen Pin mit Masse verbinden und mit SPI- oder NAND-Flash-Chips während des Bootvorgangs des Geräts interagieren, insbesondere bevor der Kernel dekomprimiert. Konsultieren Sie das Datenblatt des NAND-Flash-Chips, bevor Sie Pins kurzschließen.

7. **Rogue DHCP-Server konfigurieren**:
- Richten Sie einen Rogue-DHCP-Server mit bösartigen Parametern ein, die ein Gerät während eines PXE-Boots aufnehmen soll. Verwenden Sie Tools wie Metasploit's (MSF) DHCP-Hilfsserver. Ändern Sie den 'FILENAME'-Parameter mit Befehlsinjektionsbefehlen wie `'a";/bin/sh;#'`, um die Eingabevalidierung für die Startverfahren des Geräts zu testen.

**Hinweis**: Die Schritte, die physische Interaktionen mit den Pins des Geräts beinhalten (*mit Sternchen markiert), sollten mit äußerster Vorsicht angegangen werden, um Schäden am Gerät zu vermeiden.


## References
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

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
</details>
{% endhint %}

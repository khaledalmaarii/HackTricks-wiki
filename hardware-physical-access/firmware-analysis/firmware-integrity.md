<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Integrität der Firmware

Die **benutzerdefinierte Firmware und/oder kompilierte Binärdateien können hochgeladen werden, um Integritäts- oder Signaturüberprüfungsfehler auszunutzen**. Die folgenden Schritte können für die Kompilierung einer Backdoor-Bind-Shell befolgt werden:

1. Die Firmware kann mithilfe des Firmware-Mod-Kits (FMK) extrahiert werden.
2. Die Ziel-Firmware-Architektur und Endianness sollten identifiziert werden.
3. Ein Cross-Compiler kann mithilfe von Buildroot oder anderen geeigneten Methoden für die Umgebung erstellt werden.
4. Die Backdoor kann mithilfe des Cross-Compilers erstellt werden.
5. Die Backdoor kann in das extrahierte Firmware-/usr/bin-Verzeichnis kopiert werden.
6. Das entsprechende QEMU-Binary kann in das extrahierte Firmware-Rootfs kopiert werden.
7. Die Backdoor kann mithilfe von chroot und QEMU emuliert werden.
8. Die Backdoor kann über Netcat erreicht werden.
9. Das QEMU-Binary sollte aus dem extrahierten Firmware-Rootfs entfernt werden.
10. Die modifizierte Firmware kann mithilfe von FMK neu verpackt werden.
11. Die backdoored Firmware kann getestet werden, indem sie mit dem Firmware-Analyse-Toolkit (FAT) emuliert wird und eine Verbindung zur Ziel-Backdoor-IP und -Port unter Verwendung von Netcat hergestellt wird.

Wenn bereits eine Root-Shell durch dynamische Analyse, Bootloader-Manipulation oder Hardware-Sicherheitstests erhalten wurde, können vorab kompilierte bösartige Binärdateien wie Implantate oder Reverse-Shells ausgeführt werden. Automatisierte Payload/Implantat-Tools wie das Metasploit-Framework und 'msfvenom' können mithilfe der folgenden Schritte genutzt werden:

1. Die Ziel-Firmware-Architektur und Endianness sollten identifiziert werden.
2. Msfvenom kann verwendet werden, um das Ziel-Payload, die IP-Adresse des Angreifers, die empfangende Portnummer, den Dateityp, die Architektur, die Plattform und die Ausgabedatei anzugeben.
3. Der Payload kann auf das kompromittierte Gerät übertragen und sichergestellt werden, dass er Ausführungsberechtigungen hat.
4. Metasploit kann vorbereitet werden, um eingehende Anfragen zu verarbeiten, indem msfconsole gestartet und die Einstellungen entsprechend dem Payload konfiguriert werden.
5. Die Meterpreter-Reverse-Shell kann auf dem kompromittierten Gerät ausgeführt werden.
6. Meterpreter-Sitzungen können überwacht werden, während sie geöffnet werden.
7. Post-Exploitation-Aktivitäten können durchgeführt werden.

Wenn möglich, können Schwachstellen in Startskripten ausgenutzt werden, um dauerhaften Zugriff auf ein Gerät über Neustarts hinweg zu erlangen. Diese Schwachstellen entstehen, wenn Startskripte auf Code verweisen, [symbolisch verlinken](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data) oder von in nicht vertrauenswürdigen eingebundenen Speicherorten wie SD-Karten und Flash-Volumes abhängen, die zur Speicherung von Daten außerhalb von Root-Dateisystemen verwendet werden.

## Referenzen
* Weitere Informationen finden Sie unter [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

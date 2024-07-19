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

## Firmware-Integrität

Die **benutzerdefinierte Firmware und/oder kompilierten Binärdateien können hochgeladen werden, um Integritäts- oder Signaturüberprüfungsfehler auszunutzen**. Die folgenden Schritte können für die Kompilierung eines Backdoor-Bind-Shells befolgt werden:

1. Die Firmware kann mit firmware-mod-kit (FMK) extrahiert werden.
2. Die Ziel-Firmware-Architektur und Endianness sollten identifiziert werden.
3. Ein Cross-Compiler kann mit Buildroot oder anderen geeigneten Methoden für die Umgebung erstellt werden.
4. Die Backdoor kann mit dem Cross-Compiler erstellt werden.
5. Die Backdoor kann in das extrahierte Firmware-Verzeichnis /usr/bin kopiert werden.
6. Die geeignete QEMU-Binärdatei kann in das extrahierte Firmware-Rootfs kopiert werden.
7. Die Backdoor kann mit chroot und QEMU emuliert werden.
8. Die Backdoor kann über netcat zugegriffen werden.
9. Die QEMU-Binärdatei sollte aus dem extrahierten Firmware-Rootfs entfernt werden.
10. Die modifizierte Firmware kann mit FMK neu verpackt werden.
11. Die mit einer Backdoor versehene Firmware kann getestet werden, indem sie mit dem Firmware-Analyse-Toolkit (FAT) emuliert und eine Verbindung zur Ziel-Backdoor-IP und dem Port über netcat hergestellt wird.

Wenn bereits über dynamische Analyse, Bootloader-Manipulation oder Hardware-Sicherheitstests eine Root-Shell erlangt wurde, können vorkompilierte bösartige Binärdateien wie Implantate oder Reverse-Shells ausgeführt werden. Automatisierte Payload/Implantat-Tools wie das Metasploit-Framework und 'msfvenom' können mit den folgenden Schritten genutzt werden:

1. Die Ziel-Firmware-Architektur und Endianness sollten identifiziert werden.
2. Msfvenom kann verwendet werden, um die Ziel-Payload, die IP des Angreifers, die hörende Portnummer, den Dateityp, die Architektur, die Plattform und die Ausgabedatei anzugeben.
3. Die Payload kann auf das kompromittierte Gerät übertragen und sichergestellt werden, dass sie Ausführungsberechtigungen hat.
4. Metasploit kann vorbereitet werden, um eingehende Anfragen zu bearbeiten, indem msfconsole gestartet und die Einstellungen gemäß der Payload konfiguriert werden.
5. Die Meterpreter-Reverse-Shell kann auf dem kompromittierten Gerät ausgeführt werden.
6. Meterpreter-Sitzungen können überwacht werden, während sie geöffnet werden.
7. Nach der Ausbeutung können Aktivitäten durchgeführt werden.

Wenn möglich, können Schwachstellen in Startskripten ausgenutzt werden, um persistenten Zugriff auf ein Gerät über Neustarts hinweg zu erhalten. Diese Schwachstellen entstehen, wenn Startskripte auf Code verweisen, [symbolisch verlinken](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data) oder von Code abhängen, der sich an untrusted gemounteten Orten wie SD-Karten und Flash-Volumes befindet, die zur Speicherung von Daten außerhalb von Root-Dateisystemen verwendet werden.

## Referenzen
* Für weitere Informationen siehe [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

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

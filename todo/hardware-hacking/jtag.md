# JTAG

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos sendest.

</details>
{% endhint %}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)ist ein Tool, das mit einem Raspberry PI oder einem Arduino verwendet werden kann, um JTAG-Pins von einem unbekannten Chip zu finden.\
Im **Arduino** verbinde die **Pins von 2 bis 11 mit 10 Pins, die potenziell zu einem JTAG gehören**. Lade das Programm in den Arduino und es wird versuchen, alle Pins zu bruteforcen, um herauszufinden, ob einer der Pins zu JTAG gehört und welcher es ist.\
Im **Raspberry PI** kannst du nur **Pins von 1 bis 6** verwenden (6 Pins, also wirst du langsamer sein, wenn du jeden potenziellen JTAG-Pin testest).

### Arduino

Im Arduino, nachdem du die Kabel verbunden hast (Pin 2 bis 11 zu JTAG-Pins und Arduino GND zu dem Basisboard GND), **lade das JTAGenum-Programm in den Arduino** und sende im Serial Monitor ein **`h`** (Befehl für Hilfe) und du solltest die Hilfe sehen:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

Konfiguriere **"Keine Zeilenenden" und 115200baud**.\
Sende den Befehl s, um den Scan zu starten:

![](<../../.gitbook/assets/image (774).png>)

Wenn du einen JTAG kontaktierst, wirst du eine oder mehrere **Zeilen finden, die mit FOUND! beginnen**, die die Pins von JTAG anzeigen.

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos sendest.

</details>
{% endhint %}

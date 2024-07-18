{% hint style="success" %}
Lernen & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
{% endhint %}


# Grundlegende Payloads

* **Einfache Liste:** Einfach eine Liste mit einem Eintrag in jeder Zeile
* **Laufzeitdatei:** Eine Liste, die zur Laufzeit gelesen wird (nicht im Speicher geladen). Zur Unterstützung großer Listen.
* **Groß-/Kleinschreibung:** Wenden Sie einige Änderungen auf eine Liste von Zeichenfolgen an (Keine Änderung, zu Kleinbuchstaben, zu GROSSBUCHSTABEN, zu Eigennamen - Erster Buchstabe groß und der Rest klein -, zu Eigennamen - Erster Buchstabe groß und der Rest bleibt gleich -.
* **Zahlen:** Generieren Sie Zahlen von X bis Y mit Schritt Z oder zufällig.
* **Brute Forcer:** Zeichensatz, Mindest- und Höchstlänge.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : Payload zum Ausführen von Befehlen und Abrufen der Ausgabe über DNS-Anfragen an burpcollab.

{% embed url="https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e" %}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

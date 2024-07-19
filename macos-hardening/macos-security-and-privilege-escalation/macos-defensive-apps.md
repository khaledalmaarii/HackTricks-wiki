# macOS Defensive Apps

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Firewalls

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Es überwacht jede Verbindung, die von jedem Prozess hergestellt wird. Abhängig vom Modus (stille Erlaubung von Verbindungen, stille Ablehnung von Verbindungen und Warnung) wird es **dir eine Warnung anzeigen**, jedes Mal, wenn eine neue Verbindung hergestellt wird. Es hat auch eine sehr schöne GUI, um all diese Informationen zu sehen.
* [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See Firewall. Dies ist eine grundlegende Firewall, die dich bei verdächtigen Verbindungen warnt (sie hat eine GUI, ist aber nicht so schick wie die von Little Snitch).

## Persistenz-Erkennung

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See-Anwendung, die an mehreren Orten nachsieht, wo **Malware persistieren könnte** (es ist ein Einmal-Tool, kein Überwachungsdienst).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Wie KnockKnock, indem Prozesse überwacht werden, die Persistenz erzeugen.

## Keylogger-Erkennung

* [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See-Anwendung zur Auffindung von **Keyloggern**, die "Event Taps" für die Tastatur installieren.

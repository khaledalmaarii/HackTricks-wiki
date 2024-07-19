# FZ - Infrarot

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

## Einführung <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Für weitere Informationen darüber, wie Infrarot funktioniert, siehe:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## IR-Signalempfänger im Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper verwendet einen digitalen IR-Signalempfänger TSOP, der **das Abfangen von Signalen von IR-Fernbedienungen ermöglicht**. Es gibt einige **Smartphones** wie Xiaomi, die ebenfalls einen IR-Port haben, aber beachte, dass **die meisten von ihnen nur senden** können und **nicht empfangen** können.

Der Infrarot **Empfänger von Flipper ist ziemlich empfindlich**. Du kannst sogar **das Signal empfangen**, während du **irgendwo dazwischen** der Fernbedienung und dem Fernseher bleibst. Es ist nicht notwendig, die Fernbedienung direkt auf den IR-Port von Flipper zu richten. Dies ist nützlich, wenn jemand die Kanäle wechselt, während er in der Nähe des Fernsehers steht, und sowohl du als auch Flipper sich in einiger Entfernung befinden.

Da die **Dekodierung des Infrarotsignals** auf der **Software**-Seite erfolgt, unterstützt Flipper Zero potenziell die **Empfang und Übertragung von beliebigen IR-Fernbedienungscodes**. Im Falle von **unbekannten** Protokollen, die nicht erkannt werden konnten, **zeichnet es das rohe Signal auf und gibt es genau so wieder, wie es empfangen wurde**.

## Aktionen

### Universelle Fernbedienungen

Flipper Zero kann als **universelle Fernbedienung verwendet werden, um jeden Fernseher, Klimaanlage oder Mediencenter zu steuern**. In diesem Modus **bruteforced** Flipper alle **bekannten Codes** aller unterstützten Hersteller **laut dem Wörterbuch von der SD-Karte**. Du musst keine bestimmte Fernbedienung auswählen, um einen Restaurantfernseher auszuschalten.

Es reicht aus, die Einschalttaste im Universelle Fernbedienung-Modus zu drücken, und Flipper wird **nacheinander "Power Off"**-Befehle aller Fernseher senden, die er kennt: Sony, Samsung, Panasonic... und so weiter. Wenn der Fernseher sein Signal empfängt, wird er reagieren und sich ausschalten.

Ein solches Brute-Force benötigt Zeit. Je größer das Wörterbuch, desto länger dauert es, bis es abgeschlossen ist. Es ist unmöglich herauszufinden, welches Signal genau der Fernseher erkannt hat, da es kein Feedback vom Fernseher gibt.

### Neue Fernbedienung lernen

Es ist möglich, ein **Infrarotsignal** mit Flipper Zero **aufzufangen**. Wenn es **das Signal in der Datenbank findet**, wird Flipper automatisch **wissen, welches Gerät das ist** und dir erlauben, damit zu interagieren.\
Wenn nicht, kann Flipper das **Signal speichern** und dir erlauben, es **wiederzugeben**.

## Referenzen

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

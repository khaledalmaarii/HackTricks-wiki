# FZ - Infrarot

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

## Einführung <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Für weitere Informationen darüber, wie Infrarot funktioniert, siehe:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## IR-Signalempfänger in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper verwendet einen digitalen IR-Signalempfänger TSOP, der es ermöglicht, Signale von IR-Fernbedienungen abzufangen. Es gibt einige **Smartphones** wie Xiaomi, die auch einen IR-Anschluss haben, aber beachten Sie, dass die meisten von ihnen nur Signale übertragen können und nicht empfangen können.

Der Flipper-Infrarotempfänger ist ziemlich empfindlich. Sie können sogar das Signal erfassen, während Sie sich **irgendwo zwischen** der Fernbedienung und dem Fernseher befinden. Es ist nicht notwendig, die Fernbedienung direkt auf den IR-Anschluss von Flipper zu richten. Dies ist nützlich, wenn jemand in der Nähe des Fernsehers die Kanäle wechselt und sowohl Sie als auch Flipper sich einige Entfernung entfernt befinden.

Da die **Decodierung des Infrarotsignals** auf der **Softwareseite** erfolgt, unterstützt Flipper Zero potenziell den Empfang und die Übertragung beliebiger IR-Fernbedienungscodes. Bei **unbekannten** Protokollen, die nicht erkannt werden konnten, zeichnet es das Rohsignal auf und spielt es genau so ab, wie es empfangen wurde.

## Aktionen

### Universalfernbedienungen

Flipper Zero kann als **Universalfernbedienung verwendet werden, um jeden Fernseher, Klimaanlage oder Media Center** zu steuern. In diesem Modus **bruteforced** Flipper alle **bekannten Codes** aller unterstützten Hersteller **gemäß dem Wörterbuch von der SD-Karte**. Sie müssen keine bestimmte Fernbedienung auswählen, um den Fernseher in einem Restaurant auszuschalten.

Es reicht aus, die Ein-/Aus-Taste im Modus "Universalfernbedienung" zu drücken, und Flipper sendet sequentiell "Power Off"-Befehle aller bekannten Fernseher: Sony, Samsung, Panasonic... und so weiter. Wenn der Fernseher das Signal empfängt, reagiert er und schaltet sich aus.

Ein solches Brute-Force dauert seine Zeit. Je größer das Wörterbuch ist, desto länger dauert es, bis es abgeschlossen ist. Es ist unmöglich herauszufinden, welches Signal genau der Fernseher erkannt hat, da es kein Feedback vom Fernseher gibt.

### Neue Fernbedienung lernen

Es ist möglich, ein Infrarotsignal mit Flipper Zero zu **erfassen**. Wenn es das Signal in der Datenbank **findet**, weiß Flipper automatisch, um welches Gerät es sich handelt, und ermöglicht Ihnen die Interaktion damit.\
Wenn nicht, kann Flipper das Signal **speichern** und Ihnen ermöglichen, es **wiederzugeben**.

## Referenzen

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

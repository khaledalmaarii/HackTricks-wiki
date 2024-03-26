# FZ - Sub-GHz

<details>

<summary><strong>Erlernen Sie das Hacken von AWS von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Einführung <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero kann **Frequenzen im Bereich von 300-928 MHz empfangen und senden** mit seinem integrierten Modul, das Fernbedienungen lesen, speichern und emulieren kann. Diese Fernbedienungen werden zur Interaktion mit Toren, Schranken, Funktürschlössern, Fernbedienungsschaltern, drahtlosen Türklingeln, intelligenten Lichtern und mehr verwendet. Flipper Zero kann Ihnen helfen herauszufinden, ob Ihre Sicherheit kompromittiert ist.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz-Hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero verfügt über ein integriertes Sub-1-GHz-Modul, das auf einem [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101-Chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) und einer Funkantenne basiert (die maximale Reichweite beträgt 50 Meter). Sowohl der CC1101-Chip als auch die Antenne sind für den Betrieb bei Frequenzen in den Bändern 300-348 MHz, 387-464 MHz und 779-928 MHz ausgelegt.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Aktionen

### Frequenzanalysator

{% hint style="info" %}
Wie man herausfindet, welche Frequenz die Fernbedienung verwendet
{% endhint %}

Beim Analysieren scannt Flipper Zero die Signalstärke (RSSI) bei allen verfügbaren Frequenzen in der Frequenzkonfiguration. Flipper Zero zeigt die Frequenz mit dem höchsten RSSI-Wert an, mit einer Signalstärke von mehr als -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Um die Frequenz der Fernbedienung zu bestimmen, führen Sie folgende Schritte aus:

1. Platzieren Sie die Fernbedienung ganz nah links von Flipper Zero.
2. Gehen Sie zu **Hauptmenü** **→ Sub-GHz**.
3. Wählen Sie **Frequenzanalysator** aus und halten Sie dann die Taste auf der Fernbedienung gedrückt, die Sie analysieren möchten.
4. Überprüfen Sie den Frequenzwert auf dem Bildschirm.

### Lesen

{% hint style="info" %}
Informationen zur verwendeten Frequenz finden (auch eine andere Möglichkeit, die verwendete Frequenz zu finden)
{% endhint %}

Die **Lesen**-Option **hört auf der konfigurierten Frequenz** mit der angegebenen Modulation: standardmäßig 433,92 AM. Wenn beim Lesen **etwas gefunden wird**, werden **Informationen** auf dem Bildschirm angezeigt. Diese Informationen können verwendet werden, um das Signal in Zukunft zu replizieren.

Während Lesen verwendet wird, ist es möglich, die **linke Taste zu drücken** und **sie zu konfigurieren**.\
Zu diesem Zeitpunkt gibt es **4 Modulationen** (AM270, AM650, FM328 und FM476) und **mehrere relevante Frequenzen** sind gespeichert:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Sie können **jene einstellen, die Sie interessieren**, jedoch, wenn Sie **nicht sicher sind, welche Frequenz** von der Fernbedienung verwendet wird, **schalten Sie Hopping auf ON** (standardmäßig aus) und drücken Sie die Taste mehrmals, bis Flipper sie erfasst und Ihnen die benötigten Informationen zur Einstellung der Frequenz gibt.

{% hint style="danger" %}
Das Wechseln zwischen Frequenzen dauert einige Zeit, daher können Signale, die während des Wechsels übertragen werden, verpasst werden. Für eine bessere Signalrezeption stellen Sie eine feste Frequenz fest, die durch den Frequenzanalysator bestimmt wird.
{% endhint %}

### **Rohdaten lesen**

{% hint style="info" %}
Ein Signal in der konfigurierten Frequenz stehlen (und wiederholen)
{% endhint %}

Die **Rohdaten lesen**-Option **zeichnet Signale** auf, die auf der Empfangsfrequenz gesendet werden. Dies kann verwendet werden, um ein Signal zu **stehlen** und es zu **wiederholen**.

Standardmäßig ist **Rohdaten lesen auch bei 433,92 in AM650**, aber wenn Sie mit der Lesen-Option festgestellt haben, dass das Signal, das Sie interessiert, in einer **anderen Frequenz/Modulation liegt, können Sie das auch ändern**, indem Sie links drücken (während Sie sich in der Rohdaten-Leseoption befinden).

### Brute-Force

Wenn Sie das Protokoll kennen, das beispielsweise von der Garagentür verwendet wird, ist es möglich, **alle Codes zu generieren und mit dem Flipper Zero zu senden**. Dies ist ein Beispiel, das allgemeine gängige Arten von Garagen unterstützt: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Manuell hinzufügen

{% hint style="info" %}
Signale aus einer konfigurierten Liste von Protokollen hinzufügen
{% endhint %}

#### Liste der [unterstützten Protokolle](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (funktioniert mit der Mehrheit der statischen Codesysteme) | 433,92 | Statisch  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433,92 | Statisch  |
| Nice Flo 24bit\_433                                             | 433,92 | Statisch  |
| CAME 12bit\_433                                                 | 433,92 | Statisch  |
| CAME 24bit\_433                                                 | 433,92 | Statisch  |
| Linear\_300                                                     | 300,00 | Statisch  |
| CAME TWEE                                                       | 433,92 | Statisch  |
| Gate TX\_433                                                    | 433,92 | Statisch  |
| DoorHan\_315                                                    | 315,00 | Dynamisch |
| DoorHan\_433                                                    | 433,92 | Dynamisch |
| LiftMaster\_315                                                 | 315,00 | Dynamisch |
| LiftMaster\_390                                                 | 390,00 | Dynamisch |
| Security+2.0\_310                                               | 310,00 | Dynamisch |
| Security+2.0\_315                                               | 315,00 | Dynamisch |
| Security+2.0\_390                                               | 390,00 | Dynamisch |
### Unterstützte Sub-GHz-Anbieter

Überprüfen Sie die Liste unter [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Unterstützte Frequenzen nach Region

Überprüfen Sie die Liste unter [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

{% hint style="info" %}
Erhalten Sie dBm der gespeicherten Frequenzen
{% endhint %}

## Referenz

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

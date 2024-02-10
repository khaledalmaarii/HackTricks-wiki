# FZ - Sub-GHz

<details>

<summary>Lernen Sie das Hacken von AWS von Null auf Held mit <a href="https://training.hacktricks.xyz/courses/arte">htARTE (HackTricks AWS Red Team Expert)</a>!</summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

- Wenn Sie Ihr Unternehmen in HackTricks bewerben möchten oder HackTricks als PDF herunterladen möchten, überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
- Holen Sie sich das offizielle PEASS & HackTricks-Merchandise
- Entdecken Sie die PEASS-Familie, unsere Sammlung exklusiver NFTs
- Treten Sie der Discord-Gruppe oder der Telegram-Gruppe bei oder folgen Sie uns auf Twitter
- Teilen Sie Ihre Hacking-Tricks, indem Sie PRs zu den HackTricks- und HackTricks Cloud-GitHub-Repositories einreichen.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologieinfrastruktur, von APIs über Webanwendungen bis hin zu Cloud-Systemen. Probieren Sie es noch heute [kostenlos aus](https://www.intruder.io/?utm_source=referral&utm_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Einführung <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero kann Funkfrequenzen im Bereich von 300-928 MHz empfangen und senden. Mit seinem integrierten Modul kann es Fernbedienungen lesen, speichern und emulieren. Diese Fernbedienungen werden zur Interaktion mit Toren, Schranken, Funktürschlössern, drahtlosen Türklingeln, intelligenten Lichtern und mehr verwendet. Flipper Zero kann Ihnen helfen herauszufinden, ob Ihre Sicherheit gefährdet ist.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz-Hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero verfügt über ein integriertes Sub-1-GHz-Modul, das auf einem [CC1101-Chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) und einer Funkantenne basiert (die maximale Reichweite beträgt 50 Meter). Sowohl der CC1101-Chip als auch die Antenne sind für den Betrieb bei Frequenzen in den Bändern 300-348 MHz, 387-464 MHz und 779-928 MHz ausgelegt.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Aktionen

### Frequenzanalysator

{% hint style="info" %}
Wie man herausfindet, welche Frequenz die Fernbedienung verwendet
{% endhint %}

Beim Analysieren scannt Flipper Zero die Signalstärke (RSSI) bei allen verfügbaren Frequenzen in der Frequenzkonfiguration. Flipper Zero zeigt die Frequenz mit dem höchsten RSSI-Wert an, mit einer Signalstärke von mehr als -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Um die Frequenz der Fernbedienung zu bestimmen, gehen Sie wie folgt vor:

1. Platzieren Sie die Fernbedienung ganz nah links von Flipper Zero.
2. Gehen Sie zu **Hauptmenü → Sub-GHz**.
3. Wählen Sie **Frequenzanalysator** aus und halten Sie dann die Taste auf der Fernbedienung gedrückt, die Sie analysieren möchten.
4. Überprüfen Sie den Frequenzwert auf dem Bildschirm.

### Lesen

{% hint style="info" %}
Informationen über die verwendete Frequenz finden (auch eine andere Möglichkeit, die verwendete Frequenz zu finden)
{% endhint %}

Die Option **Lesen** **hört auf der konfigurierten Frequenz** mit der angegebenen Modulation: standardmäßig 433,92 AM. Wenn beim Lesen **etwas gefunden wird**, werden Informationen auf dem Bildschirm angezeigt. Diese Informationen können verwendet werden, um das Signal in der Zukunft zu replizieren.

Während Lesen verwendet wird, ist es möglich, die **linke Taste zu drücken und sie zu konfigurieren**.\
Zu diesem Zeitpunkt stehen **4 Modulationen** zur Verfügung (AM270, AM650, FM328 und FM476), und **mehrere relevante Frequenzen** sind gespeichert:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Sie können **jede interessante Frequenz** einstellen. Wenn Sie jedoch **nicht sicher sind, welche Frequenz** von der Fernbedienung verwendet wird, die Sie haben, **schalten Sie das Hopping ein** (standardmäßig aus) und drücken Sie die Taste mehrmals, bis Flipper sie erfasst und Ihnen die benötigten Informationen zur Einstellung der Frequenz gibt.

{% hint style="danger" %}
Das Umschalten zwischen Frequenzen dauert einige Zeit, daher können Signale, die während des Umschaltens übertragen werden, verpasst werden. Für einen besseren Signalempfang stellen Sie eine feste Frequenz ein, die durch den Frequenzanalysator bestimmt wird.
{% endhint %}

### **Rohdaten lesen**

{% hint style="info" %}
Ein Signal in der konfigurierten Frequenz stehlen (und wiederholen)
{% endhint %}

Die Option **Rohdaten lesen** **zeichnet Signale** auf, die in der empfangenen Frequenz gesendet werden. Dies kann verwendet werden, um ein Signal zu **stehlen** und es zu **wiederholen**.

Standardmäßig ist **Rohdaten lesen auch auf 433,92 in AM650** eingestellt, aber wenn Sie mit der Option Lesen festgestellt haben, dass das interessierende Signal in einer **anderen Frequenz/Modulation** liegt, können Sie dies auch ändern, indem Sie links drücken (während Sie sich in der Option Rohdaten lesen befinden).

### Brute-Force

Wenn Sie das Protokoll kennen, das beispielsweise von der Garagentür verwendet wird, können Sie **alle Codes generieren und mit dem Flipper Zero senden**. Hier ist ein Beispiel, das allgemeine gängige Arten von Garagen unterstützt: [https://github.com/tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Manuell hinzufügen

{% hint style="info" %}
Signale aus einer konfigurierten Liste von Protokollen hinzufügen
{% endhint %}

#### Liste der [unterstützten Protokolle](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (funktioniert mit den meisten statischen Codesystemen) | 433,92 | Statisch |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433,92 | Statisch |
| Nice Flo 24bit\_433                                             | 433,92 | Statisch |
| CAME 12bit\_433                                                 | 433,92 | Statisch |
| CAME 24bit\_433                                                 | 433,92 | Statisch |
| Linear\_300                                                     | 300,00 | Statisch |
| CAME TWEE                                                       | 433,92 | Statisch |
| Gate TX\_433                                                    | 433,92 | Statisch |
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
Erhalten Sie dBms der gespeicherten Frequenzen
{% endhint %}

## Referenz

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Finden Sie die wichtigsten Schwachstellen, damit Sie sie schneller beheben können. Intruder verfolgt Ihre Angriffsfläche, führt proaktive Bedrohungsscans durch und findet Probleme in Ihrer gesamten Technologie-Stack, von APIs über Webanwendungen bis hin zu Cloud-Systemen. [**Probieren Sie es noch heute kostenlos aus**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

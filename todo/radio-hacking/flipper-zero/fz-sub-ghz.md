# FZ - Sub-GHz

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


## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero kann **Funkfrequenzen im Bereich von 300-928 MHz empfangen und übertragen** mit seinem eingebauten Modul, das Fernbedienungen lesen, speichern und emulieren kann. Diese Steuerungen werden zur Interaktion mit Toren, Barrieren, Funk-Schlössern, Fernbedienungsschaltern, kabellosen Türklingeln, smarten Lichtern und mehr verwendet. Flipper Zero kann dir helfen zu lernen, ob deine Sicherheit gefährdet ist.

<figure><img src="../../../.gitbook/assets/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz Hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero hat ein eingebautes Sub-1 GHz Modul, das auf einem [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 Chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) basiert und eine Funkantenne hat (die maximale Reichweite beträgt 50 Meter). Sowohl der CC1101 Chip als auch die Antenne sind dafür ausgelegt, bei Frequenzen in den Bändern 300-348 MHz, 387-464 MHz und 779-928 MHz zu arbeiten.

<figure><img src="../../../.gitbook/assets/image (923).png" alt=""><figcaption></figcaption></figure>

## Aktionen

### Frequenzanalysator

{% hint style="info" %}
Wie man herausfindet, welche Frequenz die Fernbedienung verwendet
{% endhint %}

Beim Analysieren scannt Flipper Zero die Signalstärke (RSSI) an allen in der Frequenzkonfiguration verfügbaren Frequenzen. Flipper Zero zeigt die Frequenz mit dem höchsten RSSI-Wert an, mit einer Signalstärke höher als -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Um die Frequenz der Fernbedienung zu bestimmen, gehe wie folgt vor:

1. Platziere die Fernbedienung sehr nah links von Flipper Zero.
2. Gehe zu **Hauptmenü** **→ Sub-GHz**.
3. Wähle **Frequenzanalysator**, drücke und halte dann die Taste auf der Fernbedienung, die du analysieren möchtest.
4. Überprüfe den Frequenzwert auf dem Bildschirm.

### Lesen

{% hint style="info" %}
Finde Informationen über die verwendete Frequenz (auch eine andere Möglichkeit, um herauszufinden, welche Frequenz verwendet wird)
{% endhint %}

Die **Lesen**-Option **lauscht auf der konfigurierten Frequenz** bei der angegebenen Modulation: standardmäßig 433,92 AM. Wenn **etwas gefunden wird**, während gelesen wird, **werden Informationen** auf dem Bildschirm angezeigt. Diese Informationen können verwendet werden, um das Signal in der Zukunft zu replizieren.

Während Lesen aktiv ist, ist es möglich, die **linke Taste** zu drücken und **es zu konfigurieren**.\
Im Moment hat es **4 Modulationen** (AM270, AM650, FM328 und FM476) und **mehrere relevante Frequenzen**, die gespeichert sind:

<figure><img src="../../../.gitbook/assets/image (947).png" alt=""><figcaption></figcaption></figure>

Du kannst **jede Frequenz, die dich interessiert**, einstellen, jedoch, wenn du **nicht sicher bist, welche Frequenz** die von deiner Fernbedienung verwendete sein könnte, **stelle Hopping auf EIN** (standardmäßig AUS) und drücke die Taste mehrmals, bis Flipper sie erfasst und dir die Informationen gibt, die du benötigst, um die Frequenz einzustellen.

{% hint style="danger" %}
Der Wechsel zwischen Frequenzen benötigt etwas Zeit, daher können Signale, die während des Wechsels übertragen werden, verpasst werden. Für eine bessere Signalempfang stelle eine feste Frequenz ein, die vom Frequenzanalysator bestimmt wurde.
{% endhint %}

### **Raw Lesen**

{% hint style="info" %}
Stehle (und wiederhole) ein Signal in der konfigurierten Frequenz
{% endhint %}

Die **Raw Lesen**-Option **zeichnet Signale** auf, die in der Lauscherfrequenz gesendet werden. Dies kann verwendet werden, um ein Signal zu **stehlen** und es **zu wiederholen**.

Standardmäßig ist **Raw Lesen auch auf 433,92 in AM650**, aber wenn du mit der Lesen-Option herausgefunden hast, dass das Signal, das dich interessiert, in einer **anderen Frequenz/Modulation ist, kannst du das auch ändern**, indem du links drückst (während du in der Raw Lesen-Option bist).

### Brute-Force

Wenn du das Protokoll kennst, das beispielsweise vom Garagentor verwendet wird, ist es möglich, **alle Codes zu generieren und sie mit dem Flipper Zero zu senden.** Dies ist ein Beispiel, das allgemeine gängige Arten von Garagen unterstützt: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Manuell hinzufügen

{% hint style="info" %}
Füge Signale aus einer konfigurierten Liste von Protokollen hinzu
{% endhint %}

#### Liste der [unterstützten Protokolle](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (funktioniert mit der Mehrheit der statischen Codesysteme) | 433.92 | Statisch  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | Statisch  |
| Nice Flo 24bit\_433                                             | 433.92 | Statisch  |
| CAME 12bit\_433                                                 | 433.92 | Statisch  |
| CAME 24bit\_433                                                 | 433.92 | Statisch  |
| Linear\_300                                                     | 300.00 | Statisch  |
| CAME TWEE                                                       | 433.92 | Statisch  |
| Gate TX\_433                                                    | 433.92 | Statisch  |
| DoorHan\_315                                                    | 315.00 | Dynamisch |
| DoorHan\_433                                                    | 433.92 | Dynamisch |
| LiftMaster\_315                                                 | 315.00 | Dynamisch |
| LiftMaster\_390                                                 | 390.00 | Dynamisch |
| Security+2.0\_310                                               | 310.00 | Dynamisch |
| Security+2.0\_315                                               | 315.00 | Dynamisch |
| Security+2.0\_390                                               | 390.00 | Dynamisch |

### Unterstützte Sub-GHz Anbieter

Überprüfe die Liste unter [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Unterstützte Frequenzen nach Region

Überprüfe die Liste unter [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

{% hint style="info" %}
Erhalte dBms der gespeicherten Frequenzen
{% endhint %}

## Referenz

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

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

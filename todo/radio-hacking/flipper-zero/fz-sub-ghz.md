# FZ - Sub-GHz

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}


## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero peut **recevoir et transmettre des fréquences radio dans la plage de 300-928 MHz** avec son module intégré, qui peut lire, enregistrer et émuler des télécommandes. Ces télécommandes sont utilisées pour interagir avec des portails, des barrières, des serrures radio, des interrupteurs à distance, des sonnettes sans fil, des lumières intelligentes, et plus encore. Flipper Zero peut vous aider à apprendre si votre sécurité est compromise.

<figure><img src="../../../.gitbook/assets/image (714).png" alt=""><figcaption></figcaption></figure>

## Matériel Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero dispose d'un module sub-1 GHz intégré basé sur une [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[puce CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) et une antenne radio (la portée maximale est de 50 mètres). La puce CC1101 et l'antenne sont conçues pour fonctionner à des fréquences dans les bandes de 300-348 MHz, 387-464 MHz et 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Analyseur de Fréquence

{% hint style="info" %}
Comment trouver quelle fréquence utilise la télécommande
{% endhint %}

Lors de l'analyse, Flipper Zero scanne la force des signaux (RSSI) à toutes les fréquences disponibles dans la configuration de fréquence. Flipper Zero affiche la fréquence avec la valeur RSSI la plus élevée, avec une force de signal supérieure à -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Pour déterminer la fréquence de la télécommande, procédez comme suit :

1. Placez la télécommande très près à gauche de Flipper Zero.
2. Allez dans **Menu Principal** **→ Sub-GHz**.
3. Sélectionnez **Analyseur de Fréquence**, puis appuyez et maintenez le bouton de la télécommande que vous souhaitez analyser.
4. Consultez la valeur de fréquence à l'écran.

### Lire

{% hint style="info" %}
Trouvez des informations sur la fréquence utilisée (aussi une autre façon de trouver quelle fréquence est utilisée)
{% endhint %}

L'option **Lire** **écoute sur la fréquence configurée** sur la modulation indiquée : 433.92 AM par défaut. Si **quelque chose est trouvé** lors de la lecture, **des informations sont données** à l'écran. Ces informations peuvent être utilisées pour reproduire le signal à l'avenir.

Pendant que Lire est en cours d'utilisation, il est possible d'appuyer sur le **bouton gauche** et **de le configurer**.\
À ce moment, il a **4 modulations** (AM270, AM650, FM328 et FM476), et **plusieurs fréquences pertinentes** stockées :

<figure><img src="../../../.gitbook/assets/image (947).png" alt=""><figcaption></figcaption></figure>

Vous pouvez définir **n'importe laquelle qui vous intéresse**, cependant, si vous **n'êtes pas sûr de la fréquence** qui pourrait être celle utilisée par la télécommande que vous avez, **activez le Hopping** (désactivé par défaut), et appuyez sur le bouton plusieurs fois jusqu'à ce que Flipper la capture et vous donne les informations dont vous avez besoin pour définir la fréquence.

{% hint style="danger" %}
Le changement entre les fréquences prend du temps, donc les signaux transmis au moment du changement peuvent être manqués. Pour une meilleure réception du signal, définissez une fréquence fixe déterminée par l'Analyseur de Fréquence.
{% endhint %}

### **Lire Brut**

{% hint style="info" %}
Voler (et rejouer) un signal à la fréquence configurée
{% endhint %}

L'option **Lire Brut** **enregistre les signaux** envoyés à la fréquence d'écoute. Cela peut être utilisé pour **voler** un signal et **le répéter**.

Par défaut, **Lire Brut est également à 433.92 en AM650**, mais si avec l'option Lire vous avez trouvé que le signal qui vous intéresse est à une **fréquence/modulation différente, vous pouvez également le modifier** en appuyant à gauche (tout en étant dans l'option Lire Brut).

### Brute-Force

Si vous connaissez le protocole utilisé par exemple par la porte de garage, il est possible de **générer tous les codes et de les envoyer avec le Flipper Zero.** C'est un exemple qui prend en charge les types de garages communs : [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Ajouter Manuellement

{% hint style="info" %}
Ajouter des signaux à partir d'une liste de protocoles configurés
{% endhint %}

#### Liste des [protocoles pris en charge](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (fonctionne avec la majorité des systèmes à code statique) | 433.92 | Statique  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | Statique  |
| Nice Flo 24bit\_433                                             | 433.92 | Statique  |
| CAME 12bit\_433                                                 | 433.92 | Statique  |
| CAME 24bit\_433                                                 | 433.92 | Statique  |
| Linear\_300                                                     | 300.00 | Statique  |
| CAME TWEE                                                       | 433.92 | Statique  |
| Gate TX\_433                                                    | 433.92 | Statique  |
| DoorHan\_315                                                    | 315.00 | Dynamique |
| DoorHan\_433                                                    | 433.92 | Dynamique |
| LiftMaster\_315                                                 | 315.00 | Dynamique |
| LiftMaster\_390                                                 | 390.00 | Dynamique |
| Security+2.0\_310                                               | 310.00 | Dynamique |
| Security+2.0\_315                                               | 315.00 | Dynamique |
| Security+2.0\_390                                               | 390.00 | Dynamique |

### Fournisseurs Sub-GHz pris en charge

Consultez la liste sur [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Fréquences prises en charge par région

Consultez la liste sur [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

{% hint style="info" %}
Obtenez des dBms des fréquences enregistrées
{% endhint %}

## Référence

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

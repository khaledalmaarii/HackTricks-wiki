# FZ - Sub-GHz

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, lance des analyses de menaces proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Introduction <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero peut **recevoir et transmettre des fréquences radio dans la plage de 300 à 928 MHz** avec son module intégré, qui peut lire, enregistrer et émuler des télécommandes. Ces télécommandes sont utilisées pour interagir avec des portails, des barrières, des serrures radio, des interrupteurs de télécommande, des sonnettes sans fil, des lumières intelligentes, et plus encore. Flipper Zero peut vous aider à découvrir si votre sécurité est compromise.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Matériel Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero possède un module sub-1 GHz intégré basé sur une [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿puce CC1101 et une antenne radio (la portée maximale est de 50 mètres). La puce CC1101 et l'antenne sont conçues pour fonctionner à des fréquences dans les bandes de 300-348 MHz, 387-464 MHz et 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Actions

### Analyseur de fréquence

{% hint style="info" %}
Comment trouver quelle fréquence utilise la télécommande
{% endhint %}

Lors de l'analyse, Flipper Zero scanne la force des signaux (RSSI) à toutes les fréquences disponibles dans la configuration de fréquence. Flipper Zero affiche la fréquence avec la valeur RSSI la plus élevée, avec une force de signal supérieure à -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Pour déterminer la fréquence de la télécommande, suivez ces étapes :

1. Placez la télécommande très près à gauche de Flipper Zero.
2. Allez dans **Menu principal** **→ Sub-GHz**.
3. Sélectionnez **Analyseur de fréquence**, puis appuyez et maintenez le bouton de la télécommande que vous souhaitez analyser.
4. Consultez la valeur de fréquence à l'écran.

### Lire

{% hint style="info" %}
Trouver des informations sur la fréquence utilisée (également un autre moyen de trouver quelle fréquence est utilisée)
{% endhint %}

L'option **Lire** **écoute sur la fréquence configurée** sur la modulation indiquée : 433,92 AM par défaut. Si **quelque chose est trouvé** lors de la lecture, **des informations sont affichées** à l'écran. Ces informations peuvent être utilisées pour reproduire le signal à l'avenir.

Pendant l'utilisation de la fonction Lire, il est possible d'appuyer sur le **bouton gauche** et de le **configurer**.\
À ce moment, il y a **4 modulations** (AM270, AM650, FM328 et FM476), et **plusieurs fréquences pertinentes** sont stockées :

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Vous pouvez définir **celle qui vous intéresse**, cependant, si vous **n'êtes pas sûr de la fréquence** qui pourrait être utilisée par la télécommande que vous avez, **activez le saut à ON** (désactivé par défaut), et appuyez sur le bouton plusieurs fois jusqu'à ce que Flipper la capture et vous donne les informations nécessaires pour définir la fréquence.

{% hint style="danger" %}
Le passage d'une fréquence à une autre prend du temps, donc les signaux transmis au moment du changement peuvent être manqués. Pour une meilleure réception du signal, définissez une fréquence fixe déterminée par l'Analyseur de fréquence.
{% endhint %}

### **Lire brut**

{% hint style="info" %}
Vol (et relecture) d'un signal dans la fréquence configurée
{% endhint %}

L'option **Lire brut** **enregistre les signaux** envoyés à la fréquence d'écoute. Cela peut être utilisé pour **voler** un signal et le **répéter**.

Par défaut, **Lire brut est également à 433,92 en AM650**, mais si avec l'option Lire vous avez trouvé que le signal qui vous intéresse est dans une **fréquence/modulation différente, vous pouvez également la modifier** en appuyant sur gauche (pendant que vous êtes dans l'option Lire brut).

### Brute-Force

Si vous connaissez le protocole utilisé par exemple par la porte de garage, il est possible de **générer tous les codes et de les envoyer avec le Flipper Zero**. Voici un exemple qui prend en charge les types de garages courants : [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### Ajouter manuellement

{% hint style="info" %}
Ajouter des signaux à une liste configurée de protocoles
{% endhint %}

#### Liste des [protocoles pris en charge](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (fonctionne avec la majorité des systèmes de codes statiques) | 433,92 | Statique |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433,92 | Statique |
| Nice Flo 24bit\_433                                             | 433,92 | Statique |
| CAME 12bit\_433                                                 | 433,92 | Statique |
| CAME 24bit\_433                                                 | 433,92 | Statique |
| Linear\_300                                                     | 300,00 | Statique |
| CAME TWEE                                                       | 433,92 | Statique |
| Gate TX\_433                                                    | 433,92 | Statique |
| DoorHan\_315                                                    | 315,00 | Dynamique |
| DoorHan\_433                                                    | 433,92 | Dynamique |
| LiftMaster\_315                                                 | 315,00 | Dynamique |
| LiftMaster\_390                                                 | 390,00 | Dynamique |
| Security+2.0\_310                                               | 310,00 | Dynamique |
| Security+2.0\_315                                               | 315,00 | Dynamique |
| Security+2.0\_390                                               | 390,00 | Dynamique |

### Vendeurs Sub-GHz pris en charge

Consultez la liste sur [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Fréquences prises en charge par région

Consultez la liste sur [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

{% hint style="info" %}
Obtenez les dBm des fréquences enregistrées
{% endhint %}

## Référence

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, lance des analyses de menaces proactives, trouve des problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

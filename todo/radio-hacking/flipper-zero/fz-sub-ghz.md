# FZ - Sub-GHz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives, trouve des problèmes dans toute votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Introduction <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero peut **recevoir et transmettre des fréquences radio dans la plage de 300 à 928 MHz** avec son module intégré, qui peut lire, enregistrer et émuler des télécommandes. Ces télécommandes sont utilisées pour interagir avec des portails, des barrières, des serrures radio, des interrupteurs de télécommande, des sonnettes sans fil, des lumières intelligentes, et plus encore. Flipper Zero peut vous aider à savoir si votre sécurité est compromise.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Matériel Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero dispose d'un module sub-1 GHz intégré basé sur une [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[puce CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) et d'une antenne radio (la portée maximale est de 50 mètres). La puce CC1101 et l'antenne sont conçues pour fonctionner à des fréquences dans les bandes 300-348 MHz, 387-464 MHz et 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Actions

### Analyseur de fréquence

{% hint style="info" %}
Comment trouver la fréquence utilisée par la télécommande
{% endhint %}

Lors de l'analyse, Flipper Zero analyse la force du signal (RSSI) sur toutes les fréquences disponibles dans la configuration de fréquence. Flipper Zero affiche la fréquence ayant la valeur RSSI la plus élevée, avec une puissance de signal supérieure à -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Pour déterminer la fréquence de la télécommande, procédez comme suit :

1. Placez la télécommande très près de la gauche de Flipper Zero.
2. Allez dans **Menu principal** **→ Sub-GHz**.
3. Sélectionnez **Analyseur de fréquence**, puis appuyez et maintenez le bouton de la télécommande que vous souhaitez analyser.
4. Vérifiez la valeur de la fréquence à l'écran.

### Lire

{% hint style="info" %}
Trouver des informations sur la fréquence utilisée (également une autre façon de trouver la fréquence utilisée)
{% endhint %}

L'option **Lire** **écoute la fréquence configurée** sur la modulation indiquée : 433,92 AM par défaut. Si **quelque chose est trouvé** lors de la lecture, des **informations sont fournies** à l'écran. Ces informations peuvent être utilisées pour reproduire le signal à l'avenir.

Pendant l'utilisation de la fonction Lire, il est possible d'appuyer sur le **bouton gauche** et de le **configurer**.\
À ce moment-là, il dispose de **4 modulations** (AM270, AM650, FM328 et FM476), et **plusieurs fréquences pertinentes** sont stockées :

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Vous pouvez définir **celle qui vous intéresse**, cependant, si vous n'êtes **pas sûr de la fréquence** qui pourrait être utilisée par la télécommande que vous avez, **activez le saut de fréquence (Hopping)** (désactivé par défaut), et appuyez plusieurs fois sur le bouton jusqu'à ce que Flipper la capture et vous donne les informations dont vous avez besoin pour définir la fréquence.

{% hint style="danger" %}
Le passage d'une fréquence à une autre prend du temps, il est donc possible de manquer les signaux transmis au moment du passage. Pour une meilleure réception du signal, définissez une fréquence fixe déterminée par l'analyseur de fréquence.
{% endhint %}

### **Lire brut**

{% hint style="info" %}
Vol (et relecture) d'un signal dans la fréquence configurée
{% endhint %}

L'option **Lire brut** **enregistre les signaux** envoyés à la fréquence d'écoute. Cela peut être utilisé pour **voler** un signal et le **reproduire**.

Par défaut, **Lire brut est également en 433,92 en AM650**, mais si avec l'option Lire vous avez trouvé que le signal qui vous intéresse est dans une **fréquence/modulation différente, vous pouvez également la modifier** en appuyant sur la gauche (tout en étant dans l'option Lire brut).
### Brute-Force

Si vous connaissez le protocole utilisé, par exemple, par la porte de garage, il est possible de **générer tous les codes et de les envoyer avec le Flipper Zero**. Voici un exemple qui prend en charge les types courants de portes de garage : [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### Ajouter manuellement

{% hint style="info" %}
Ajouter des signaux à partir d'une liste de protocoles configurés
{% endhint %}

#### Liste des [protocoles pris en charge](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (fonctionne avec la plupart des systèmes de codes statiques) | 433.92 | Statique |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | Statique |
| Nice Flo 24bit\_433                                             | 433.92 | Statique |
| CAME 12bit\_433                                                 | 433.92 | Statique |
| CAME 24bit\_433                                                 | 433.92 | Statique |
| Linear\_300                                                     | 300.00 | Statique |
| CAME TWEE                                                       | 433.92 | Statique |
| Gate TX\_433                                                    | 433.92 | Statique |
| DoorHan\_315                                                    | 315.00 | Dynamique |
| DoorHan\_433                                                    | 433.92 | Dynamique |
| LiftMaster\_315                                                 | 315.00 | Dynamique |
| LiftMaster\_390                                                 | 390.00 | Dynamique |
| Security+2.0\_310                                               | 310.00 | Dynamique |
| Security+2.0\_315                                               | 315.00 | Dynamique |
| Security+2.0\_390                                               | 390.00 | Dynamique |

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

Trouvez les vulnérabilités les plus importantes afin de pouvoir les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des analyses de menace proactives et détecte les problèmes dans l'ensemble de votre pile technologique, des API aux applications web et aux systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) dès aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

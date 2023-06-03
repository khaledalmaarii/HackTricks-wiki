# FZ - Sub-GHz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero peut **recevoir et transmettre des fréquences radio dans la plage de 300 à 928 MHz** avec son module intégré, qui peut lire, enregistrer et émuler des télécommandes. Ces télécommandes sont utilisées pour interagir avec des portails, des barrières, des serrures radio, des interrupteurs de télécommande, des sonnettes sans fil, des lumières intelligentes et plus encore. Flipper Zero peut vous aider à savoir si votre sécurité est compromise.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Matériel Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero dispose d'un module sub-1 GHz intégré basé sur une puce [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) et d'une antenne radio (la portée maximale est de 50 mètres). La puce CC1101 et l'antenne sont conçues pour fonctionner à des fréquences dans les bandes 300-348 MHz, 387-464 MHz et 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Actions

### Analyseur de fréquence

{% hint style="info" %}
Comment trouver la fréquence utilisée par la télécommande
{% endhint %}

Lors de l'analyse, Flipper Zero analyse la force du signal (RSSI) à toutes les fréquences disponibles dans la configuration de fréquence. Flipper Zero affiche la fréquence avec la valeur RSSI la plus élevée, avec une force de signal supérieure à -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Pour déterminer la fréquence de la télécommande, procédez comme suit :

1. Placez la télécommande très près de la gauche de Flipper Zero.
2. Allez dans **Menu principal → Sub-GHz**.
3. Sélectionnez **Analyseur de fréquence**, puis appuyez et maintenez le bouton de la télécommande que vous souhaitez analyser.
4. Vérifiez la valeur de fréquence à l'écran.

### Lire

{% hint style="info" %}
Trouver des informations sur la fréquence utilisée (également une autre façon de trouver la fréquence utilisée)
{% endhint %}

L'option **Lire** **écoute la fréquence configurée** sur la modulation indiquée : 433,92 AM par défaut. Si **quelque chose est trouvé** lors de la lecture, **des informations sont données** à l'écran. Ces informations peuvent être utilisées pour reproduire le signal à l'avenir.

Pendant l'utilisation de la fonction Lire, il est possible d'appuyer sur le **bouton gauche** et de le **configurer**.\
À ce moment, il dispose de **4 modulations** (AM270, AM650, FM328 et FM476), et **plusieurs fréquences pertinentes** sont stockées :

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Vous pouvez définir **celle qui vous intéresse**, cependant, si vous **n'êtes pas sûr de la fréquence** qui pourrait être utilisée par la télécommande que vous avez, **activez le saut de fréquence** (désactivé par défaut), et appuyez sur le bouton plusieurs fois jusqu'à ce que Flipper la capture et vous donne les informations dont vous avez besoin pour définir la fréquence.

{% hint style="danger" %}
Le passage d'une fréquence à une autre prend du temps, donc les signaux transmis au moment du passage peuvent être manqués. Pour une meilleure réception du signal, définissez une fréquence fixe déterminée par l'analyseur de fréquence.
{% endhint %}

### **Lire brut**

{% hint style="info" %}
Vol

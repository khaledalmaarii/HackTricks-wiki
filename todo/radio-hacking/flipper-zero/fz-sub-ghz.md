# FZ - Sub-GHz

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Trouvez les vulnérabilités les plus importantes pour les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des scans de menaces proactifs, trouve des problèmes dans toute votre pile technologique, des API aux applications web et systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero peut **recevoir et transmettre des fréquences radio dans la gamme de 300-928 MHz** avec son module intégré, qui peut lire, sauvegarder et émuler des télécommandes. Ces commandes sont utilisées pour interagir avec des portails, barrières, serrures radio, interrupteurs télécommandés, sonnettes sans fil, lumières intelligentes, et plus encore. Flipper Zero peut vous aider à apprendre si votre sécurité est compromise.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Matériel Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero possède un module sub-1 GHz intégré basé sur une [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[puce CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) et une antenne radio (la portée maximale est de 50 mètres). La puce CC1101 et l'antenne sont conçues pour fonctionner à des fréquences dans les bandes 300-348 MHz, 387-464 MHz et 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Actions

### Analyseur de Fréquence

{% hint style="info" %}
Comment trouver quelle fréquence la télécommande utilise
{% endhint %}

Lors de l'analyse, Flipper Zero scanne la force des signaux (RSSI) à toutes les fréquences disponibles dans la configuration de fréquence. Flipper Zero affiche la fréquence avec la valeur RSSI la plus élevée, avec une force de signal supérieure à -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Pour déterminer la fréquence de la télécommande, procédez comme suit :

1. Placez la télécommande très près de la gauche du Flipper Zero.
2. Allez dans **Menu Principal** **→ Sub-GHz**.
3. Sélectionnez **Analyseur de Fréquence**, puis appuyez et maintenez le bouton de la télécommande que vous souhaitez analyser.
4. Vérifiez la valeur de la fréquence sur l'écran.

### Lire

{% hint style="info" %}
Trouver des informations sur la fréquence utilisée (également une autre façon de trouver quelle fréquence est utilisée)
{% endhint %}

L'option **Lire** **écoute sur la fréquence configurée** sur la modulation indiquée : 433.92 AM par défaut. Si **quelque chose est trouvé** lors de la lecture, **des informations sont données** à l'écran. Ces informations pourraient être utilisées pour répliquer le signal à l'avenir.

Pendant l'utilisation de Lire, il est possible d'appuyer sur le **bouton gauche** et de **le configurer**.\
À ce moment, il a **4 modulations** (AM270, AM650, FM328 et FM476), et **plusieurs fréquences pertinentes** enregistrées :

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Vous pouvez définir **celle qui vous intéresse**, cependant, si vous **n'êtes pas sûr de la fréquence** qui pourrait être celle utilisée par la télécommande que vous avez, **mettez Hopping sur ON** (Off par défaut), et appuyez plusieurs fois sur le bouton jusqu'à ce que Flipper la capture et vous donne les informations dont vous avez besoin pour régler la fréquence.

{% hint style="danger" %}
Le changement entre les fréquences prend du temps, donc les signaux transmis au moment du changement peuvent être manqués. Pour une meilleure réception du signal, réglez une fréquence fixe déterminée par l'Analyseur de Fréquence.
{% endhint %}

### **Lire Brut**

{% hint style="info" %}
Vol (et replay) d'un signal sur la fréquence configurée
{% endhint %}

L'option **Lire Brut** **enregistre les signaux** envoyés sur la fréquence d'écoute. Cela peut être utilisé pour **voler** un signal et le **répéter**.

Par défaut **Lire Brut est aussi en 433.92 en AM650**, mais si avec l'option Lire vous avez trouvé que le signal qui vous intéresse est sur une **fréquence/modulation différente, vous pouvez également modifier cela** en appuyant à gauche (tout en étant dans l'option Lire Brut).

### Brute-Force

Si vous connaissez le protocole utilisé par exemple par la porte de garage, il est possible de **générer tous les codes et de les envoyer avec le Flipper Zero.** Voici un exemple qui prend en charge les types généraux de garages courants : [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### Ajouter Manuellement

{% hint style="info" %}
Ajouter des signaux à partir d'une liste configurée de protocoles
{% endhint %}

#### Liste des [protocoles pris en charge](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (fonctionne avec la majorité des systèmes à code statique) | 433.92 | Statique |
| ------------------------------------------------------------------------ | ------ | -------- |
| Nice Flo 12bit\_433                                                      | 433.92 | Statique |
| Nice Flo 24bit\_433                                                      | 433.92 | Statique |
| CAME 12bit\_433                                                          | 433.92 | Statique |
| CAME 24bit\_433                                                          | 433.92 | Statique |
| Linear\_300                                                              | 300.00 | Statique |
| CAME TWEE                                                                | 433.92 | Statique |
| Gate TX\_433                                                             | 433.92 | Statique |
| DoorHan\_315                                                             | 315.00 | Dynamique|
| DoorHan\_433                                                             | 433.92 | Dynamique|
| LiftMaster\_315                                                          | 315.00 | Dynamique|
| LiftMaster\_390                                                          | 390.00 | Dynamique|
| Security+2.0\_310                                                        | 310.00 | Dynamique|
| Security+2.0\_315                                                        | 315.00 | Dynamique|
| Security+2.0\_390                                                        | 390.00 | Dynamique|

### Fournisseurs Sub-GHz pris en charge

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

Trouvez les vulnérabilités les plus importantes pour les corriger plus rapidement. Intruder suit votre surface d'attaque, effectue des scans de menaces proactifs, trouve des problèmes dans toute votre pile technologique, des API aux applications web et systèmes cloud. [**Essayez-le gratuitement**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) aujourd'hui.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# Infrarouge

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Fonctionnement de l'infrarouge <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La lumière infrarouge est invisible pour les humains**. La longueur d'onde de l'infrarouge va de **0,7 à 1000 microns**. Les télécommandes domestiques utilisent un signal infrarouge pour la transmission de données et fonctionnent dans la plage de longueurs d'onde de 0,75 à 1,4 microns. Un microcontrôleur dans la télécommande fait clignoter une LED infrarouge avec une fréquence spécifique, transformant le signal numérique en signal infrarouge.

Pour recevoir les signaux infrarouges, un **photorécepteur** est utilisé. Il **convertit la lumière infrarouge en impulsions de tension**, qui sont déjà des **signaux numériques**. Habituellement, il y a un **filtre de lumière sombre à l'intérieur du récepteur**, qui laisse passer **seulement la longueur d'onde désirée** et élimine le bruit.

### Variété de protocoles infrarouges <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Les protocoles infrarouges diffèrent selon 3 facteurs :

* encodage des bits
* structure des données
* fréquence porteuse — souvent dans la plage de 36 à 38 kHz

#### Méthodes d'encodage des bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Encodage de la distance d'impulsion**

Les bits sont encodés en modulant la durée de l'espace entre les impulsions. La largeur de l'impulsion elle-même est constante.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Encodage de la largeur d'impulsion**

Les bits sont encodés en modulant la largeur de l'impulsion. La largeur de l'espace après la rafale d'impulsions est constante.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Encodage de phase**

Il est également connu sous le nom d'encodage Manchester. La valeur logique est définie par la polarité de la transition entre la rafale d'impulsions et l'espace. "Espace vers rafale d'impulsions" représente la logique "0", "rafale d'impulsions vers espace" représente la logique "1".

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinaison des précédents et autres exotiques**

{% hint style="info" %}
Il existe des protocoles infrarouges qui **tentent de devenir universels** pour plusieurs types d'appareils. Les plus célèbres sont RC5 et NEC. Malheureusement, les plus célèbres **ne signifient pas les plus courants**. Dans mon environnement, j'ai rencontré seulement deux télécommandes NEC et aucune télécommande RC5.

Les fabricants aiment utiliser leurs propres protocoles infrarouges uniques, même au sein de la même gamme d'appareils (par exemple, les décodeurs TV). Par conséquent, les télécommandes de différentes entreprises et parfois de différents modèles de la même entreprise, ne peuvent pas fonctionner avec d'autres appareils du même type.
{% endhint %}

### Exploration d'un signal infrarouge

La manière la plus fiable de voir à quoi ressemble le signal infrarouge de la télécommande est d'utiliser un oscilloscope. Il ne démodule ni n'inverse le signal reçu, il est simplement affiché "tel quel". Cela est utile pour les tests et le débogage. Je montrerai le signal attendu sur l'exemple du protocole infrarouge NEC.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

Généralement, il y a un préambule au début d'un paquet encodé. Cela permet au récepteur de déterminer le niveau de gain et l'arrière-plan. Il existe également des protocoles sans préambule, par exemple, Sharp.

Ensuite, les données sont transmises. La structure, le préambule et la méthode d'encodage des bits sont déterminés par le protocole spécifique.

Le protocole infrarouge **NEC** contient une commande courte et un code de répétition, qui est envoyé lorsque le bouton est enfoncé. Tant la commande que le code de répétition ont le même préambule au début.

La **commande NEC**, en plus du préambule, se compose d'un octet d'adresse et d'un octet de numéro de commande, par lesquels l'appareil comprend ce qui doit être effectué. Les octets d'adresse et de numéro de commande sont dupliqués avec des valeurs inverses, pour vérifier l'intégrité de la transmission. Il y a un bit d'arrêt supplémentaire à la fin de la commande.

Le **code de répétition** a un "1" après le préambule, qui est un bit d'arrêt.

Pour les **logiques "0" et "1"**, NEC utilise l'Encodage de la Distance d'Impulsion : d'abord, une rafale d'impulsions est transmise, après quoi il y a une pause, dont la longueur définit la valeur du bit.

### Climatiseurs

Contrairement aux autres télécommandes, **les climatiseurs ne transmettent pas seulement le code du bouton pressé**. Ils **transmettent également toutes les informations** lorsqu'un bouton est pressé pour s'assurer que la **machine climatisée et la télécommande sont synchronisées**.\
Cela évitera qu'une machine réglée à 20ºC ne soit augmentée à 21ºC avec une télécommande, puis lorsque qu'une autre télécommande, qui a toujours la température à 20ºC, est utilisée pour augmenter davantage la température, elle "l'augmentera" à 21ºC (et non à 22ºC en pensant qu'elle est à 21ºC).

### Attaques

Vous pouvez attaquer l'infrarouge avec Flipper Zero :

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Références

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/) 

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

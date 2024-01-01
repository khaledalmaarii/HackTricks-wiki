# Infrarouge

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Fonctionnement de l'Infrarouge <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La lumière infrarouge est invisible pour les humains**. La longueur d'onde IR est de **0,7 à 1000 microns**. Les télécommandes domestiques utilisent un signal IR pour la transmission de données et fonctionnent dans la plage de longueur d'onde de 0,75..1,4 microns. Un microcontrôleur dans la télécommande fait clignoter une LED infrarouge avec une fréquence spécifique, transformant le signal numérique en signal IR.

Pour recevoir des signaux IR, un **photoreceiver** est utilisé. Il **convertit la lumière IR en impulsions de tension**, qui sont déjà des **signaux numériques**. Habituellement, il y a un **filtre de lumière sombre à l'intérieur du récepteur**, qui laisse **passer uniquement la longueur d'onde souhaitée** et élimine le bruit.

### Variété de protocoles IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Les protocoles IR diffèrent selon 3 facteurs :

* codage des bits
* structure des données
* fréquence porteuse — souvent dans la plage 36..38 kHz

#### Méthodes de codage des bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codage par Distance d'Impulsion**

Les bits sont codés en modulant la durée de l'espace entre les impulsions. La largeur de l'impulsion elle-même est constante.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. Codage par Largeur d'Impulsion**

Les bits sont codés par modulation de la largeur de l'impulsion. La largeur de l'espace après la salve d'impulsion est constante.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Codage de Phase**

Il est également connu sous le nom de codage Manchester. La valeur logique est définie par la polarité de la transition entre la salve d'impulsion et l'espace. "Espace à salve d'impulsion" indique logique "0", "salve d'impulsion à espace" indique logique "1".

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Combinaison des précédentes et autres exotiques**

{% hint style="info" %}
Il existe des protocoles IR qui **tentent de devenir universels** pour plusieurs types d'appareils. Les plus célèbres sont RC5 et NEC. Malheureusement, le plus célèbre **ne signifie pas le plus commun**. Dans mon environnement, j'ai rencontré juste deux télécommandes NEC et aucune RC5.

Les fabricants aiment utiliser leurs propres protocoles IR uniques, même au sein de la même gamme d'appareils (par exemple, les boîtiers TV). Par conséquent, les télécommandes de différentes entreprises et parfois de différents modèles de la même entreprise, ne peuvent pas fonctionner avec d'autres appareils du même type.
{% endhint %}

### Exploration d'un signal IR

La manière la plus fiable de voir à quoi ressemble le signal IR d'une télécommande est d'utiliser un oscilloscope. Il ne démodule ni n'inverse le signal reçu, il est simplement affiché "tel quel". Cela est utile pour les tests et le débogage. Je vais montrer le signal attendu sur l'exemple du protocole IR NEC.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

Habituellement, il y a un préambule au début d'un paquet codé. Cela permet au récepteur de déterminer le niveau de gain et de fond. Il existe également des protocoles sans préambule, par exemple Sharp.

Ensuite, les données sont transmises. La structure, le préambule et la méthode de codage des bits sont déterminés par le protocole spécifique.

Le **protocole IR NEC** contient une commande courte et un code de répétition, qui est envoyé tant que le bouton est pressé. La commande et le code de répétition ont le même préambule au début.

La **commande NEC**, en plus du préambule, se compose d'un octet d'adresse et d'un octet de numéro de commande, par lesquels l'appareil comprend ce qui doit être effectué. Les octets d'adresse et de numéro de commande sont dupliqués avec des valeurs inversées, pour vérifier l'intégrité de la transmission. Il y a un bit d'arrêt supplémentaire à la fin de la commande.

Le **code de répétition** a un "1" après le préambule, qui est un bit d'arrêt.

Pour **logique "0" et "1"** NEC utilise le Codage par Distance d'Impulsion : d'abord, une salve d'impulsion est transmise après quoi il y a une pause, sa longueur définit la valeur du bit.

### Climatiseurs

Contrairement aux autres télécommandes, **les climatiseurs ne transmettent pas seulement le code du bouton pressé**. Ils **transmettent également toutes les informations** lorsqu'un bouton est pressé pour s'assurer que la **machine climatisée et la télécommande sont synchronisées**.\
Cela évitera qu'une machine réglée à 20ºC soit augmentée à 21ºC avec une télécommande, puis lorsqu'une autre télécommande, qui a toujours la température à 20ºC, est utilisée pour augmenter davantage la température, elle l'"augmentera" à 21ºC (et non à 22ºC en pensant qu'elle est à 21ºC).

### Attaques

Vous pouvez attaquer l'Infrarouge avec Flipper Zero :

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Références

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

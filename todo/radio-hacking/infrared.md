# Infrarouge

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Comment fonctionne l'infrarouge <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La lumière infrarouge est invisible pour les humains**. La longueur d'onde de l'infrarouge est de **0,7 à 1000 microns**. Les télécommandes domestiques utilisent un signal infrarouge pour la transmission de données et fonctionnent dans la plage de longueurs d'onde de 0,75 à 1,4 microns. Un microcontrôleur dans la télécommande fait clignoter une LED infrarouge avec une fréquence spécifique, transformant le signal numérique en un signal infrarouge.

Pour recevoir les signaux infrarouges, un **photorécepteur** est utilisé. Il **convertit la lumière infrarouge en impulsions de tension**, qui sont déjà des **signaux numériques**. Habituellement, il y a un **filtre de lumière sombre à l'intérieur du récepteur**, qui laisse passer **seulement la longueur d'onde désirée** et élimine le bruit.

### Variété de protocoles infrarouges <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Les protocoles infrarouges diffèrent selon 3 facteurs :

* encodage de bits
* structure des données
* fréquence porteuse - souvent dans la plage de 36 à 38 kHz

#### Modes d'encodage de bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Encodage de distance d'impulsion**

Les bits sont encodés en modulant la durée de l'espace entre les impulsions. La largeur de l'impulsion elle-même est constante.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. Encodage de la largeur d'impulsion**

Les bits sont encodés par modulation de la largeur d'impulsion. La largeur de l'espace après la rafale d'impulsions est constante.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Encodage de phase**

Il est également connu sous le nom d'encodage Manchester. La valeur logique est définie par la polarité de la transition entre la rafale d'impulsions et l'espace. "Espace à la rafale d'impulsions" indique la logique "0", "rafale d'impulsions à l'espace" indique la logique "1".

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Combinaison des précédents et autres exotiques**

{% hint style="info" %}
Il existe des protocoles infrarouges qui **tentent de devenir universels** pour plusieurs types de dispositifs. Les plus célèbres sont RC5 et NEC. Malheureusement, les plus célèbres **ne signifient pas les plus courants**. Dans mon environnement, je n'ai rencontré que deux télécommandes NEC et aucune télécommande RC5.

Les fabricants aiment utiliser leurs propres protocoles infrarouges uniques, même au sein de la même gamme de dispositifs (par exemple, les décodeurs TV). Par conséquent, les télécommandes de différentes entreprises et parfois de différents modèles de la même entreprise, ne peuvent pas fonctionner avec d'autres dispositifs du même type.
{% endhint %}

### Exploration d'un signal infrarouge

La manière la plus fiable de voir à quoi ressemble le signal infrarouge de la télécommande est d'utiliser un oscilloscope. Il ne démodule ni n'inverse le signal reçu, il est simplement affiché "tel quel". Cela est utile pour les tests et le débogage. Je vais montrer le signal attendu sur l'exemple du protocole infrarouge NEC.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

Habituellement, il y a un préambule au début d'un paquet encodé. Cela permet au récepteur de déterminer le niveau de gain et de bruit de fond. Il existe également des protocoles sans préambule, par exemple Sharp.

Ensuite, les données sont transmises. La structure, le préambule et la méthode d'encodage des bits sont déterminés par le protocole spécifique.

Le **protocole infrarouge NEC** contient une commande courte et un code de répétition, qui est envoyé pendant que le bouton est enfoncé. La commande et le code de répétition ont le même préambule au début.

La **commande NEC**, en plus du préambule, se compose d'un octet d'adresse et d'un octet de numéro de commande, par lequel le dispositif comprend ce qui doit être effectué. Les octets d'adresse et de numéro de commande sont dupliqués avec des valeurs inverses, pour vérifier l'intégrité de la transmission. Il y a un bit d'arrêt supplémentaire à la fin de la commande.

Le **code de répétition** a un "1" après le préambule, qui est un bit d'arrêt.

Pour la logique "0" et "1", NEC utilise l'encodage de distance d'impulsion : d'abord,

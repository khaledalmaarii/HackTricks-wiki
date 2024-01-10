<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


#

# JTAG

JTAG permet d'effectuer un scan de limite. Le scan de limite analyse certains circuits, y compris les cellules et registres de scan de limite intégrés pour chaque broche.

La norme JTAG définit **des commandes spécifiques pour réaliser des scans de limite**, y compris les suivantes :

* **BYPASS** permet de tester un circuit spécifique sans la surcharge de passer par d'autres circuits.
* **SAMPLE/PRELOAD** prend un échantillon des données entrant et sortant de l'appareil lorsqu'il est en mode de fonctionnement normal.
* **EXTEST** définit et lit les états des broches.

Il peut également prendre en charge d'autres commandes telles que :

* **IDCODE** pour identifier un appareil
* **INTEST** pour le test interne de l'appareil

Vous pourriez rencontrer ces instructions lorsque vous utilisez un outil comme le JTAGulator.

## Le port d'accès au test

Les scans de limite incluent des tests du port à quatre fils **Test Access Port (TAP)**, un port polyvalent qui fournit **l'accès aux fonctions de support de test JTAG** intégrées dans un composant. Le TAP utilise les cinq signaux suivants :

* Entrée d'horloge de test (**TCK**) Le TCK est l'**horloge** qui définit la fréquence à laquelle le contrôleur TAP prendra une action unique (en d'autres termes, passer à l'état suivant dans la machine à états).
* Entrée de sélection de mode de test (**TMS**) TMS contrôle la **machine à états finis**. À chaque battement de l'horloge, le contrôleur TAP JTAG de l'appareil vérifie la tension sur la broche TMS. Si la tension est en dessous d'un certain seuil, le signal est considéré comme bas et interprété comme 0, tandis que si la tension est au-dessus d'un certain seuil, le signal est considéré comme haut et interprété comme 1.
* Entrée de données de test (**TDI**) TDI est la broche qui envoie **les données dans la puce à travers les cellules de scan**. Chaque fournisseur est responsable de la définition du protocole de communication sur cette broche, car JTAG ne le définit pas.
* Sortie de données de test (**TDO**) TDO est la broche qui envoie **les données hors de la puce**.
* Entrée de réinitialisation de test (**TRST**) Le TRST optionnel réinitialise la machine à états finis **à un état connu comme bon**. Alternativement, si le TMS est maintenu à 1 pendant cinq cycles d'horloge consécutifs, il invoque une réinitialisation, de la même manière que la broche TRST le ferait, c'est pourquoi TRST est optionnel.

Parfois, vous pourrez trouver ces broches marquées sur le PCB. Dans d'autres cas, vous pourriez avoir besoin de **les trouver**.

## Identifier les broches JTAG

La manière la plus rapide mais la plus coûteuse de détecter les ports JTAG est d'utiliser le **JTAGulator**, un appareil créé spécifiquement à cet effet (bien qu'il puisse **également détecter les brochages UART**).

Il dispose de **24 canaux** que vous pouvez connecter aux broches des cartes. Ensuite, il effectue une **attaque BF** de toutes les combinaisons possibles en envoyant des commandes de scan de limite **IDCODE** et **BYPASS**. S'il reçoit une réponse, il affiche le canal correspondant à chaque signal JTAG

Une manière moins chère mais beaucoup plus lente d'identifier les brochages JTAG est d'utiliser [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) chargé sur un microcontrôleur compatible Arduino.

En utilisant **JTAGenum**, vous devriez d'abord **définir les broches de l'appareil de sondage** que vous utiliserez pour l'énumération. Vous devriez vous référer au schéma de brochage de l'appareil, puis connecter ces broches aux points de test de votre appareil cible.

Une **troisième manière** d'identifier les broches JTAG est d'**inspecter le PCB** pour l'un des brochages. Dans certains cas, les PCB pourraient commodément fournir l'**interface Tag-Connect**, ce qui est une indication claire que la carte a également un connecteur JTAG. Vous pouvez voir à quoi ressemble cette interface sur [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). De plus, l'inspection des **fiches techniques des chipsets sur le PCB** pourrait révéler des schémas de brochage qui indiquent des interfaces JTAG.

# SDW

SWD est un protocole spécifique à ARM conçu pour le débogage.

L'interface SWD nécessite **deux broches** : un signal bidirectionnel **SWDIO**, qui est l'équivalent des broches **TDI et TDO de JTAG et une horloge**, et **SWCLK**, qui est l'équivalent de **TCK** dans JTAG. De nombreux appareils prennent en charge le **Serial Wire or JTAG Debug Port (SWJ-DP)**, une interface JTAG et SWD combinée qui vous permet de connecter soit une sonde SWD soit une sonde JTAG à la cible.


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

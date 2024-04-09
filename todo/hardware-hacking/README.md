# Piratage du matériel

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## JTAG

JTAG permet d'effectuer un balayage de limite. Le balayage de limite analyse certaines circuits, y compris les cellules de balayage de limite intégrées et les registres pour chaque broche.

La norme JTAG définit **des commandes spécifiques pour effectuer des balayages de limite**, notamment les suivantes :

* **BYPASS** vous permet de tester une puce spécifique sans les frais généraux de passage par d'autres puces.
* **SAMPLE/PRELOAD** prend un échantillon des données entrant et sortant du dispositif lorsqu'il est en mode de fonctionnement normal.
* **EXTEST** définit et lit les états des broches.

Il peut également prendre en charge d'autres commandes telles que :

* **IDCODE** pour identifier un dispositif
* **INTEST** pour le test interne du dispositif

Vous pourriez rencontrer ces instructions lorsque vous utilisez un outil comme le JTAGulator.

### Le port d'accès aux tests

Les balayages de limite comprennent des tests du **port d'accès aux tests (TAP)** à quatre fils, un port polyvalent qui fournit **l'accès aux fonctions de support des tests JTAG** intégrées dans un composant. TAP utilise les cinq signaux suivants :

* Entrée d'horloge de test (**TCK**) Le TCK est l'**horloge** qui définit à quelle fréquence le contrôleur TAP prendra une seule action (en d'autres termes, passera à l'état suivant dans la machine à états).
* Sélection du mode de test (**TMS**) L'entrée TMS contrôle la **machine à états finis**. À chaque battement de l'horloge, le contrôleur TAP JTAG du dispositif vérifie la tension sur la broche TMS. Si la tension est inférieure à un certain seuil, le signal est considéré comme bas et interprété comme 0, tandis que si la tension est supérieure à un certain seuil, le signal est considéré comme haut et interprété comme 1.
* Entrée de données de test (**TDI**) TDI est la broche qui envoie **des données dans la puce via les cellules de balayage**. Chaque fabricant est responsable de définir le protocole de communication sur cette broche, car JTAG ne le définit pas.
* Sortie de données de test (**TDO**) TDO est la broche qui envoie **des données hors de la puce**.
* Réinitialisation de test (**TRST**) entrée La réinitialisation TRST facultative remet la machine à états finis **dans un état connu bon**. Sinon, si le TMS est maintenu à 1 pendant cinq cycles d'horloge consécutifs, il invoque une réinitialisation, de la même manière que la broche TRST, c'est pourquoi TRST est facultatif.

Parfois, vous pourrez trouver ces broches marquées sur le PCB. Dans d'autres cas, vous pourriez avoir besoin de **les trouver**.

### Identification des broches JTAG

La manière la plus rapide mais la plus coûteuse de détecter les ports JTAG est d'utiliser le **JTAGulator**, un dispositif créé spécifiquement à cette fin (bien qu'il puisse **également détecter les configurations de broches UART**).

Il dispose de **24 canaux** auxquels vous pouvez connecter les broches des cartes. Ensuite, il effectue une **attaque BF** de toutes les combinaisons possibles en envoyant les commandes de balayage de limite **IDCODE** et **BYPASS**. S'il reçoit une réponse, il affiche le canal correspondant à chaque signal JTAG.

Une manière moins chère mais beaucoup plus lente d'identifier les configurations de broches JTAG est d'utiliser le [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) chargé sur un microcontrôleur compatible Arduino.

En utilisant **JTAGenum**, vous devriez d'abord **définir les broches du dispositif de sondage** que vous utiliserez pour l'énumération. Vous devrez vous référer au schéma des broches du dispositif, puis connecter ces broches aux points de test sur votre dispositif cible.

Une **troisième manière** d'identifier les broches JTAG est d'**inspecter le PCB** pour l'une des configurations de broches. Dans certains cas, les PCB pourraient fournir de manière pratique l'interface **Tag-Connect**, ce qui est une indication claire que la carte possède également un connecteur JTAG. Vous pouvez voir à quoi ressemble cette interface sur [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). De plus, l'inspection des **fiches techniques des jeux de puces sur le PCB** pourrait révéler des schémas de broches indiquant des interfaces JTAG.

## SDW

SWD est un protocole spécifique à ARM conçu pour le débogage.

L'interface SWD nécessite **deux broches** : un signal bidirectionnel **SWDIO**, qui est l'équivalent des broches **TDI et TDO de JTAG et une horloge**, et **SWCLK**, qui est l'équivalent de **TCK** dans JTAG. De nombreux dispositifs prennent en charge le **port de débogage série ou JTAG (SWJ-DP)**, une interface combinée JTAG et SWD qui vous permet de connecter soit une sonde SWD soit JTAG à la cible.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

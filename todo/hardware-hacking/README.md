<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


#

# JTAG

JTAG permet d'effectuer un balayage de frontière. Le balayage de frontière analyse certains circuits, y compris les cellules et les registres de balayage de frontière intégrés pour chaque broche.

La norme JTAG définit des **commandes spécifiques pour effectuer des balayages de frontière**, notamment les suivantes :

* **BYPASS** vous permet de tester une puce spécifique sans la surcharge de passer par d'autres puces.
* **SAMPLE/PRELOAD** prend un échantillon des données entrant et sortant du dispositif lorsqu'il est en mode de fonctionnement normal.
* **EXTEST** définit et lit les états des broches.

Il peut également prendre en charge d'autres commandes telles que :

* **IDCODE** pour identifier un dispositif
* **INTEST** pour le test interne du dispositif

Vous pourriez rencontrer ces instructions lorsque vous utilisez un outil comme le JTAGulator.

## Le port d'accès de test

Les balayages de frontière comprennent des tests des quatre fils du **port d'accès de test (TAP)**, un port général qui fournit **l'accès aux fonctions de support de test JTAG** intégrées à un composant. TAP utilise les cinq signaux suivants :

* Entrée d'horloge de test (**TCK**) Le TCK est l'**horloge** qui définit à quelle fréquence le contrôleur TAP prendra une seule action (en d'autres termes, sautera à l'état suivant dans la machine à états).
* Sélection de mode de test (**TMS**) L'entrée TMS contrôle la **machine à états finis**. À chaque battement de l'horloge, le contrôleur TAP JTAG du dispositif vérifie la tension sur la broche TMS. Si la tension est inférieure à un certain seuil, le signal est considéré comme faible et interprété comme 0, tandis que si la tension est supérieure à un certain seuil, le signal est considéré comme élevé et interprété comme 1.
* Entrée de données de test (**TDI**) TDI est la broche qui envoie **des données dans la puce par les cellules de balayage**. Chaque fournisseur est responsable de la définition du protocole de communication sur cette broche, car JTAG ne le définit pas.
* Sortie de données de test (**TDO**) TDO est la broche qui envoie **des données hors de la puce**.
* Réinitialisation de test (**TRST**) entrée La réinitialisation TRST facultative réinitialise la machine à états finis **à un état connu et bon**. Alternativement, si le TMS est maintenu à 1 pendant cinq cycles d'horloge consécutifs, il invoque une réinitialisation, de la même manière que la broche TRST, c'est pourquoi TRST est facultatif.

Parfois, vous pourrez trouver ces broches marquées sur le PCB. Dans d'autres occasions, vous devrez les **trouver**.

## Identification des broches JTAG

Le moyen le plus rapide mais le plus coûteux de détecter les ports JTAG consiste à utiliser le **JTAGulator**, un dispositif créé spécifiquement à cet effet (bien qu'il puisse également **détecter les configurations de broches UART**).

Il dispose de **24 canaux** auxquels vous pouvez connecter les broches de la carte. Ensuite, il effectue une **attaque BF** de toutes les combinaisons possibles en envoyant des commandes de balayage de frontière **IDCODE** et **BYPASS**. S'il reçoit une réponse, il affiche le canal correspondant à chaque signal JTAG.

Un moyen moins cher mais beaucoup plus lent d'identifier les configurations de broches JTAG consiste à utiliser le [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) chargé sur un microcontrôleur compatible Arduino.

En utilisant **JTAGenum**, vous devriez d'abord **définir les broches de la sonde** que vous utiliserez pour l'énumération. Vous devrez vous référer au diagramme de brochage du dispositif, puis connecter ces broches aux points de test sur votre dispositif cible.

Un **troisième moyen** d'identifier les broches JTAG consiste à **inspecter le PCB** pour l'une des configurations de broches. Dans certains cas, les PCB peuvent fournir commodément l'interface **Tag-Connect**, ce qui est une indication claire que la carte a un connecteur JTAG. Vous pouvez voir à quoi ressemble cette interface sur [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). De plus, l'inspection des **fiches techniques des chipsets sur le PCB** peut révéler des diagrammes de brochage qui pointent vers des interfaces JTAG.

# SDW

SWD est un protocole spécifique à ARM conçu pour le débogage.

L'interface SWD nécessite **deux broches** : un signal bidirectionnel **SWDIO**, qui est l'équivalent des broches **TDI et TDO de JTAG et une horloge**, et **SWCLK**, qui est l'équivalent de **TCK** dans JTAG. De nombreux dispositifs prennent en charge le **port de débogage série ou JTAG (SWJ-DP)**, une interface JTAG et SWD combinée qui vous permet de connecter une sonde SWD ou JTAG à la cible. 

</details>

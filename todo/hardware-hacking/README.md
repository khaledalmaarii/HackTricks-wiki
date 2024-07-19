# Hardware Hacking

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

## JTAG

JTAG permet d'effectuer un scan de frontière. Le scan de frontière analyse certains circuits, y compris les cellules de scan de frontière intégrées et les registres pour chaque broche.

La norme JTAG définit **des commandes spécifiques pour effectuer des scans de frontière**, y compris les suivantes :

* **BYPASS** vous permet de tester une puce spécifique sans le surcoût de passer par d'autres puces.
* **SAMPLE/PRELOAD** prend un échantillon des données entrant et sortant du dispositif lorsqu'il est en mode de fonctionnement normal.
* **EXTEST** définit et lit les états des broches.

Il peut également prendre en charge d'autres commandes telles que :

* **IDCODE** pour identifier un dispositif
* **INTEST** pour le test interne du dispositif

Vous pourriez rencontrer ces instructions lorsque vous utilisez un outil comme le JTAGulator.

### Le Port d'Accès de Test

Les scans de frontière incluent des tests du **Port d'Accès de Test (TAP)** à quatre fils, un port à usage général qui fournit **un accès aux fonctions de support de test JTAG** intégrées dans un composant. TAP utilise les cinq signaux suivants :

* Entrée d'horloge de test (**TCK**) Le TCK est l'**horloge** qui définit à quelle fréquence le contrôleur TAP effectuera une action unique (en d'autres termes, passer à l'état suivant dans la machine d'état).
* Entrée de sélection de mode de test (**TMS**) Le TMS contrôle la **machine d'état finie**. À chaque battement de l'horloge, le contrôleur TAP JTAG du dispositif vérifie la tension sur la broche TMS. Si la tension est inférieure à un certain seuil, le signal est considéré comme bas et interprété comme 0, tandis que si la tension est supérieure à un certain seuil, le signal est considéré comme haut et interprété comme 1.
* Entrée de données de test (**TDI**) Le TDI est la broche qui envoie **des données dans la puce via les cellules de scan**. Chaque fournisseur est responsable de la définition du protocole de communication sur cette broche, car JTAG ne le définit pas.
* Sortie de données de test (**TDO**) Le TDO est la broche qui envoie **des données hors de la puce**.
* Entrée de réinitialisation de test (**TRST**) L'optionnelle TRST réinitialise la machine d'état finie **à un état connu**. Alternativement, si le TMS est maintenu à 1 pendant cinq cycles d'horloge consécutifs, cela invoque une réinitialisation, de la même manière que la broche TRST le ferait, c'est pourquoi TRST est optionnelle.

Parfois, vous pourrez trouver ces broches marquées sur le PCB. Dans d'autres cas, vous pourriez avoir besoin de **les trouver**.

### Identification des broches JTAG

La manière la plus rapide mais la plus coûteuse de détecter les ports JTAG est d'utiliser le **JTAGulator**, un dispositif créé spécifiquement à cet effet (bien qu'il puisse **également détecter les pinouts UART**).

Il a **24 canaux** que vous pouvez connecter aux broches des cartes. Ensuite, il effectue une **attaque BF** de toutes les combinaisons possibles en envoyant des commandes de scan de frontière **IDCODE** et **BYPASS**. S'il reçoit une réponse, il affiche le canal correspondant à chaque signal JTAG.

Une manière moins chère mais beaucoup plus lente d'identifier les pinouts JTAG est d'utiliser le [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) chargé sur un microcontrôleur compatible Arduino.

En utilisant **JTAGenum**, vous devez d'abord **définir les broches du dispositif de sonde** que vous utiliserez pour l'énumération. Vous devrez vous référer au diagramme de pinout du dispositif, puis connecter ces broches aux points de test de votre dispositif cible.

Une **troisième manière** d'identifier les broches JTAG est d'**inspecter le PCB** pour l'un des pinouts. Dans certains cas, les PCB peuvent fournir commodément l'**interface Tag-Connect**, ce qui est une indication claire que la carte a également un connecteur JTAG. Vous pouvez voir à quoi ressemble cette interface sur [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). De plus, l'inspection des **fiches techniques des chipsets sur le PCB** pourrait révéler des diagrammes de pinout qui pointent vers des interfaces JTAG.

## SDW

SWD est un protocole spécifique à ARM conçu pour le débogage.

L'interface SWD nécessite **deux broches** : un signal bidirectionnel **SWDIO**, qui est l'équivalent des broches **TDI et TDO de JTAG**, et une horloge, **SWCLK**, qui est l'équivalent de **TCK** dans JTAG. De nombreux dispositifs prennent en charge le **Port de Débogage à Fil Série ou JTAG (SWJ-DP)**, une interface combinée JTAG et SWD qui vous permet de connecter soit une sonde SWD soit une sonde JTAG à la cible.

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

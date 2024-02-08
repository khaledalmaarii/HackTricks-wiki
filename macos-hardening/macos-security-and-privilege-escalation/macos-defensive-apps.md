# Applications de défense macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Pare-feux

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html) : Il surveillera chaque connexion établie par chaque processus. Selon le mode (autoriser silencieusement les connexions, refuser silencieusement les connexions et alerter), il **vous montrera une alerte** à chaque nouvelle connexion établie. Il dispose également d'une interface graphique très pratique pour voir toutes ces informations.
* [**LuLu**](https://objective-see.org/products/lulu.html) : Pare-feu Objective-See. Il s'agit d'un pare-feu de base qui vous alertera des connexions suspectes (il possède une interface graphique mais elle n'est pas aussi élaborée que celle de Little Snitch).

## Détection de la persistance

* [**KnockKnock**](https://objective-see.org/products/knockknock.html) : Application Objective-See qui recherchera dans plusieurs emplacements où **les logiciels malveillants pourraient persister** (c'est un outil ponctuel, pas un service de surveillance).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html) : Comme KnockKnock en surveillant les processus générant de la persistance.

## Détection des enregistreurs de frappe

* [**ReiKey**](https://objective-see.org/products/reikey.html) : Application Objective-See pour trouver les **enregistreurs de frappe** qui installent des "taps d'événements" clavier.

## Détection des rançongiciels

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html) : Application Objective-See pour détecter les actions de **chiffrement de fichiers**.

## Détection du microphone et de la webcam

* [**OverSight**](https://objective-see.org/products/oversight.html) : Application Objective-See pour détecter les **applications qui commencent à utiliser la webcam et le microphone**.

## Détection de l'injection de processus

* [**Shield**](https://theevilbit.github.io/shield/) : Application qui **détecte différentes techniques d'injection de processus**.

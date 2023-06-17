# Applications de défense macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Pare-feux

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html) : Il surveillera chaque connexion effectuée par chaque processus. Selon le mode (autoriser silencieusement les connexions, refuser silencieusement les connexions et alerter), il vous **affichera une alerte** chaque fois qu'une nouvelle connexion est établie. Il dispose également d'une interface graphique très agréable pour voir toutes ces informations.
* [**LuLu**](https://objective-see.org/products/lulu.html) : Pare-feu Objective-See. Il s'agit d'un pare-feu de base qui vous alertera pour les connexions suspectes (il dispose d'une interface graphique mais elle n'est pas aussi élégante que celle de Little Snitch).

## Détection de la persistance

* [**KnockKnock**](https://objective-see.org/products/knockknock.html) : Application Objective-See qui recherchera dans plusieurs emplacements où **les logiciels malveillants pourraient persister** (c'est un outil ponctuel, pas un service de surveillance).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html) : Comme KnockKnock en surveillant les processus qui génèrent la persistance.

## Détection des enregistreurs de frappe

* [**ReiKey**](https://objective-see.org/products/reikey.html) : Application Objective-See pour trouver les **enregistreurs de frappe** qui installent des "touches d'événement" de clavier.

## Détection des rançongiciels

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html) : Application Objective-See pour détecter les actions de **chiffrement de fichiers**.

## Détection du microphone et de la webcam

* [**OverSight**](https://objective-see.org/products/oversight.html) : Application Objective-See pour détecter les **applications qui commencent à utiliser la webcam et le microphone.**

## Détection de l'injection de processus

* [**Shield**](https://theevilbit.github.io/shield/) : Application qui **détecte différentes techniques d'injection de processus**.

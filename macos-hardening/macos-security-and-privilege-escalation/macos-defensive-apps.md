# Applications défensives macOS

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Pare-feux

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html) : Il surveille chaque connexion établie par chaque processus. Selon le mode (autoriser les connexions en silence, refuser la connexion en silence et alerte), il vous **montrera une alerte** à chaque fois qu'une nouvelle connexion est établie. Il dispose également d'une interface graphique très agréable pour voir toutes ces informations.
* [**LuLu**](https://objective-see.org/products/lulu.html) : Pare-feu Objective-See. C'est un pare-feu basique qui vous alertera pour les connexions suspectes (il a une interface graphique mais elle n'est pas aussi sophistiquée que celle de Little Snitch).

## Détection de persistance

* [**KnockKnock**](https://objective-see.org/products/knockknock.html) : Application Objective-See qui recherche dans plusieurs emplacements où **le malware pourrait persister** (c'est un outil ponctuel, pas un service de surveillance).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html) : Comme KnockKnock en surveillant les processus qui génèrent de la persistance.

## Détection de keyloggers

* [**ReiKey**](https://objective-see.org/products/reikey.html) : Application Objective-See pour trouver les **keyloggers** qui installent des "event taps" de clavier.

## Détection de ransomware

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html) : Application Objective-See pour détecter les actions de **chiffrement de fichiers**.

## Détection de micro & webcam

* [**OverSight**](https://objective-see.org/products/oversight.html) : Application Objective-See pour détecter **l'application qui commence à utiliser la webcam et le micro.**

## Détection d'injection de processus

* [**Shield**](https://theevilbit.github.io/shield/) : Application qui **détecte différentes techniques d'injection de processus**.

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

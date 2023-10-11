# Applications de défense pour macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Pare-feux

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html) : Il surveillera chaque connexion établie par chaque processus. Selon le mode (autoriser silencieusement les connexions, refuser silencieusement les connexions et alerter), il **vous montrera une alerte** à chaque nouvelle connexion établie. Il dispose également d'une interface graphique très pratique pour visualiser toutes ces informations.
* [**LuLu**](https://objective-see.org/products/lulu.html) : Pare-feu Objective-See. Il s'agit d'un pare-feu basique qui vous alertera des connexions suspectes (il dispose d'une interface graphique mais elle n'est pas aussi élaborée que celle de Little Snitch).

## Détection de la persistance

* [**KnockKnock**](https://objective-see.org/products/knockknock.html) : Application Objective-See qui recherchera dans plusieurs emplacements où **les logiciels malveillants pourraient persister** (il s'agit d'un outil ponctuel, pas d'un service de surveillance).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html) : Comme KnockKnock, il surveille les processus qui génèrent de la persistance.

## Détection des enregistreurs de frappe

* [**ReiKey**](https://objective-see.org/products/reikey.html) : Application Objective-See pour trouver les **enregistreurs de frappe** qui installent des "event taps" clavier.

## Détection des ransomwares

* [**RansomWhere**](https://objective-see.org/products/ransomwhere.html) : Application Objective-See pour détecter les actions de **chiffrement de fichiers**.

## Détection du microphone et de la webcam

* [**OverSight**](https://objective-see.org/products/oversight.html) : Application Objective-See pour détecter les **applications qui utilisent la webcam et le microphone**.

## Détection de l'injection de processus

* [**Shield**](https://theevilbit.github.io/shield/) : Application qui **détecte différentes techniques d'injection de processus**.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

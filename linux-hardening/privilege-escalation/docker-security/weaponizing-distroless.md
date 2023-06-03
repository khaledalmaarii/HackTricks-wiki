# Armer Distroless

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Qu'est-ce que Distroless

Un conteneur distroless est un type de conteneur qui **contient uniquement les dépendances nécessaires pour exécuter une application spécifique**, sans aucun logiciel ou outil supplémentaire qui n'est pas requis. Ces conteneurs sont conçus pour être aussi **légers** et **sécurisés** que possible, et ils visent à **minimiser la surface d'attaque** en supprimant tous les composants inutiles.

Les conteneurs distroless sont souvent utilisés dans les **environnements de production où la sécurité et la fiabilité sont primordiales**.

Quelques **exemples** de **conteneurs distroless** sont :

* Fournis par **Google** : [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Fournis par **Chainguard** : [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Armer Distroless

Le but de l'armement d'un conteneur distroless est de pouvoir **exécuter des binaires et des charges utiles arbitraires même avec les limitations** impliquées par **distroless** (manque de binaires courants dans le système) et aussi les protections couramment trouvées dans les conteneurs tels que **lecture seule** ou **no-execute** dans `/dev/shm`.

### Via la mémoire

À venir à un moment donné de 2023...

### Via des binaires existants

#### openssl

****[**Dans ce post,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) il est expliqué que le binaire **`openssl`** est fréquemment trouvé dans ces conteneurs, potentiellement parce qu'il est **nécessaire** pour le logiciel qui va être exécuté à l'intérieur du conteneur.

En abusant du binaire **`openssl`**, il est possible d'**exécuter des choses arbitraires**.

# Armer Distroless

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs exclusifs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Qu'est-ce que Distroless

Un conteneur distroless est un type de conteneur qui **contient uniquement les dépendances nécessaires pour exécuter une application spécifique**, sans aucun logiciel ou outil supplémentaire qui n'est pas requis. Ces conteneurs sont conçus pour être aussi **légers** et **sécurisés** que possible, et ils visent à **minimiser la surface d'attaque** en supprimant tous les composants inutiles.

Les conteneurs distroless sont souvent utilisés dans des **environnements de production où la sécurité et la fiabilité sont primordiales**.

Quelques **exemples** de **conteneurs distroless** sont :

* Fournis par **Google** : [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Fournis par **Chainguard** : [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Armer Distroless

L'objectif d'armer un conteneur distroless est de pouvoir **exécuter des binaires et des charges utiles arbitraires même avec les limitations** impliquées par **distroless** (manque de binaires communs dans le système) et aussi les protections couramment trouvées dans les conteneurs telles que **read-only** ou **no-execute** dans `/dev/shm`.

### Par la mémoire

À venir à un moment donné de 2023...

### Via les binaires existants

#### openssl

****[**Dans cet article,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) il est expliqué que le binaire **`openssl`** est fréquemment trouvé dans ces conteneurs, potentiellement parce qu'il est **nécessaire** pour le logiciel qui va être exécuté à l'intérieur du conteneur.

Abuser du binaire **`openssl`** permet d'**exécuter des choses arbitraires**.

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs exclusifs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

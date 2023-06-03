# Pickle Rick

## Pickle Rick

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](../../.gitbook/assets/picklerick.gif)

Cette machine a été classée comme facile et elle était assez facile.

## Énumération

J'ai commencé **à énumérer la machine en utilisant mon outil** [**Legion**](https://github.com/carlospolop/legion) :

![](<../../.gitbook/assets/image (79) (2).png>)

Comme vous pouvez le voir, 2 ports sont ouverts : 80 (**HTTP**) et 22 (**SSH**)

J'ai donc lancé legion pour énumérer le service HTTP :

![](<../../.gitbook/assets/image (234).png>)

Notez que dans l'image, vous pouvez voir que `robots.txt` contient la chaîne `Wubbalubbadubdub`

Après quelques secondes, j'ai examiné ce que `disearch` avait déjà découvert :

![](<../../.gitbook/assets/image (235).png>)

![](<../../.gitbook/assets/image (236).png>)

Et comme vous pouvez le voir dans la dernière image, une **page de connexion** a été découverte.

En vérifiant le code source de la page racine, un nom d'utilisateur est découvert : `R1ckRul3s`

![](<../../.gitbook/assets/image (237) (1).png>)

Par conséquent, vous pouvez vous connecter sur la page de connexion en utilisant les identifiants `R1ckRul3s:Wubbalubbadubdub`

## Utilisateur

En utilisant ces identifiants, vous accéderez à un portail où vous pouvez exécuter des commandes :

![](<../../.gitbook/assets/image (241).png>)

Certaines commandes comme cat ne sont pas autorisées, mais vous pouvez lire le premier ingrédient (flag) en utilisant, par exemple, grep :

![](<../../.gitbook/assets/image (242).png>)

Ensuite, j'ai utilisé :

![](<../../.gitbook/assets/image (243) (1).png>)

Pour obtenir un shell inversé :

![](<../../.gitbook/assets/image (239) (1).png>)

Le **deuxième ingrédient** peut être trouvé dans `/home/rick`

![](<../../.gitbook/assets/image (240).png>)

## Racine

L'utilisateur **www-data peut exécuter n'importe quoi en tant que sudo** :

![](<../../.gitbook/assets/image (238).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

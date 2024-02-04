# Pickle Rick

## Pickle Rick

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous voulez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

![](../../.gitbook/assets/picklerick.gif)

Cette machine a été catégorisée comme facile et elle était assez simple.

## Énumération

J'ai commencé **à énumérer la machine en utilisant mon outil** [**Legion**](https://github.com/carlospolop/legion) :

![](<../../.gitbook/assets/image (79) (2).png>)

Comme vous pouvez le voir, 2 ports sont ouverts : 80 (**HTTP**) et 22 (**SSH**)

J'ai donc lancé Legion pour énumérer le service HTTP :

![](<../../.gitbook/assets/image (234).png>)

Notez que dans l'image, vous pouvez voir que `robots.txt` contient la chaîne `Wubbalubbadubdub`

Après quelques secondes, j'ai vérifié ce que `disearch` avait déjà découvert :

![](<../../.gitbook/assets/image (235).png>)

![](<../../.gitbook/assets/image (236).png>)

Et comme vous pouvez le voir dans la dernière image, une page de **connexion** a été découverte.

En vérifiant le code source de la page racine, un nom d'utilisateur est découvert : `R1ckRul3s`

![](<../../.gitbook/assets/image (237) (1).png>)

Par conséquent, vous pouvez vous connecter sur la page de connexion en utilisant les identifiants `R1ckRul3s:Wubbalubbadubdub`

## Utilisateur

En utilisant ces identifiants, vous accéderez à un portail où vous pouvez exécuter des commandes :

![](<../../.gitbook/assets/image (241).png>)

Certaines commandes comme cat ne sont pas autorisées, mais vous pouvez lire le premier ingrédient (drapeau) en utilisant par exemple grep :

![](<../../.gitbook/assets/image (242).png>)

Ensuite, j'ai utilisé :

![](<../../.gitbook/assets/image (243) (1).png>)

Pour obtenir un shell inversé :

![](<../../.gitbook/assets/image (239) (1).png>)

Le **deuxième ingrédient** peut être trouvé dans `/home/rick`

![](<../../.gitbook/assets/image (240).png>)

## Root

L'utilisateur **www-data peut exécuter n'importe quoi en tant que sudo** :

![](<../../.gitbook/assets/image (238).png>)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous voulez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

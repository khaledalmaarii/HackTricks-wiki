<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


# Résumé de l'attaque

Imaginez un serveur qui **signe** des **données** en **ajoutant** un **secret** à des données en clair connues, puis en hachant ces données. Si vous connaissez :

* **La longueur du secret** (cela peut également être obtenu par force brute dans une plage de longueurs données)
* **Les données en clair**
* **L'algorithme (et qu'il est vulnérable à cette attaque)**
* **Le padding est connu**
* Habituellement, un padding par défaut est utilisé, donc si les 3 autres conditions sont remplies, celui-ci l'est également
* Le padding varie en fonction de la longueur du secret+des données, c'est pourquoi la longueur du secret est nécessaire

Alors, il est possible pour un **attaquant** d'**ajouter** des **données** et de **générer** une **signature** valide pour les **données précédentes + données ajoutées**.

## Comment ?

Essentiellement, les algorithmes vulnérables génèrent les hachages en hachant d'abord un bloc de données, puis, à partir du hachage précédemment créé (état), ils ajoutent le bloc de données suivant et le hachent.

Ensuite, imaginez que le secret est "secret" et les données sont "data", le MD5 de "secretdata" est 6036708eba0d11f6ef52ad44e8b74d5b.\
Si un attaquant souhaite ajouter la chaîne "append", il peut :

* Générer un MD5 de 64 "A"
* Changer l'état du hachage initialisé précédemment en 6036708eba0d11f6ef52ad44e8b74d5b
* Ajouter la chaîne "append"
* Terminer le hachage et le hachage résultant sera un **valide pour "secret" + "data" + "padding" + "append"**

## **Outil**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Références

Vous pouvez trouver cette attaque bien expliquée dans [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

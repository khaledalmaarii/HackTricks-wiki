<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# CBC

Si le **cookie** est **uniquement** le **nom d'utilisateur** (ou la première partie du cookie est le nom d'utilisateur) et que vous souhaitez usurper l'identité du nom d'utilisateur "**admin**". Alors, vous pouvez créer le nom d'utilisateur **"bdmin"** et **forcer brutalement** le **premier octet** du cookie.

# CBC-MAC

En cryptographie, un **code d'authentification de message en chaînage de blocs de chiffrement** (**CBC-MAC**) est une technique pour construire un code d'authentification de message à partir d'un chiffrement par blocs. Le message est chiffré avec un algorithme de chiffrement par blocs en mode CBC pour créer une **chaîne de blocs telle que chaque bloc dépend du chiffrement correct du bloc précédent**. Cette interdépendance garantit qu'un **changement** dans **n'importe quel** des **bits** en clair entraînera un **changement** du **bloc chiffré final** d'une manière qui ne peut être prédite ou contrée sans connaître la clé du chiffrement par blocs.

Pour calculer le CBC-MAC d'un message m, on chiffre m en mode CBC avec un vecteur d'initialisation à zéro et on conserve le dernier bloc. La figure suivante illustre le calcul du CBC-MAC d'un message composé de blocs ![m\_{1}\\|m\_{2}\\|\cdots \\|m\_{x}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) en utilisant une clé secrète k et un chiffrement par blocs E :

![Structure CBC-MAC (en).svg](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Vulnérabilité

Avec CBC-MAC, généralement le **IV utilisé est 0**.\
C'est un problème car 2 messages connus (`m1` et `m2`) généreront indépendamment 2 signatures (`s1` et `s2`). Donc :

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Ensuite, un message composé de m1 et m2 concaténés (m3) générera 2 signatures (s31 et s32) :

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Ce qui est possible à calculer sans connaître la clé du chiffrement.**

Imaginez que vous chiffrez le nom **Administrator** en blocs de **8 octets** :

* `Administ`
* `rator\00\00\00`

Vous pouvez créer un nom d'utilisateur appelé **Administ** (m1) et récupérer la signature (s1).\
Ensuite, vous pouvez créer un nom d'utilisateur appelé le résultat de `rator\00\00\00 XOR s1`. Cela générera `E(m2 XOR s1 XOR 0)` qui est s32.\
Maintenant, vous pouvez utiliser s32 comme signature du nom complet **Administrator**.

### Résumé

1. Obtenez la signature du nom d'utilisateur **Administ** (m1) qui est s1
2. Obtenez la signature du nom d'utilisateur **rator\x00\x00\x00 XOR s1 XOR 0** qui est s32**.**
3. Réglez le cookie sur s32 et il sera un cookie valide pour l'utilisateur **Administrator**.

# Attaque Contrôlant IV

Si vous pouvez contrôler le IV utilisé, l'attaque pourrait être très facile.\
Si le cookie est juste le nom d'utilisateur chiffré, pour usurper l'utilisateur "**administrator**", vous pouvez créer l'utilisateur "**Administrator**" et vous obtiendrez son cookie.\
Maintenant, si vous pouvez contrôler le IV, vous pouvez changer le premier octet du IV de sorte que **IV\[0] XOR "A" == IV'\[0] XOR "a"** et régénérer le cookie pour l'utilisateur **Administrator**. Ce cookie sera valide pour **usurper** l'utilisateur **administrator** avec le **IV** initial.

# Références

Plus d'informations sur [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs.

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# CBC

Si le **cookie** est **seulement** le **nom d'utilisateur** (ou la première partie du cookie est le nom d'utilisateur) et que vous voulez vous faire passer pour l'utilisateur "**admin**". Alors, vous pouvez créer le nom d'utilisateur **"bdmin"** et **bruteforcer** le **premier octet** du cookie.

# CBC-MAC

En cryptographie, un **code d'authentification de message en mode de chiffrement par blocs en chaîne** (**CBC-MAC**) est une technique de construction d'un code d'authentification de message à partir d'un algorithme de chiffrement par blocs. Le message est chiffré avec un algorithme de chiffrement par blocs en mode CBC pour créer une **chaîne de blocs telle que chaque bloc dépend du chiffrement correct du bloc précédent**. Cette interdépendance garantit qu'un **changement** de **n'importe quel** bit du texte en clair provoquera le **changement** du **dernier bloc chiffré** d'une manière qui ne peut être prédite ou contrecarrée sans connaître la clé du chiffrement par blocs.

Pour calculer le CBC-MAC du message m, on chiffre m en mode CBC avec un vecteur d'initialisation nul et on conserve le dernier bloc. La figure suivante illustre le calcul du CBC-MAC d'un message comprenant des blocs![m\_{1}\\|m\_{2}\\|\cdots \\|m\_{x}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) en utilisant une clé secrète k et un chiffrement par blocs E :

![CBC-MAC structure (en).svg](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Vulnérabilité

Avec CBC-MAC, l'**IV utilisé est généralement 0**.\
C'est un problème car 2 messages connus (`m1` et `m2`) généreront indépendamment 2 signatures (`s1` et `s2`). Ainsi :

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Ensuite, un message composé de m1 et m2 concaténés (m3) générera 2 signatures (s31 et s32) :

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Ce qui est possible à calculer sans connaître la clé du chiffrement.**

Imaginez que vous chiffrez le nom **Administrateur** en blocs de **8 octets** :

* `Administ`
* `rator\00\00\00`

Vous pouvez créer un nom d'utilisateur appelé **Administ** (m1) et récupérer la signature (s1).\
Ensuite, vous pouvez créer un nom d'utilisateur appelé le résultat de `rator\00\00\00 XOR s1`. Cela générera `E(m2 XOR s1 XOR 0)` qui est s32.\
maintenant, vous pouvez utiliser s32 comme signature du nom complet **Administrateur**.

### Résumé

1. Obtenez la signature du nom d'utilisateur **Administ** (m1) qui est s1
2. Obtenez la signature du nom d'utilisateur **rator\x00\x00\x00 XOR s1 XOR 0** est s32**.**
3. Définissez le cookie sur s32 et ce sera un cookie valide pour l'utilisateur **Administrateur**.

# Contrôle de l'IV d'attaque

Si vous pouvez contrôler l'IV utilisé, l'attaque peut être très facile.\
Si les cookies ne sont que le nom d'utilisateur chiffré, pour vous faire passer pour l'utilisateur "**administrateur**", vous pouvez créer l'utilisateur "**Administrator**" et vous obtiendrez son cookie.\
Maintenant, si vous pouvez contrôler l'IV, vous pouvez changer le premier octet de l'IV de sorte que **IV\[0] XOR "A" == IV'\[0] XOR "a"** et régénérer le cookie pour l'utilisateur **Administrator**. Ce cookie sera valide pour **se faire passer pour** l'utilisateur **administrateur** avec l'IV initial.

# Références

Plus d'informations sur [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)

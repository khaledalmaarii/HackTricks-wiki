{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}


# CBC

Si le **cookie** est **seulement** le **nom d'utilisateur** (ou la première partie du cookie est le nom d'utilisateur) et que vous souhaitez vous faire passer pour l'utilisateur "**admin**". Ensuite, vous pouvez créer le nom d'utilisateur **"bdmin"** et **bruteforcer** le **premier octet** du cookie.

# CBC-MAC

Le **code d'authentification de message en mode chaînage de blocs** (**CBC-MAC**) est une méthode utilisée en cryptographie. Il fonctionne en prenant un message et en l'encryptant bloc par bloc, où le chiffrement de chaque bloc est lié à celui qui le précède. Ce processus crée une **chaîne de blocs**, garantissant que même un seul bit du message original modifié entraînera un changement imprévisible dans le dernier bloc de données chiffrées. Pour effectuer ou inverser un tel changement, la clé de chiffrement est requise, assurant la sécurité.

Pour calculer le CBC-MAC du message m, on chiffre m en mode CBC avec un vecteur d'initialisation nul et on garde le dernier bloc. La figure suivante esquisse le calcul du CBC-MAC d'un message composé de blocs ![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) en utilisant une clé secrète k et un chiffrement de bloc E :

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Vulnérabilité

Avec le CBC-MAC, l'**IV utilisé est généralement 0**.\
C'est un problème car 2 messages connus (`m1` et `m2`) généreront indépendamment 2 signatures (`s1` et `s2`). Ainsi :

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Ensuite, un message composé de m1 et m2 concaténés (m3) générera 2 signatures (s31 et s32) :

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Il est possible de calculer cela sans connaître la clé de chiffrement.**

Imaginez que vous chiffrez le nom **Administrateur** en blocs de **8 octets** :

* `Administ`
* `rator\00\00\00`

Vous pouvez créer un nom d'utilisateur appelé **Administ** (m1) et récupérer la signature (s1).\
Ensuite, vous pouvez créer un nom d'utilisateur appelé le résultat de `rator\00\00\00 XOR s1`. Cela générera `E(m2 XOR s1 XOR 0)` qui est s32.\
maintenant, vous pouvez utiliser s32 comme la signature du nom complet **Administrateur**.

### Résumé

1. Obtenez la signature du nom d'utilisateur **Administ** (m1) qui est s1
2. Obtenez la signature du nom d'utilisateur **rator\x00\x00\x00 XOR s1 XOR 0** qui est s32**.**
3. Définissez le cookie sur s32 et il sera un cookie valide pour l'utilisateur **Administrateur**.

# Contrôle de l'attaque IV

Si vous pouvez contrôler l'IV utilisé, l'attaque pourrait être très facile.\
Si les cookies ne sont que le nom d'utilisateur chiffré, pour vous faire passer pour l'utilisateur "**administrateur**" vous pouvez créer l'utilisateur "**Administrateur**" et vous obtiendrez son cookie.\
Maintenant, si vous pouvez contrôler l'IV, vous pouvez changer le premier octet de l'IV donc **IV\[0] XOR "A" == IV'\[0] XOR "a"** et régénérer le cookie pour l'utilisateur **Administrateur**. Ce cookie sera valide pour **usurper** l'utilisateur **administrateur** avec l'IV initial.

## Références

Plus d'informations sur [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

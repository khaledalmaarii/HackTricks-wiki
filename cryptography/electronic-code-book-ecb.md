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


# ECB

(ECB) Electronic Code Book - schéma de chiffrement symétrique qui **remplace chaque bloc du texte en clair** par le **bloc de texte chiffré**. C'est le schéma de chiffrement le **plus simple**. L'idée principale est de **diviser** le texte en clair en **blocs de N bits** (dépend de la taille du bloc de données d'entrée, de l'algorithme de chiffrement) puis de chiffrer (déchiffrer) chaque bloc de texte en clair en utilisant la seule clé.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

L'utilisation de l'ECB a plusieurs implications en termes de sécurité :

* **Des blocs du message chiffré peuvent être supprimés**
* **Des blocs du message chiffré peuvent être déplacés**

# Détection de la vulnérabilité

Imaginez que vous vous connectez à une application plusieurs fois et que vous **obtenez toujours le même cookie**. Cela est dû au fait que le cookie de l'application est **`<nom d'utilisateur>|<mot de passe>`**.\
Ensuite, vous générez deux nouveaux utilisateurs, tous deux avec le **même mot de passe long** et **presque** le **même** **nom d'utilisateur**.\
Vous découvrez que les **blocs de 8B** où les **informations des deux utilisateurs** sont les mêmes sont **identiques**. Ensuite, vous imaginez que cela pourrait être dû à l'utilisation de l'ECB.

Comme dans l'exemple suivant. Observez comment ces **2 cookies décodés** ont plusieurs fois le bloc **`\x23U\xE45K\xCB\x21\xC8`**
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Cela est dû au fait que le **nom d'utilisateur et le mot de passe de ces cookies contenaient plusieurs fois la lettre "a"** (par exemple). Les **blocs** qui sont **différents** sont des blocs qui contenaient **au moins 1 caractère différent** (peut-être le délimiteur "|" ou une différence nécessaire dans le nom d'utilisateur).

Maintenant, l'attaquant doit simplement découvrir si le format est `<nom d'utilisateur><délimiteur><mot de passe>` ou `<mot de passe><délimiteur><nom d'utilisateur>`. Pour ce faire, il peut simplement **générer plusieurs noms d'utilisateur** avec des **noms d'utilisateur et des mots de passe similaires et longs jusqu'à ce qu'il trouve le format et la longueur du délimiteur :**

| Longueur du nom d'utilisateur : | Longueur du mot de passe : | Longueur du nom d'utilisateur + mot de passe : | Longueur du cookie (après décodage) : |
| ------------------------------- | -------------------------- | ------------------------------------------- | --------------------------------------- |
| 2                               | 2                          | 4                                           | 8                                       |
| 3                               | 3                          | 6                                           | 8                                       |
| 3                               | 4                          | 7                                           | 8                                       |
| 4                               | 4                          | 8                                           | 16                                      |
| 7                               | 7                          | 14                                          | 16                                      |

# Exploitation de la vulnérabilité

## Suppression de blocs entiers

Connaissant le format du cookie (`<nom d'utilisateur>|<mot de passe>`), afin d'usurper l'identité de l'utilisateur `admin`, créez un nouvel utilisateur appelé `aaaaaaaaadmin` et obtenez le cookie, puis décodez-le :
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Nous pouvons voir le motif `\x23U\xE45K\xCB\x21\xC8` créé précédemment avec le nom d'utilisateur qui ne contenait que `a`.\
Ensuite, vous pouvez supprimer le premier bloc de 8B et vous obtiendrez un cookie valide pour le nom d'utilisateur `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Déplacement de blocs

Dans de nombreuses bases de données, il est équivalent de rechercher `WHERE username='admin';` ou `WHERE username='admin    ';` _(Notez les espaces supplémentaires)_

Ainsi, une autre façon d'usurper l'utilisateur `admin` serait de :

* Générer un nom d'utilisateur tel que : `len(<username>) + len(<delimiter) % len(block)`. Avec une taille de bloc de `8B`, vous pouvez générer un nom d'utilisateur appelé : `username       `, avec le délimiteur `|` le morceau `<username><delimiter>` générera 2 blocs de 8B.
* Ensuite, générer un mot de passe qui remplira un nombre exact de blocs contenant le nom d'utilisateur que nous voulons usurper et des espaces, par exemple : `admin   `

Le cookie de cet utilisateur sera composé de 3 blocs : les 2 premiers sont les blocs du nom d'utilisateur + délimiteur et le troisième est celui du mot de passe (qui simule le nom d'utilisateur) : `username       |admin   `

**Ensuite, il suffit de remplacer le premier bloc par le dernier et vous usurperez l'utilisateur `admin` : `admin          |username`**

## Références

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))

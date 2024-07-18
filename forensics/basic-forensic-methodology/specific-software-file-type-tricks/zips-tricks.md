# Astuces ZIP

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

Les outils en ligne de commande pour gérer les **fichiers zip** sont essentiels pour diagnostiquer, réparer et craquer les fichiers zip. Voici quelques utilitaires clés :

- **`unzip`** : Révèle pourquoi un fichier zip peut ne pas se décompresser.
- **`zipdetails -v`** : Offre une analyse détaillée des champs du format de fichier zip.
- **`zipinfo`** : Liste le contenu d'un fichier zip sans les extraire.
- **`zip -F input.zip --out output.zip`** et **`zip -FF input.zip --out output.zip`** : Essayez de réparer les fichiers zip corrompus.
- **[fcrackzip](https://github.com/hyc/fcrackzip)** : Un outil pour craquer par force brute les mots de passe zip, efficace pour les mots de passe jusqu'à environ 7 caractères.

La [spécification du format de fichier Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fournit des détails complets sur la structure et les normes des fichiers zip.

Il est crucial de noter que les fichiers zip protégés par mot de passe **n'encryptent pas les noms de fichiers ni les tailles de fichiers** à l'intérieur, une faille de sécurité non partagée avec les fichiers RAR ou 7z qui encryptent ces informations. De plus, les fichiers zip encryptés avec la méthode ZipCrypto plus ancienne sont vulnérables à une **attaque en texte clair** si une copie non encryptée d'un fichier compressé est disponible. Cette attaque exploite le contenu connu pour craquer le mot de passe du zip, une vulnérabilité détaillée dans [l'article de HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) et expliquée plus en détail dans [cet article académique](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Cependant, les fichiers zip sécurisés avec le chiffrement **AES-256** sont immunisés contre cette attaque en texte clair, mettant en évidence l'importance de choisir des méthodes de chiffrement sécurisées pour les données sensibles.

## Références
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

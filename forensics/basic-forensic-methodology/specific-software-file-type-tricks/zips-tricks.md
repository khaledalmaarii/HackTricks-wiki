# Astuces ZIP

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

Il existe plusieurs outils en ligne de commande pour les fichiers zip qui seront utiles à connaître.

* `unzip` fournira souvent des informations utiles sur la raison pour laquelle un zip ne se décompresse pas.
* `zipdetails -v` fournira des informations approfondies sur les valeurs présentes dans les différents champs du format.
* `zipinfo` liste des informations sur le contenu du fichier zip, sans l'extraire.
* `zip -F input.zip --out output.zip` et `zip -FF input.zip --out output.zip` tentent de réparer un fichier zip corrompu.
* [fcrackzip](https://github.com/hyc/fcrackzip) devine par force brute un mot de passe zip (pour des mots de passe <7 caractères environ).

[Spécification du format de fichier Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

Une note importante en matière de sécurité concernant les fichiers zip protégés par mot de passe est qu'ils n'encryptent pas les noms de fichiers et les tailles de fichiers originaux des fichiers compressés qu'ils contiennent, contrairement aux fichiers RAR ou 7z protégés par mot de passe.

Une autre note sur le craquage de zip est que si vous avez une copie non chiffrée/décompressée de l'un des fichiers qui sont compressés dans le zip chiffré, vous pouvez effectuer une "attaque en clair" et craquer le zip, comme [détailé ici](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files), et expliqué dans [ce document](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Le nouveau schéma de protection par mot de passe des fichiers zip (avec AES-256, plutôt que "ZipCrypto") n'a pas cette faiblesse.

De : [https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](https://app.gitbook.com/o/Iwnw24TnSs9D9I2OtTKX/s/-L\_2uGJGU7AVNRcqRvEi/)

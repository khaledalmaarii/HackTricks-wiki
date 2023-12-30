# Astuces ZIP

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Il existe plusieurs outils en ligne de commande pour les fichiers zip qui seront utiles à connaître.

* `unzip` affiche souvent des informations utiles sur les raisons pour lesquelles un zip ne se décompresse pas.
* `zipdetails -v` fournit des informations détaillées sur les valeurs présentes dans les différents champs du format.
* `zipinfo` liste des informations sur le contenu du fichier zip, sans l'extraire.
* `zip -F input.zip --out output.zip` et `zip -FF input.zip --out output.zip` tentent de réparer un fichier zip corrompu.
* [fcrackzip](https://github.com/hyc/fcrackzip) effectue des tentatives de force brute pour deviner un mot de passe zip (pour des mots de passe de <7 caractères environ).

[Spécification du format de fichier Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

Un point important concernant la sécurité des fichiers zip protégés par mot de passe est qu'ils ne chiffrent pas les noms de fichiers et les tailles de fichiers originales des fichiers compressés qu'ils contiennent, contrairement aux fichiers RAR ou 7z protégés par mot de passe.

Un autre point concernant le crack de zip est que si vous avez une copie non chiffrée/non compressée de l'un des fichiers qui sont compressés dans le zip chiffré, vous pouvez effectuer une "attaque par texte en clair" et cracker le zip, comme [décrit ici](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files), et expliqué dans [ce document](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Le nouveau schéma de protection par mot de passe des fichiers zip (avec AES-256, plutôt que "ZipCrypto") n'a pas cette faiblesse.

De : [https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](https://app.gitbook.com/o/Iwnw24TnSs9D9I2OtTKX/s/-L\_2uGJGU7AVNRcqRvEi/)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

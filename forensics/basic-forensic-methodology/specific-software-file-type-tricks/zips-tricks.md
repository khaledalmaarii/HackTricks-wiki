# Astuces pour les fichiers ZIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Il existe plusieurs outils en ligne de commande pour les fichiers ZIP qui seront utiles à connaître.

* `unzip` affiche souvent des informations utiles sur la raison pour laquelle un fichier ZIP ne peut pas être décompressé.
* `zipdetails -v` fournit des informations détaillées sur les valeurs présentes dans les différents champs du format.
* `zipinfo` liste les informations sur le contenu du fichier ZIP, sans l'extraire.
* `zip -F input.zip --out output.zip` et `zip -FF input.zip --out output.zip` tentent de réparer un fichier ZIP corrompu.
* [fcrackzip](https://github.com/hyc/fcrackzip) effectue une attaque par force brute pour deviner le mot de passe d'un fichier ZIP (pour les mots de passe de moins de 7 caractères environ).

[Spécification du format de fichier ZIP](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

Une note importante en matière de sécurité concernant les fichiers ZIP protégés par mot de passe est qu'ils n'encryptent pas les noms de fichiers et les tailles de fichiers d'origine des fichiers compressés qu'ils contiennent, contrairement aux fichiers RAR ou 7z protégés par mot de passe.

Une autre note concernant le craquage des fichiers ZIP est que si vous disposez d'une copie non chiffrée/non compressée de l'un des fichiers qui sont compressés dans le fichier ZIP chiffré, vous pouvez effectuer une "attaque par texte en clair" et craquer le fichier ZIP, comme [détaillé ici](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files), et expliqué dans [ce document](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Le nouveau schéma de protection par mot de passe des fichiers ZIP (avec AES-256, plutôt que "ZipCrypto") n'a pas cette faiblesse.

Source : [https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](http://127.0.0.1:5000/s/-L\_2uGJGU7AVNRcqRvEi/)

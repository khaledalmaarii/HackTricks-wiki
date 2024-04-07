# Stockage Cloud Local

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

<figure><img src="../../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser facilement des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

Sous Windows, vous pouvez trouver le dossier OneDrive dans `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Et à l'intérieur de `logs\Personal`, il est possible de trouver le fichier `SyncDiagnostics.log` qui contient certaines données intéressantes concernant les fichiers synchronisés :

* Taille en octets
* Date de création
* Date de modification
* Nombre de fichiers dans le cloud
* Nombre de fichiers dans le dossier
* **CID** : Identifiant unique de l'utilisateur OneDrive
* Heure de génération du rapport
* Taille du disque dur du système d'exploitation

Une fois que vous avez trouvé le CID, il est recommandé de **rechercher des fichiers contenant cet ID**. Vous pourriez trouver des fichiers portant le nom : _**\<CID>.ini**_ et _**\<CID>.dat**_ qui peuvent contenir des informations intéressantes comme les noms des fichiers synchronisés avec OneDrive.

## Google Drive

Sous Windows, vous pouvez trouver le dossier principal de Google Drive dans `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ce dossier contient un fichier appelé Sync\_log.log avec des informations telles que l'adresse e-mail du compte, les noms de fichiers, les horodatages, les hachages MD5 des fichiers, etc. Même les fichiers supprimés apparaissent dans ce fichier journal avec leur hachage MD5 correspondant.

Le fichier **`Cloud_graph\Cloud_graph.db`** est une base de données sqlite qui contient la table **`cloud_graph_entry`**. Dans cette table, vous pouvez trouver le **nom** des **fichiers synchronisés**, l'heure de modification, la taille et le hachage MD5 des fichiers.

Les données de la table de la base de données **`Sync_config.db`** contiennent l'adresse e-mail du compte, le chemin des dossiers partagés et la version de Google Drive.

## Dropbox

Dropbox utilise des **bases de données SQLite** pour gérer les fichiers. Dans ce cas,\
Vous pouvez trouver les bases de données dans les dossiers :

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

Et les principales bases de données sont :

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

L'extension ".dbx" signifie que les **bases de données** sont **chiffrées**. Dropbox utilise **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Pour mieux comprendre le chiffrement utilisé par Dropbox, vous pouvez lire [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Cependant, les principales informations sont :

* **Entropie** : d114a55212655f74bd772e37e64aee9b
* **Sel** : 0D638C092E8B82FC452883F95F355B8E
* **Algorithme** : PBKDF2
* **Itérations** : 1066

Outre ces informations, pour déchiffrer les bases de données, vous avez encore besoin de :

* La **clé DPAPI chiffrée** : Vous pouvez la trouver dans le registre à l'intérieur de `NTUSER.DAT\Software\Dropbox\ks\client` (exportez ces données en binaire)
* Les ruches **`SYSTEM`** et **`SECURITY`**
* Les **clés maîtresses DPAPI** : Qui peuvent être trouvées dans `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* Le **nom d'utilisateur** et le **mot de passe** de l'utilisateur Windows

Ensuite, vous pouvez utiliser l'outil [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (440).png>)

Si tout se passe comme prévu, l'outil indiquera la **clé principale** dont vous avez besoin pour **récupérer l'originale**. Pour récupérer l'originale, utilisez simplement cette [recette cyber\_chef](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\) en mettant la clé principale comme "phrase secrète" à l'intérieur de la recette.

Le hex résultant est la clé finale utilisée pour chiffrer les bases de données qui peuvent être déchiffrées avec :
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
La base de données **`config.dbx`** contient :

- **Email** : L'email de l'utilisateur
- **usernamedisplayname** : Le nom de l'utilisateur
- **dropbox\_path** : Chemin où se trouve le dossier Dropbox
- **Host\_id : Hash** utilisé pour s'authentifier sur le cloud. Cela ne peut être révoqué que depuis le web.
- **Root\_ns** : Identifiant de l'utilisateur

La base de données **`filecache.db`** contient des informations sur tous les fichiers et dossiers synchronisés avec Dropbox. La table `File_journal` est celle qui contient le plus d'informations utiles :

- **Server\_path** : Chemin où se trouve le fichier sur le serveur (ce chemin est précédé par l'`host_id` du client).
- **local\_sjid** : Version du fichier
- **local\_mtime** : Date de modification
- **local\_ctime** : Date de création

D'autres tables à l'intérieur de cette base de données contiennent des informations plus intéressantes :

- **block\_cache** : hachage de tous les fichiers et dossiers de Dropbox
- **block\_ref** : Relie l'ID de hachage de la table `block_cache` avec l'ID de fichier dans la table `file_journal`
- **mount\_table** : Partager des dossiers de Dropbox
- **deleted\_fields** : Fichiers supprimés de Dropbox
- **date\_added**

<figure><img src="../../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Rejoignez** 💬 le groupe Discord](https://discord.gg/hRep4RUj7f) ou le [groupe Telegram](https://t.me/peass) ou **suivez-nous** sur Twitter 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

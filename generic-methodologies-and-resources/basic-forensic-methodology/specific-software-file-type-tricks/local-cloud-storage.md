# Stockage Cloud Local

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR au** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) pour créer et **automatiser des flux de travail** alimentés par les **outils communautaires les plus avancés** au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

## OneDrive

Dans Windows, vous pouvez trouver le dossier OneDrive dans `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Et à l'intérieur de `logs\Personal`, il est possible de trouver le fichier `SyncDiagnostics.log` qui contient des données intéressantes concernant les fichiers synchronisés :

* Taille en octets
* Date de création
* Date de modification
* Nombre de fichiers dans le cloud
* Nombre de fichiers dans le dossier
* **CID** : ID unique de l'utilisateur OneDrive
* Heure de génération du rapport
* Taille du disque dur du système d'exploitation

Une fois que vous avez trouvé le CID, il est recommandé de **chercher des fichiers contenant cet ID**. Vous pourriez être en mesure de trouver des fichiers avec le nom : _**\<CID>.ini**_ et _**\<CID>.dat**_ qui peuvent contenir des informations intéressantes comme les noms des fichiers synchronisés avec OneDrive.

## Google Drive

Dans Windows, vous pouvez trouver le dossier principal de Google Drive dans `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ce dossier contient un fichier appelé Sync\_log.log avec des informations comme l'adresse e-mail du compte, les noms de fichiers, les horodatages, les hachages MD5 des fichiers, etc. Même les fichiers supprimés apparaissent dans ce fichier journal avec leur MD5 correspondant.

Le fichier **`Cloud_graph\Cloud_graph.db`** est une base de données sqlite qui contient la table **`cloud_graph_entry`**. Dans cette table, vous pouvez trouver le **nom** des **fichiers synchronisés**, l'heure de modification, la taille et le hachage MD5 des fichiers.

Les données de la table de la base de données **`Sync_config.db`** contiennent l'adresse e-mail du compte, le chemin des dossiers partagés et la version de Google Drive.

## Dropbox

Dropbox utilise des **bases de données SQLite** pour gérer les fichiers. Dans ce\
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

Cependant, les informations principales sont :

* **Entropie** : d114a55212655f74bd772e37e64aee9b
* **Sel** : 0D638C092E8B82FC452883F95F355B8E
* **Algorithme** : PBKDF2
* **Itérations** : 1066

En plus de ces informations, pour déchiffrer les bases de données, vous avez encore besoin de :

* La **clé DPAPI chiffrée** : Vous pouvez la trouver dans le registre à l'intérieur de `NTUSER.DAT\Software\Dropbox\ks\client` (exportez ces données au format binaire)
* Les **hives** **`SYSTEM`** et **`SECURITY`**
* Les **clés maîtresses DPAPI** : Qui peuvent être trouvées dans `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* Le **nom d'utilisateur** et le **mot de passe** de l'utilisateur Windows

Ensuite, vous pouvez utiliser l'outil [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (443).png>)

Si tout se passe comme prévu, l'outil indiquera la **clé primaire** que vous devez **utiliser pour récupérer l'originale**. Pour récupérer l'originale, utilisez simplement cette [recette cyber\_chef](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) en mettant la clé primaire comme "phrase de passe" à l'intérieur de la recette.

Le hex résultant est la clé finale utilisée pour chiffrer les bases de données qui peuvent être déchiffrées avec :
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Le **`config.dbx`** base de données contient :

* **Email** : L'email de l'utilisateur
* **usernamedisplayname** : Le nom de l'utilisateur
* **dropbox\_path** : Chemin où le dossier Dropbox est situé
* **Host\_id: Hash** utilisé pour s'authentifier dans le cloud. Cela ne peut être révoqué que depuis le web.
* **Root\_ns** : Identifiant de l'utilisateur

La **`filecache.db`** base de données contient des informations sur tous les fichiers et dossiers synchronisés avec Dropbox. La table `File_journal` est celle avec les informations les plus utiles :

* **Server\_path** : Chemin où le fichier est situé à l'intérieur du serveur (ce chemin est précédé par le `host_id` du client).
* **local\_sjid** : Version du fichier
* **local\_mtime** : Date de modification
* **local\_ctime** : Date de création

D'autres tables à l'intérieur de cette base de données contiennent des informations plus intéressantes :

* **block\_cache** : hash de tous les fichiers et dossiers de Dropbox
* **block\_ref** : Relie l'ID de hash de la table `block_cache` avec l'ID de fichier dans la table `file_journal`
* **mount\_table** : Dossiers partagés de Dropbox
* **deleted\_fields** : Fichiers supprimés de Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) pour créer facilement et **automatiser des flux de travail** alimentés par les **outils communautaires les plus avancés** au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

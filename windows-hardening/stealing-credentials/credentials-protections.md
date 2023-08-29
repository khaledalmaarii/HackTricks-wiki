# Protections des informations d'identification Windows

## Protections des informations d'identification

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## WDigest

Le protocole [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) a été introduit dans Windows XP et a été conçu pour être utilisé avec le protocole HTTP pour l'authentification. Microsoft a activé ce protocole **par défaut dans plusieurs versions de Windows** (Windows XP - Windows 8.0 et Windows Server 2003 - Windows Server 2012), ce qui signifie que **les mots de passe en texte clair sont stockés dans le LSASS** (Local Security Authority Subsystem Service). **Mimikatz** peut interagir avec le LSASS, permettant à un attaquant de **récupérer ces informations d'identification** grâce à la commande suivante :
```
sekurlsa::wdigest
```
Ce comportement peut être désactivé/activé en définissant la valeur de _**UseLogonCredential**_ et _**Negotiate**_ sur 1 dans _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_.\
Si ces clés de registre n'existent pas ou si la valeur est "0", alors WDigest sera désactivé.
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Protection LSA

Microsoft dans **Windows 8.1 et versions ultérieures** a fourni une protection supplémentaire pour le LSA afin de **prévenir** les processus non fiables de pouvoir **lire sa mémoire** ou d'injecter du code. Cela empêchera le fonctionnement correct de la commande `mimikatz.exe sekurlsa:logonpasswords`.\
Pour **activer cette protection**, vous devez définir la valeur _**RunAsPPL**_ dans _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ sur 1.
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Contournement

Il est possible de contourner cette protection en utilisant le pilote Mimikatz mimidrv.sys :

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard** est une nouvelle fonctionnalité de Windows 10 (éditions Enterprise et Education) qui aide à protéger vos informations d'identification sur une machine contre des menaces telles que le pass the hash. Cela fonctionne grâce à une technologie appelée Virtual Secure Mode (VSM) qui utilise les extensions de virtualisation du CPU (mais ce n'est pas une machine virtuelle réelle) pour fournir une **protection aux zones de mémoire** (vous pouvez entendre cela appelé Sécurité basée sur la virtualisation ou VBS). VSM crée une "bulle" séparée pour les **processus** clés qui sont **isolés** des processus réguliers du **système d'exploitation**, même du noyau, et **seuls des processus de confiance spécifiques peuvent communiquer avec les processus** (appelés **trustlets**) dans VSM. Cela signifie qu'un processus dans le système d'exploitation principal ne peut pas lire la mémoire de VSM, même les processus du noyau. L'**Autorité de sécurité locale (LSA) est l'un des trustlets** dans VSM, en plus du processus **LSASS** standard qui s'exécute toujours dans le système d'exploitation principal pour assurer la compatibilité avec les processus existants, mais qui agit en réalité comme un proxy ou un stub pour communiquer avec la version dans VSM, garantissant ainsi que les informations d'identification réelles s'exécutent sur la version dans VSM et sont donc protégées contre les attaques. Pour Windows 10, Credential Guard doit être activé et déployé dans votre organisation car il n'est **pas activé par défaut**.
À partir de [https://www.itprotoday.com/windows-10/what-credential-guard](https://www.itprotoday.com/windows-10/what-credential-guard). Vous pouvez trouver plus d'informations et un script PS1 pour activer Credential Guard [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage). Cependant, à partir de Windows 11 Enterprise, version 22H2 et Windows 11 Education, version 22H2, les systèmes compatibles ont Windows Defender Credential Guard [activé par défaut](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage#Default%20Enablement).

Dans ce cas, **Mimikatz ne peut pas faire grand-chose pour contourner** cela et extraire les hachages de LSASS. Mais vous pouvez toujours ajouter votre **SSP personnalisé** et **capturer les informations d'identification** lorsque l'utilisateur essaie de se connecter en **clair**.
Plus d'informations sur [**SSP et comment le faire ici**](../active-directory-methodology/custom-ssp.md).

Credentials Guard peut être **activé de différentes manières**. Pour vérifier s'il est activé en utilisant le registre, vous pouvez vérifier la valeur de la clé _**LsaCfgFlags**_ dans _**HKLM\System\CurrentControlSet\Control\LSA**_. Si la valeur est **"1"**, alors il est actif avec verrouillage UEFI, si **"2"**, il est actif sans verrouillage et si **"0"**, il n'est pas activé.
Cela **n'est pas suffisant pour activer Credentials Guard** (mais c'est un indicateur fort).
Vous pouvez trouver plus d'informations et un script PS1 pour activer Credential Guard [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
## Mode RestrictedAdmin RDP

Avec Windows 8.1 et Windows Server 2012 R2, de nouvelles fonctionnalités de sécurité ont été introduites. L'une de ces fonctionnalités de sécurité est le mode _Restricted Admin pour RDP_. Cette nouvelle fonctionnalité de sécurité est introduite pour atténuer le risque d'attaques de type [pass the hash](https://blog.ahasayen.com/pass-the-hash/).

Lorsque vous vous connectez à un ordinateur distant en utilisant RDP, vos informations d'identification sont stockées sur l'ordinateur distant auquel vous vous connectez en RDP. Habituellement, vous utilisez un compte puissant pour vous connecter à des serveurs distants, et avoir vos informations d'identification stockées sur tous ces ordinateurs représente en effet une menace pour la sécurité.

En utilisant le mode _Restricted Admin pour RDP_, lorsque vous vous connectez à un ordinateur distant en utilisant la commande **mstsc.exe /RestrictedAdmin**, vous serez authentifié sur l'ordinateur distant, mais **vos informations d'identification ne seront pas stockées sur cet ordinateur distant**, comme cela aurait été le cas par le passé. Cela signifie que si un logiciel malveillant ou même un utilisateur malveillant est actif sur ce serveur distant, vos informations d'identification ne seront pas disponibles sur ce serveur de bureau distant pour que le logiciel malveillant puisse les attaquer.

Notez que vos informations d'identification ne sont pas enregistrées dans la session RDP, si vous **essayez d'accéder à des ressources réseau**, vos informations d'identification ne seront pas utilisées. **L'identité de la machine sera utilisée à la place**.

![](../../.gitbook/assets/ram.png)

À partir de [ici](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Informations d'identification mises en cache

Les **informations d'identification du domaine** sont utilisées par les composants du système d'exploitation et sont **authentifiées** par l'**Autorité de sécurité locale** (LSA). Généralement, les informations d'identification du domaine sont établies pour un utilisateur lorsqu'un package de sécurité enregistré authentifie les données de connexion de l'utilisateur. Ce package de sécurité enregistré peut être le protocole **Kerberos** ou **NTLM**.

**Windows stocke les dix dernières informations d'identification de connexion au domaine au cas où le contrôleur de domaine serait hors ligne**. Si le contrôleur de domaine est hors ligne, un utilisateur pourra **tout de même se connecter à son ordinateur**. Cette fonctionnalité est principalement destinée aux utilisateurs d'ordinateurs portables qui ne se connectent pas régulièrement au domaine de leur entreprise. Le nombre d'informations d'identification stockées par l'ordinateur peut être contrôlé par la clé de registre suivante, ou via une stratégie de groupe :
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Les informations d'identification sont cachées aux utilisateurs normaux, y compris aux comptes administrateurs. L'utilisateur **SYSTEM** est le seul utilisateur ayant les **privilèges** nécessaires pour **afficher** ces **informations d'identification**. Afin qu'un administrateur puisse consulter ces informations d'identification dans le registre, il doit y accéder en tant qu'utilisateur SYSTEM.\
Les informations d'identification mises en cache sont stockées dans le registre à l'emplacement suivant :
```
HKEY_LOCAL_MACHINE\SECURITY\Cache
```
**Extraction depuis Mimikatz**: `lsadump::cache`\
À partir de [ici](http://juggernaut.wikidot.com/cached-credentials).

## Utilisateurs protégés

Lorsque l'utilisateur connecté est membre du groupe Utilisateurs protégés, les protections suivantes sont appliquées :

* La délégation des informations d'identification (CredSSP) ne mettra pas en cache les informations d'identification en texte brut de l'utilisateur, même lorsque le paramètre de stratégie de groupe **Autoriser la délégation des informations d'identification par défaut** est activé.
* À partir de Windows 8.1 et de Windows Server 2012 R2, Windows Digest ne mettra pas en cache les informations d'identification en texte brut de l'utilisateur, même lorsque Windows Digest est activé.
* **NTLM** ne mettra **pas en cache** les informations d'identification en texte brut de l'utilisateur ni la fonction unidirectionnelle NT (NTOWF).
* **Kerberos** ne créera plus de clés **DES** ou **RC4**. De plus, il ne mettra pas en cache les informations d'identification en texte brut de l'utilisateur ni les clés à long terme après l'acquisition du TGT initial.
* Un vérificateur mis en cache n'est pas créé lors de la connexion ou du déverrouillage, donc la connexion hors ligne n'est plus prise en charge.

Après l'ajout du compte utilisateur au groupe Utilisateurs protégés, la protection commencera lorsque l'utilisateur se connectera à l'appareil. **À partir** [**d'ici**](https://docs.microsoft.com/fr-fr/windows-server/security/credentials-protection-and-management/protected-users-security-group)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Opérateurs de compte    | Opérateurs de compte     | Opérateurs de compte                                                          | Opérateurs de compte         |
| Administrateur          | Administrateur           | Administrateur                                                                | Administrateur               |
| Administrateurs         | Administrateurs          | Administrateurs                                                               | Administrateurs              |
| Opérateurs de sauvegarde| Opérateurs de sauvegarde | Opérateurs de sauvegarde                                                       | Opérateurs de sauvegarde     |
| Éditeurs de certificats |                          |                                                                               |                              |
| Administrateurs de domaine | Administrateurs de domaine | Administrateurs de domaine                                                   | Administrateurs de domaine   |
| Contrôleurs de domaine  | Contrôleurs de domaine   | Contrôleurs de domaine                                                         | Contrôleurs de domaine       |
| Administrateurs d'entreprise | Administrateurs d'entreprise | Administrateurs d'entreprise                                               | Administrateurs d'entreprise|
|                         |                          |                                                                               | Administrateurs de clé d'entreprise |
|                         |                          |                                                                               | Administrateurs de clé       |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Opérateurs d'impression | Opérateurs d'impression  | Opérateurs d'impression                                                        | Opérateurs d'impression      |
|                         |                          | Contrôleurs de domaine en lecture seule                                        | Contrôleurs de domaine en lecture seule |
| Réplicateur             | Réplicateur              | Réplicateur                                                                    | Réplicateur                   |
| Administrateurs de schéma | Administrateurs de schéma | Administrateurs de schéma                                                   | Administrateurs de schéma    |
| Opérateurs de serveur   | Opérateurs de serveur    | Opérateurs de serveur                                                          | Opérateurs de serveur        |

**Tableau à partir** [**d'ici**](https://docs.microsoft.com/fr-fr/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

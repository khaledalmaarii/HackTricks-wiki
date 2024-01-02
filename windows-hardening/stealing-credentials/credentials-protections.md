# Protections des identifiants Windows

## Protections des identifiants

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## WDigest

Le protocole [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) a été introduit dans Windows XP et a été conçu pour être utilisé avec le protocole HTTP pour l'authentification. Microsoft a ce protocole **activé par défaut dans plusieurs versions de Windows** (Windows XP — Windows 8.0 et Windows Server 2003 — Windows Server 2012), ce qui signifie que **les mots de passe en clair sont stockés dans le LSASS** (Local Security Authority Subsystem Service). **Mimikatz** peut interagir avec le LSASS permettant à un attaquant de **récupérer ces identifiants** grâce à la commande suivante :
```
sekurlsa::wdigest
```
Ce comportement peut être **désactivé/activé en définissant sur 1** la valeur de _**UseLogonCredential**_ et _**Negotiate**_ dans _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_.\
Si ces clés de registre **n'existent pas** ou si la valeur est **"0"**, alors WDigest sera **désactivé**.
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Protection LSA

Microsoft dans **Windows 8.1 et versions ultérieures** a fourni une protection supplémentaire pour le LSA afin de **prévenir** les processus non fiables de pouvoir **lire sa mémoire** ou d'injecter du code. Cela empêchera le fonctionnement correct de `mimikatz.exe sekurlsa:logonpasswords`.\
Pour **activer cette protection**, vous devez définir la valeur _**RunAsPPL**_ dans _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ à 1.
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Contournement

Il est possible de contourner cette protection en utilisant le pilote Mimikatz mimidrv.sys :

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard** est une nouvelle fonctionnalité de Windows 10 (éditions Enterprise et Education) qui aide à protéger vos identifiants sur une machine contre des menaces telles que pass the hash. Cela fonctionne grâce à une technologie appelée Virtual Secure Mode (VSM) qui utilise les extensions de virtualisation du CPU (mais ce n'est pas une véritable machine virtuelle) pour fournir **une protection aux zones de mémoire** (vous pourriez entendre cela désigné sous le nom de Virtualization Based Security ou VBS). VSM crée une "bulle" séparée pour les **processus** clés qui sont **isolés** des processus réguliers du **système d'exploitation**, y compris le noyau et **seuls les processus de confiance spécifiques peuvent communiquer avec les processus** (connus sous le nom de **trustlets**) dans le VSM. Cela signifie qu'un processus dans le système d'exploitation principal ne peut pas lire la mémoire de VSM, même les processus du noyau. **L'Autorité de Sécurité Locale (LSA) est l'un des trustlets** dans VSM en plus du processus standard **LSASS** qui fonctionne toujours dans le système d'exploitation principal pour assurer la compatibilité avec les processus existants mais agit vraiment comme un proxy ou un stub pour communiquer avec la version dans VSM en s'assurant que les identifiants réels fonctionnent sur la version dans VSM et sont donc protégés contre les attaques. Pour Windows 10, Credential Guard doit être activé et déployé dans votre organisation car il n'est **pas activé par défaut.**
Depuis [https://www.itprotoday.com/windows-10/what-credential-guard](https://www.itprotoday.com/windows-10/what-credential-guard). Plus d'informations et un script PS1 pour activer Credential Guard [peuvent être trouvés ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage). Cependant, à partir de Windows 11 Enterprise, version 22H2 et Windows 11 Education, version 22H2, les systèmes compatibles ont Windows Defender Credential Guard [activé par défaut](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage#Default%20Enablement).

Dans ce cas, **Mimikatz ne peut pas faire grand-chose pour contourner** cela et extraire les hachages de LSASS. Mais vous pourriez toujours ajouter votre **SSP personnalisé** et **capturer les identifiants** lorsqu'un utilisateur essaie de se connecter en **texte clair**.\
Plus d'informations sur [**SSP et comment faire cela ici**](../active-directory-methodology/custom-ssp.md).

Credential Guard pourrait être **activé de différentes manières**. Pour vérifier s'il a été activé en utilisant le registre, vous pourriez vérifier la valeur de la clé _**LsaCfgFlags**_ dans _**HKLM\System\CurrentControlSet\Control\LSA**_. Si la valeur est **"1"**, alors il est actif avec verrouillage UEFI, si **"2"**, il est actif sans verrouillage et si **"0"**, il n'est pas activé.\
Cela n'est **pas suffisant pour activer Credential Guard** (mais c'est un indicateur fort).\
Plus d'informations et un script PS1 pour activer Credential Guard [peuvent être trouvés ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
## Mode RDP RestrictedAdmin

Avec Windows 8.1 et Windows Server 2012 R2, de nouvelles fonctionnalités de sécurité ont été introduites. L'une de ces fonctionnalités de sécurité est le _mode Restricted Admin pour RDP_. Cette nouvelle fonctionnalité de sécurité est introduite pour atténuer le risque d'attaques [pass the hash](https://blog.ahasayen.com/pass-the-hash/).

Lorsque vous vous connectez à un ordinateur distant en utilisant RDP, vos identifiants sont stockés sur l'ordinateur distant auquel vous vous connectez en RDP. Habituellement, vous utilisez un compte puissant pour vous connecter aux serveurs distants, et le fait d'avoir vos identifiants stockés sur tous ces ordinateurs constitue effectivement une menace pour la sécurité.

En utilisant le _mode Restricted Admin pour RDP_, lorsque vous vous connectez à un ordinateur distant en utilisant la commande, **mstsc.exe /RestrictedAdmin**, vous serez authentifié sur l'ordinateur distant, mais **vos identifiants ne seront pas stockés sur cet ordinateur distant**, comme ils l'auraient été par le passé. Cela signifie que si un logiciel malveillant ou même un utilisateur malveillant est actif sur ce serveur distant, vos identifiants ne seront pas disponibles sur ce serveur de bureau à distance pour que le logiciel malveillant puisse attaquer.

Notez que comme vos identifiants ne sont pas sauvegardés dans la session RDP, si **vous essayez d'accéder aux ressources réseau**, vos identifiants ne seront pas utilisés. **L'identité de la machine sera utilisée à la place**.

![](../../.gitbook/assets/ram.png)

Depuis [ici](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Identifiants mis en cache

**Les identifiants de domaine** sont utilisés par les composants du système d'exploitation et sont **authentifiés** par l'**Autorité de sécurité locale** (LSA). Typiquement, les identifiants de domaine sont établis pour un utilisateur lorsque un package de sécurité enregistré authentifie les données de connexion de l'utilisateur. Ce package de sécurité enregistré peut être le protocole **Kerberos** ou **NTLM**.

**Windows stocke les dix derniers identifiants de connexion au domaine dans l'éventualité où le contrôleur de domaine serait hors ligne**. Si le contrôleur de domaine est hors ligne, un utilisateur pourra **toujours se connecter à son ordinateur**. Cette fonctionnalité est principalement destinée aux utilisateurs d'ordinateurs portables qui ne se connectent pas régulièrement au domaine de leur entreprise. Le nombre d'identifiants que l'ordinateur stocke peut être contrôlé par la **clé de registre suivante, ou via la stratégie de groupe** :
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Les identifiants sont cachés des utilisateurs normaux, même des comptes administrateurs. L'utilisateur **SYSTEM** est le seul utilisateur qui a les **privilèges** pour **voir** ces **identifiants**. Pour qu'un administrateur puisse voir ces identifiants dans le registre, il doit accéder au registre en tant qu'utilisateur SYSTEM.
Les identifiants mis en cache sont stockés dans le registre à l'emplacement suivant :
```
HKEY_LOCAL_MACHINE\SECURITY\Cache
```
**Extraction depuis Mimikatz** : `lsadump::cache`\
Depuis [ici](http://juggernaut.wikidot.com/cached-credentials).

## Utilisateurs Protégés

Lorsque l'utilisateur connecté est membre du groupe Utilisateurs Protégés, les protections suivantes sont appliquées :

* La délégation d'identifiants (CredSSP) ne mettra pas en cache les identifiants en clair de l'utilisateur, même lorsque le paramètre de stratégie de groupe **Autoriser la délégation des identifiants par défaut** est activé.
* À partir de Windows 8.1 et Windows Server 2012 R2, Windows Digest ne mettra pas en cache les identifiants en clair de l'utilisateur, même lorsque Windows Digest est activé.
* **NTLM** ne mettra **pas en cache** les identifiants en clair de l'utilisateur ou la fonction **à sens unique NT** (NTOWF).
* **Kerberos** ne créera plus de clés **DES** ou **RC4**. De plus, il ne mettra pas en cache les identifiants en clair de l'utilisateur ou les clés à long terme après l'acquisition du TGT initial.
* **Un vérificateur mis en cache n'est pas créé lors de la connexion ou du déverrouillage**, donc la connexion hors ligne n'est plus prise en charge.

Après l'ajout du compte utilisateur au groupe Utilisateurs Protégés, la protection commencera lorsque l'utilisateur se connectera à l'appareil. **Depuis** [**ici**](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

**Tableau depuis** [**ici**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

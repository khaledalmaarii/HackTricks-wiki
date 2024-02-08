# Protections des identifiants Windows

## Protections des identifiants

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## WDigest

Le protocole [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396), introduit avec Windows XP, est conçu pour l'authentification via le protocole HTTP et est **activé par défaut sur Windows XP à Windows 8.0 et Windows Server 2003 à Windows Server 2012**. Ce paramètre par défaut entraîne un **stockage des mots de passe en texte clair dans LSASS** (Local Security Authority Subsystem Service). Un attaquant peut utiliser Mimikatz pour **extraire ces identifiants** en exécutant :
```bash
sekurlsa::wdigest
```
Pour **activer ou désactiver cette fonctionnalité**, les clés de registre _**UseLogonCredential**_ et _**Negotiate**_ situées dans _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ doivent être définies sur "1". Si ces clés sont **absentes ou définies sur "0"**, WDigest est **désactivé**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Protection LSA

À partir de **Windows 8.1**, Microsoft a amélioré la sécurité de LSA pour **bloquer les lectures de mémoire non autorisées ou les injections de code par des processus non fiables**. Cette amélioration entrave le fonctionnement habituel de commandes telles que `mimikatz.exe sekurlsa:logonpasswords`. Pour **activer cette protection renforcée**, la valeur _**RunAsPPL**_ dans _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ doit être ajustée à 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Contournement

Il est possible de contourner cette protection en utilisant le pilote Mimikatz mimidrv.sys :

![](../../.gitbook/assets/mimidrv.png)

## Garde des informations d'identification

**Garde des informations d'identification**, une fonctionnalité exclusive aux éditions **Windows 10 (Entreprise et Éducation)**, renforce la sécurité des informations d'identification de la machine en utilisant le **Mode sécurisé virtuel (VSM)** et la **Sécurité basée sur la virtualisation (VBS)**. Elle exploite les extensions de virtualisation du CPU pour isoler les processus clés dans un espace mémoire protégé, hors de portée du système d'exploitation principal. Cette isolation garantit que même le noyau ne peut pas accéder à la mémoire dans le VSM, protégeant efficacement les informations d'identification contre des attaques comme le **pass-the-hash**. L'**Autorité de sécurité locale (LSA)** fonctionne dans cet environnement sécurisé en tant que trustlet, tandis que le processus **LSASS** dans le système d'exploitation principal agit simplement comme un communicateur avec l'LSA du VSM.

Par défaut, la **Garde des informations d'identification** n'est pas active et nécessite une activation manuelle au sein d'une organisation. C'est essentiel pour renforcer la sécurité contre des outils comme **Mimikatz**, qui sont entravés dans leur capacité à extraire des informations d'identification. Cependant, des vulnérabilités peuvent encore être exploitées en ajoutant des **Fournisseurs de support de sécurité (SSP)** personnalisés pour capturer des informations d'identification en clair lors de tentatives de connexion.

Pour vérifier l'état d'activation de la **Garde des informations d'identification**, la clé de registre **_LsaCfgFlags_** sous **_HKLM\System\CurrentControlSet\Control\LSA_** peut être inspectée. Une valeur de "**1**" indique une activation avec **verrouillage UEFI**, "**2**" sans verrouillage, et "**0**" indique qu'elle n'est pas activée. Cette vérification de registre, bien qu'un indicateur fort, n'est pas la seule étape pour activer la Garde des informations d'identification. Des directives détaillées et un script PowerShell pour activer cette fonctionnalité sont disponibles en ligne.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Pour une compréhension complète et des instructions sur l'activation de **Credential Guard** dans Windows 10 et son activation automatique dans les systèmes compatibles de **Windows 11 Enterprise et Education (version 22H2)**, visitez la [documentation de Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Des détails supplémentaires sur la mise en œuvre de SSP personnalisés pour la capture d'informations d'identification sont fournis dans [ce guide](../active-directory-methodology/custom-ssp.md).


## Mode RestrictedAdmin RDP

**Windows 8.1 et Windows Server 2012 R2** ont introduit plusieurs nouvelles fonctionnalités de sécurité, y compris le **_mode Restricted Admin pour RDP_**. Ce mode a été conçu pour renforcer la sécurité en atténuant les risques associés aux attaques de type **[pass the hash](https://blog.ahasayen.com/pass-the-hash/)**.

Traditionnellement, lors de la connexion à un ordinateur distant via RDP, vos informations d'identification sont stockées sur la machine cible. Cela pose un risque de sécurité important, en particulier lors de l'utilisation de comptes avec des privilèges élevés. Cependant, avec l'introduction du **_mode Restricted Admin_**, ce risque est considérablement réduit.

Lors de l'initialisation d'une connexion RDP en utilisant la commande **mstsc.exe /RestrictedAdmin**, l'authentification sur l'ordinateur distant est effectuée sans stocker vos informations d'identification sur celui-ci. Cette approche garantit que, en cas d'infection par un logiciel malveillant ou si un utilisateur malveillant accède au serveur distant, vos informations d'identification ne sont pas compromises, car elles ne sont pas stockées sur le serveur.

Il est important de noter que dans le **mode Restricted Admin**, les tentatives d'accès aux ressources réseau à partir de la session RDP n'utiliseront pas vos informations d'identification personnelles; à la place, l'**identité de la machine** est utilisée.

Cette fonctionnalité marque une avancée significative dans la sécurisation des connexions de bureau à distance et la protection des informations sensibles contre toute exposition en cas de violation de sécurité.

![](../../.gitbook/assets/ram.png)

Pour des informations plus détaillées, visitez [cette ressource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).


## Informations d'identification mises en cache

Windows sécurise les **informations d'identification de domaine** via l'**Autorité de sécurité locale (LSA)**, prenant en charge les processus de connexion avec des protocoles de sécurité tels que **Kerberos** et **NTLM**. Une fonctionnalité clé de Windows est sa capacité à mettre en cache les **dix dernières connexions de domaine** pour garantir que les utilisateurs puissent toujours accéder à leurs ordinateurs même si le **contrôleur de domaine est hors ligne**—un avantage pour les utilisateurs d'ordinateurs portables souvent loin du réseau de leur entreprise.

Le nombre de connexions mises en cache est ajustable via une **clé de registre spécifique ou une stratégie de groupe**. Pour afficher ou modifier ce paramètre, la commande suivante est utilisée:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
L'accès à ces informations d'identification mises en cache est étroitement contrôlé, seul le compte **SYSTEM** ayant les autorisations nécessaires pour les visualiser. Les administrateurs qui ont besoin d'accéder à ces informations doivent le faire avec les privilèges utilisateur SYSTEM. Les informations d'identification sont stockées à l'emplacement : `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** peut être utilisé pour extraire ces informations d'identification mises en cache en utilisant la commande `lsadump::cache`.

Pour plus de détails, la [source](http://juggernaut.wikidot.com/cached-credentials) originale fournit des informations complètes.


## Utilisateurs Protégés

L'appartenance au groupe **Utilisateurs Protégés** introduit plusieurs améliorations de sécurité pour les utilisateurs, garantissant des niveaux de protection plus élevés contre le vol et l'abus d'informations d'identification :

- **Délégation d'informations d'identification (CredSSP)** : Même si le paramètre de stratégie de groupe pour **Autoriser la délégation des informations d'identification par défaut** est activé, les informations d'identification en texte clair des Utilisateurs Protégés ne seront pas mises en cache.
- **Windows Digest** : À partir de **Windows 8.1 et Windows Server 2012 R2**, le système ne mettra pas en cache les informations d'identification en texte clair des Utilisateurs Protégés, quel que soit le statut de Windows Digest.
- **NTLM** : Le système ne mettra pas en cache les informations d'identification en texte clair des Utilisateurs Protégés ou les fonctions unidirectionnelles NT (NTOWF).
- **Kerberos** : Pour les Utilisateurs Protégés, l'authentification Kerberos ne générera pas de clés **DES** ou **RC4**, ni ne mettra en cache les informations d'identification en texte clair ou les clés à long terme au-delà de l'acquisition initiale du Ticket-Granting Ticket (TGT).
- **Connexion Hors Ligne** : Les Utilisateurs Protégés n'auront pas de vérificateur mis en cache créé lors de la connexion ou du déverrouillage, ce qui signifie que la connexion hors ligne n'est pas prise en charge pour ces comptes.

Ces protections sont activées dès qu'un utilisateur, membre du groupe **Utilisateurs Protégés**, se connecte à l'appareil. Cela garantit que des mesures de sécurité critiques sont en place pour se protéger contre diverses méthodes de compromission des informations d'identification.

Pour des informations plus détaillées, consultez la [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) officielle.

**Tableau extrait de** [**la documentation**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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
|                         |                          | Contrôleurs de domaine en lecture seule                                       | Contrôleurs de domaine en lecture seule |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

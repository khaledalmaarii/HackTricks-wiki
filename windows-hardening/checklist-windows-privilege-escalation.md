# Checklist - Élévation de privilèges locale Windows

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Meilleur outil pour rechercher des vecteurs d'élévation de privilèges locaux Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informations Système](windows-local-privilege-escalation/#system-info)

* [ ] Obtenir des [**informations système**](windows-local-privilege-escalation/#system-info)
* [ ] Rechercher des **exploits de noyau** [**à l'aide de scripts**](windows-local-privilege-escalation/#version-exploits)
* [ ] Utiliser **Google pour rechercher** des **exploits de noyau**
* [ ] Utiliser **searchsploit pour rechercher** des **exploits de noyau**
* [ ] Informations intéressantes dans les [**variables d'environnement**](windows-local-privilege-escalation/#environment) ?
* [ ] Mots de passe dans l'[**historique PowerShell**](windows-local-privilege-escalation/#powershell-history) ?
* [ ] Informations intéressantes dans les [**paramètres Internet**](windows-local-privilege-escalation/#internet-settings) ?
* [ ] [**Lecteurs**](windows-local-privilege-escalation/#drives) ?
* [ ] [**Exploit WSUS**](windows-local-privilege-escalation/#wsus) ?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated) ?

### [Énumération des logs/AV](windows-local-privilege-escalation/#enumeration)

* [ ] Vérifier les paramètres [**Audit**](windows-local-privilege-escalation/#audit-settings) et [**WEF**](windows-local-privilege-escalation/#wef)
* [ ] Vérifier [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Vérifier si [**WDigest**](windows-local-privilege-escalation/#wdigest) est actif
* [ ] [**Protection LSA**](windows-local-privilege-escalation/#lsa-protection) ?
* [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard) ?
* [ ] [**Identifiants en cache**](windows-local-privilege-escalation/#cached-credentials) ?
* [ ] Vérifier s'il y a un [**AV**](windows-av-bypass)
* [ ] [**Politique AppLocker**](authentication-credentials-uac-and-efs#applocker-policy) ?
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**Privilèges utilisateur**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Vérifier les [**privilèges de l'utilisateur actuel**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Êtes-vous [**membre d'un groupe privilégié**](windows-local-privilege-escalation/#privileged-groups) ?
* [ ] Vérifier si vous avez [l'un de ces jetons activés](windows-local-privilege-escalation/#token-manipulation) : **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Sessions utilisateurs**](windows-local-privilege-escalation/#logged-users-sessions) ?
* [ ] Vérifier les [**domiciles des utilisateurs**](windows-local-privilege-escalation/#home-folders) (accès ?)
* [ ] Vérifier la [**Politique de mot de passe**](windows-local-privilege-escalation/#password-policy)
* [ ] Qu'y a-t-il [**dans le Presse-papiers**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard) ?

### [Réseau](windows-local-privilege-escalation/#network)

* [ ] Vérifier les [**informations réseau actuelles**](windows-local-privilege-escalation/#network)
* [ ] Vérifier les **services locaux cachés** restreints à l'extérieur

### [Processus en cours](windows-local-privilege-escalation/#running-processes)

* [ ] Permissions des [**fichiers binaires des processus et des dossiers**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**Extraction de mots de passe en mémoire**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**Applications GUI non sécurisées**](windows-local-privilege-escalation/#insecure-gui-apps)

### [Services](windows-local-privilege-escalation/#services)

* [ ] [Pouvez-vous **modifier un service** ?](windows-local-privilege-escalation#permissions)
* [ ] [Pouvez-vous **modifier** le **binaire** qui est **exécuté** par un **service** ?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Pouvez-vous **modifier** le **registre** d'un **service** ?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [Pouvez-vous tirer parti d'un **chemin de binaire de service non cité** ?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/#applications)

* [ ] **Écrire** des [**permissions sur les applications installées**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**Applications de démarrage**](windows-local-privilege-escalation/#run-at-startup)
* [ ] [**Pilotes vulnérables**](windows-local-privilege-escalation/#drivers)

### [Détournement de DLL](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Pouvez-vous **écrire dans un dossier du PATH** ?
* [ ] Y a-t-il un service connu qui **essaie de charger une DLL inexistante** ?
* [ ] Pouvez-vous **écrire** dans un **dossier de binaires** ?

### [Réseau](windows-local-privilege-escalation/#network)

* [ ] Énumérer le réseau (partages, interfaces, routes, voisins, ...)
* [ ] Porter une attention particulière aux services réseau écoutant sur localhost (127.0.0.1)

### [Identifiants Windows](windows-local-privilege-escalation/#windows-credentials)

* [ ] Identifiants [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)
* [ ] Identifiants [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) que vous pourriez utiliser ?
* [ ] Informations intéressantes sur les [**identifiants DPAPI**](windows-local-privilege-escalation/#dpapi) ?
* [ ] Mots de passe des [**réseaux Wifi enregistrés**](windows-local-privilege-escalation/#wifi) ?
* [ ] Informations intéressantes dans les [**connexions RDP enregistrées**](windows-local-privilege-escalation/#saved-rdp-connections) ?
* [ ] Mots de passe dans les [**commandes récemment exécutées**](windows-local-privilege-escalation/#recently-run-commands) ?
* [ ] Mots de passe du [**Gestionnaire d'identifiants de Bureau à distance**](windows-local-privilege-escalation/#remote-desktop-credential-manager) ?
* [ ] [**AppCmd.exe** existe](windows-local-privilege-escalation/#appcmd-exe) ? Identifiants ?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm) ? Chargement latéral de DLL ?

### [Fichiers et Registre (Identifiants)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty :** [**Identifiants**](windows-local-privilege-escalation/#putty-creds) **et** [**clés d'hôte SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**Clés SSH dans le registre**](windows-local-privilege-escalation/#ssh-keys-in-registry) ?
* [ ] Mots de passe dans les [**fichiers non surveillés**](windows-local-privilege-escalation/#unattended-files) ?
* [ ] Une sauvegarde [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) ?
* [ ] [**Identifiants Cloud**](windows-local-privilege-escalation/#cloud-credentials) ?
* [ ] Fichier [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) ?
* [ ] [**Mot de passe GPP en cache**](windows-local-privilege-escalation/#cached-gpp-pasword) ?
* [ ] Mot de passe dans le [**fichier de configuration Web IIS**](windows-local-privilege-escalation/#iis-web-config) ?
* [ ] Informations intéressantes dans les [**logs web**](windows-local-privilege-escalation/#logs) ?
* [ ] Voulez-vous [**demander des identifiants**](windows-local-privilege-escalation/#ask-for-credentials) à l'utilisateur ?
* [ ] Fichiers intéressants dans la [**Corbeille**](windows-local-privilege-escalation/#credentials-in-the-recyclebin) ?
* [ ] Autres [**registres contenant des identifiants**](windows-local-privilege-escalation/#inside-the-registry) ?
* [ ] À l'intérieur des [**données du navigateur**](windows-local-privilege-escalation/#browsers-history) (dbs, historique, favoris, ...) ?
* [ ] [**Recherche générique de mots de passe**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) dans les fichiers et le registre
* [ ] [**Outils**](windows-local-privilege-escalation/#tools-that-search-for-passwords) pour rechercher automatiquement des mots de passe

### [Gestionnaires divulgués](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Avez-vous accès à un gestionnaire d'un processus exécuté par l'administrateur ?

### [Usurpation de client de pipe](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Vérifiez si vous pouvez en abuser

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

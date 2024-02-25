# Abus de jetons

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Vous voulez voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Jetons

Si vous **ne savez pas ce que sont les jetons d'accès Windows**, lisez cette page avant de continuer :

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Peut-être pourriez-vous être en mesure d'escalader les privilèges en abusant des jetons que vous avez déjà**

### SeImpersonatePrivilege

Il s'agit d'un privilège détenu par n'importe quel processus qui permet l'impersonation (mais pas la création) de n'importe quel jeton, à condition qu'une poignée de celui-ci puisse être obtenue. Un jeton privilégié peut être acquis à partir d'un service Windows (DCOM) en l'incitant à effectuer une authentification NTLM contre une exploitation, permettant ensuite l'exécution d'un processus avec des privilèges SYSTEM. Cette vulnérabilité peut être exploitée à l'aide de divers outils, tels que [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (qui nécessite que winrm soit désactivé), [SweetPotato](https://github.com/CCob/SweetPotato) et [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Il est très similaire à **SeImpersonatePrivilege**, il utilisera la **même méthode** pour obtenir un jeton privilégié.\
Ensuite, ce privilège permet de **assigner un jeton principal** à un processus nouveau/en attente. Avec le jeton d'impersonation privilégié, vous pouvez dériver un jeton principal (DuplicateTokenEx).\
Avec le jeton, vous pouvez créer un **nouveau processus** avec 'CreateProcessAsUser' ou créer un processus en attente et **définir le jeton** (en général, vous ne pouvez pas modifier le jeton principal d'un processus en cours d'exécution).

### SeTcbPrivilege

Si vous avez activé ce jeton, vous pouvez utiliser **KERB\_S4U\_LOGON** pour obtenir un **jeton d'impersonation** pour tout autre utilisateur sans connaître les informations d'identification, **ajouter un groupe arbitraire** (administrateurs) au jeton, définir le **niveau d'intégrité** du jeton sur "**moyen**" et assigner ce jeton au **thread actuel** (SetThreadToken).

### SeBackupPrivilege

Le système est amené à **accorder un accès en lecture** à n'importe quel fichier (limité aux opérations de lecture) par ce privilège. Il est utilisé pour **lire les hachages de mots de passe des comptes Administrateur locaux** à partir du registre, après quoi, des outils comme "**psexec**" ou "**wmicexec**" peuvent être utilisés avec le hachage (technique Pass-the-Hash). Cependant, cette technique échoue dans deux cas : lorsque le compte Administrateur local est désactivé, ou lorsqu'une stratégie est en place qui supprime les droits administratifs des administrateurs locaux se connectant à distance.\
Vous pouvez **abuser de ce privilège** avec :

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* en suivant **IppSec** dans [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Ou comme expliqué dans la section **escalade de privilèges avec les opérateurs de sauvegarde** de :

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

La permission pour **accéder en écriture** à n'importe quel fichier système, indépendamment de la liste de contrôle d'accès (ACL) du fichier, est fournie par ce privilège. Cela ouvre de nombreuses possibilités d'escalade, y compris la capacité de **modifier des services**, d'effectuer du détournement de DLL et de définir des **débogueurs** via les options d'exécution de fichiers image, entre autres techniques.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege est une permission puissante, particulièrement utile lorsqu'un utilisateur possède la capacité d'impersonner des jetons, mais aussi en l'absence de SeImpersonatePrivilege. Cette capacité repose sur la capacité d'impersonner un jeton qui représente le même utilisateur et dont le niveau d'intégrité n'excède pas celui du processus actuel.

**Points clés :**
- **Impersonation sans SeImpersonatePrivilege :** Il est possible d'utiliser SeCreateTokenPrivilege pour l'EoP en impersonnant des jetons dans des conditions spécifiques.
- **Conditions pour l'impersonation de jetons :** L'impersonation réussie nécessite que le jeton cible appartienne au même utilisateur et ait un niveau d'intégrité inférieur ou égal à celui du processus tentant l'impersonation.
- **Création et modification de jetons d'impersonation :** Les utilisateurs peuvent créer un jeton d'impersonation et l'améliorer en ajoutant l'identifiant de sécurité (SID) d'un groupe privilégié.

### SeLoadDriverPrivilege

Ce privilège permet de **charger et décharger des pilotes de périphériques** avec la création d'une entrée de registre avec des valeurs spécifiques pour `ImagePath` et `Type`. Comme l'accès en écriture direct à `HKLM` (HKEY_LOCAL_MACHINE) est restreint, `HKCU` (HKEY_CURRENT_USER) doit être utilisé à la place. Cependant, pour rendre `HKCU` reconnaissable par le noyau pour la configuration du pilote, un chemin spécifique doit être suivi.

Ce chemin est `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, où `<RID>` est l'identifiant relatif de l'utilisateur actuel. À l'intérieur de `HKCU`, ce chemin complet doit être créé, et deux valeurs doivent être définies :
- `ImagePath`, qui est le chemin d'accès binaire à exécuter
- `Type`, avec une valeur de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Étapes à suivre :**
1. Accédez à `HKCU` au lieu de `HKLM` en raison de l'accès en écriture restreint.
2. Créez le chemin `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dans `HKCU`, où `<RID>` représente l identifiant relatif de l'utilisateur actuel.
3. Définissez le `ImagePath` sur le chemin d'exécution du binaire.
4. Attribuez le `Type` comme `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
D'autres façons d'abuser de ce privilège se trouvent sur [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ceci est similaire à **SeRestorePrivilege**. Sa fonction principale permet à un processus de **prendre possession d'un objet**, contournant ainsi l'exigence d'accès discrétionnaire explicite en fournissant des droits d'accès WRITE_OWNER. Le processus implique d'abord de sécuriser la propriété de la clé de registre prévue à des fins d'écriture, puis de modifier le DACL pour permettre des opérations d'écriture.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Ce privilège permet de **déboguer d'autres processus**, y compris de lire et écrire dans la mémoire. Diverses stratégies d'injection de mémoire, capables de contourner la plupart des antivirus et des solutions de prévention des intrusions hôtes, peuvent être utilisées avec ce privilège.

#### Dump de mémoire

Vous pourriez utiliser [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de la [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) pour **capturer la mémoire d'un processus**. Plus précisément, cela peut s'appliquer au processus **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, qui est responsable de stocker les informations d'identification de l'utilisateur une fois qu'un utilisateur s'est connecté avec succès à un système.

Vous pouvez ensuite charger ce dump dans mimikatz pour obtenir des mots de passe:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Si vous voulez obtenir un shell `NT SYSTEM`, vous pourriez utiliser :

- ****[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)****
- ****[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
- ****[**psgetsys.ps1 (Script Powershell)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Vérifier les privilèges
```
whoami /priv
```
Les **jetons qui apparaissent comme Désactivés** peuvent être activés, vous pouvez en fait abuser des jetons _Activés_ et _Désactivés_.

### Activer tous les jetons

Si vous avez des jetons désactivés, vous pouvez utiliser le script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) pour activer tous les jetons :
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ou le **script** intégré dans ce [**poste**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tableau

Feuille de triche complète sur les privilèges de jetons à [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), le résumé ci-dessous ne répertorie que les moyens directs d'exploiter le privilège pour obtenir une session administrateur ou lire des fichiers sensibles.

| Privilège                  | Impact      | Outil                    | Chemin d'exécution                                                                                                                                                                                                                                                                                                                                     | Remarques                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Outil tiers          | _"Cela permettrait à un utilisateur d'usurper des jetons et de s'élever en privilège vers le système nt en utilisant des outils tels que potato.exe, rottenpotato.exe et juicypotato.exe"_                                                                                                                                                                                                      | Merci à [Aurélien Chalot](https://twitter.com/Defte\_) pour la mise à jour. J'essaierai de reformuler cela bientôt de manière plus proche d'une recette.                                                                                                                                                                                        |
| **`SeBackup`**             | **Menace**  | _**Commandes intégrées**_ | Lire des fichiers sensibles avec `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Peut être plus intéressant si vous pouvez lire %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (et robocopy) n'est pas utile pour les fichiers ouverts.<br><br>- Robocopy nécessite à la fois SeBackup et SeRestore pour fonctionner avec le paramètre /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Outil tiers          | Créer un jeton arbitraire incluant des droits d'administrateur local avec `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliquer le jeton `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Script à trouver sur [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Outil tiers          | <p>1. Charger un pilote de noyau défectueux tel que <code>szkg64.sys</code><br>2. Exploiter la vulnérabilité du pilote<br><br>Alternativement, le privilège peut être utilisé pour décharger des pilotes liés à la sécurité avec la commande intégrée <code>ftlMC</code>. par exemple : <code>fltMC sysmondrv</code></p>                                                                           | <p>1. La vulnérabilité de <code>szkg64</code> est répertoriée sous <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Le code d'exploitation de <code>szkg64</code> a été créé par <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Lancer PowerShell/ISE avec le privilège SeRestore présent.<br>2. Activer le privilège avec <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renommer utilman.exe en utilman.old<br>4. Renommer cmd.exe en utilman.exe<br>5. Verrouiller la console et appuyer sur Win+U</p> | <p>L'attaque peut être détectée par certains logiciels antivirus.</p><p>Une méthode alternative repose sur le remplacement des binaires de service stockés dans "Program Files" en utilisant le même privilège</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Commandes intégrées**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renommer cmd.exe en utilman.exe<br>4. Verrouiller la console et appuyer sur Win+U</p>                                                                                                                                       | <p>L'attaque peut être détectée par certains logiciels antivirus.</p><p>Une méthode alternative repose sur le remplacement des binaires de service stockés dans "Program Files" en utilisant le même privilège.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Outil tiers          | <p>Manipuler les jetons pour inclure des droits d'administrateur local. Peut nécessiter SeImpersonate.</p><p>À vérifier.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Référence

* Consultez ce tableau définissant les jetons Windows : [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Consultez [**ce document**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) sur l'élévation de privilèges avec les jetons.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

# Abus des jetons

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez** le [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le **groupe Telegram** ou **suivez** moi sur **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Jetons

Si vous **ne savez pas ce que sont les jetons d'accès Windows**, lisez cette page avant de continuer :

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Peut-être pourriez-vous escalader les privilèges en abusant des jetons que vous avez déjà**

### SeImpersonatePrivilege (3.1.1)

Tout processus détenant ce privilège peut **usurper l'identité** (mais pas créer) de tout **jeton** pour lequel il peut obtenir une poignée. Vous pouvez obtenir un **jeton privilégié** à partir d'un **service Windows** (DCOM) en le faisant effectuer une **authentification NTLM** contre l'exploit, puis exécuter un processus en tant que **SYSTEM**. Exploitez-le avec [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM ](https://github.com/antonioCoco/RogueWinRM)(nécessite la désactivation de winrm), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) :

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege (3.1.2)

Il est très similaire à **SeImpersonatePrivilege**, il utilisera la **même méthode** pour obtenir un jeton privilégié.\
Ensuite, ce privilège permet de **assigner un jeton principal** à un processus nouveau/suspendu. Avec le jeton d'usurpation privilégié, vous pouvez dériver un jeton principal (DuplicateTokenEx).\
Avec le jeton, vous pouvez créer un **nouveau processus** avec 'CreateProcessAsUser' ou créer un processus suspendu et **définir le jeton** (en général, vous ne pouvez pas modifier le jeton principal d'un processus en cours d'exécution).

### SeTcbPrivilege (3.1.3)

Si vous avez activé ce jeton, vous pouvez utiliser **KERB\_S4U\_LOGON** pour obtenir un **jeton d'usurpation** pour tout autre utilisateur sans connaître les informations d'identification, **ajouter un groupe arbitraire** (administrateurs) au jeton, définir le **niveau d'intégrité** du jeton sur "**moyen**", et assigner ce jeton au **thread actuel** (SetThreadToken).

### SeBackupPrivilege (3.1.4)

Ce privilège fait en sorte que le système accorde **tous les droits de lecture** à tout fichier (lecture seule).\
Utilisez-le pour **lire les hachages de mots de passe des comptes Administrateur locaux** depuis le registre, puis utilisez "**psexec**" ou "**wmicexec**" avec le hachage (PTH).\
Cette attaque ne fonctionnera pas si l'Administrateur local est désactivé, ou s'il est configuré qu'un Admin local n'est pas administrateur s'il est connecté à distance.\
Vous pouvez **abuser de ce privilège** avec :

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* en suivant **IppSec** dans [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Ou comme expliqué dans la section **escalade de privilèges avec les opérateurs de sauvegarde** de :

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege (3.1.5)

Contrôle d'accès en **écriture** à tout fichier sur le système, indépendamment de la liste de contrôle d'accès des fichiers.\
Vous pouvez **modifier les services**, le détournement de DLL, définir un **débogueur** (Options d'exécution de fichiers d'image)... Beaucoup d'options pour l'escalade.

### SeCreateTokenPrivilege (3.1.6)

Ce jeton **peut être utilisé** comme méthode d'EoP **uniquement** si l'utilisateur **peut usurper** des jetons (même sans SeImpersonatePrivilege).\
Dans un scénario possible, un utilisateur peut usurper le jeton s'il est pour le même utilisateur et que le niveau d'intégrité est inférieur ou égal au niveau d'intégrité du processus actuel.\
Dans ce cas, l'utilisateur pourrait **créer un jeton d'usurpation** et y ajouter un SID de groupe privilégié.

### SeLoadDriverPrivilege (3.1.7)

**Charger et décharger des pilotes de périphériques.**\
Vous devez créer une entrée dans le registre avec des valeurs pour ImagePath et Type.\
Comme vous n'avez pas accès en écriture à HKLM, vous devez **utiliser HKCU**. Mais HKCU ne signifie rien pour le noyau, la manière de guider le noyau ici et d'utiliser le chemin attendu pour une configuration de pilote est d'utiliser le chemin : "\Registry\User\S-1-5-21-582075628-3447520101-2530640108-1003\System\CurrentControlSet\Services\DriverName" (l'ID est le **RID** de l'utilisateur actuel).\
Vous devez donc **créer tout ce chemin à l'intérieur de HKCU et définir l'ImagePath** (chemin vers le binaire qui va être exécuté) **et le Type** (SERVICE\_KERNEL\_DRIVER 0x00000001).

{% content-ref url="abuse-seloaddriverprivilege.md" %}
[abuse-seloaddriverprivilege.md](abuse-seloaddriverprivilege.md)
{% endcontent-ref %}

### SeTakeOwnershipPrivilege (3.1.8)

Ce privilège est très similaire à **SeRestorePrivilege**.\
Il permet à un processus de "**prendre possession d'un objet** sans se voir accorder un accès discrétionnaire" en accordant le droit d'accès WRITE\_OWNER.\
Tout d'abord, vous devez **prendre possession de la clé de registre** sur laquelle vous allez écrire et **modifier le DACL** pour pouvoir écrire dessus.
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
### SeDebugPrivilege (3.1.9)

Il permet au titulaire de **déboguer un autre processus**, ce qui inclut la lecture et **l'écriture** dans la **mémoire de ce processus**.\
Il existe de nombreuses stratégies de **injection de mémoire** qui peuvent être utilisées avec ce privilège pour contourner la plupart des solutions AV/HIPS.

#### Dump de mémoire

Un exemple d'**abus de ce privilège** est d'exécuter [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de [SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) pour **dumper la mémoire d'un processus**. Par exemple, le processus **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local\_Security\_Authority\_Subsystem\_Service)**)**, qui stocke les informations d'identification de l'utilisateur après sa connexion à un système.

Vous pouvez ensuite charger ce dump dans mimikatz pour obtenir des mots de passe:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Si vous voulez obtenir un shell `NT SYSTEM`, vous pourriez utiliser :

- ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
- ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
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

Vous pouvez utiliser le script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) pour activer tous les jetons :
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ou le **script** intégré dans ce [**poste**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tableau

Feuille de triche complète des privilèges de jeton sur [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), le résumé ci-dessous ne répertoriera que les moyens directs d'exploiter le privilège pour obtenir une session administrateur ou lire des fichiers sensibles.\\

| Privilège                  | Impact      | Outil                    | Chemin d'exécution                                                                                                                                                                                                                                                                                                                                     | Remarques                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Outil tiers          | _"Cela permettrait à un utilisateur d'usurper des jetons et de s'élever en tant que système nt en utilisant des outils tels que potato.exe, rottenpotato.exe et juicypotato.exe"_                                                                                                                                                                                                      | Merci à [Aurélien Chalot](https://twitter.com/Defte\_) pour la mise à jour. J'essaierai de reformuler cela bientôt de manière plus proche d'une recette.                                                                                                                                                                                        |
| **`SeBackup`**             | **Menace**  | _**Commandes intégrées**_ | Lire des fichiers sensibles avec `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Peut être plus intéressant si vous pouvez lire %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (et robocopy) n'est pas utile pour les fichiers ouverts.<br><br>- Robocopy nécessite à la fois SeBackup et SeRestore pour fonctionner avec le paramètre /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Outil tiers          | Créer un jeton arbitraire incluant des droits d'administrateur local avec `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliquer le jeton `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Script à trouver sur [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Outil tiers          | <p>1. Charger un pilote de noyau bogué tel que <code>szkg64.sys</code><br>2. Exploiter la vulnérabilité du pilote<br><br>Alternativement, le privilège peut être utilisé pour décharger des pilotes liés à la sécurité avec la commande intégrée <code>ftlMC</code>. par exemple : <code>fltMC sysmondrv</code></p>                                                                           | <p>1. La vulnérabilité de <code>szkg64</code> est répertoriée sous le nom de <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Le code d'exploitation de <code>szkg64</code> a été créé par <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Lancer PowerShell/ISE avec le privilège SeRestore présent.<br>2. Activer le privilège avec <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renommer utilman.exe en utilman.old<br>4. Renommer cmd.exe en utilman.exe<br>5. Verrouiller la console et appuyer sur Win+U</p> | <p>L'attaque peut être détectée par certains logiciels antivirus.</p><p>Une méthode alternative repose sur le remplacement des binaires de service stockés dans "Program Files" en utilisant le même privilège</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Commandes intégrées**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renommer cmd.exe en utilman.exe<br>4. Verrouiller la console et appuyer sur Win+U</p>                                                                                                                                       | <p>L'attaque peut être détectée par certains logiciels antivirus.</p><p>Une méthode alternative repose sur le remplacement des binaires de service stockés dans "Program Files" en utilisant le même privilège.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Outil tiers          | <p>Manipuler les jetons pour inclure des droits d'administrateur local. Peut nécessiter SeImpersonate.</p><p>À vérifier.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Référence

* Consultez ce tableau définissant les jetons Windows : [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Consultez [**ce document**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) sur l'élévation de privilèges avec les jetons.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

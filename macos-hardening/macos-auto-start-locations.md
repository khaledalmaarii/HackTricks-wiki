# Emplacements de démarrage automatique de macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Voici les emplacements sur le système qui pourraient conduire à l'**exécution** d'un binaire **sans** **interaction** **utilisateur**.

### Launchd

**`launchd`** est le **premier** **processus** exécuté par le noyau OX S au démarrage et le dernier à se terminer à l'arrêt. Il doit toujours avoir le **PID 1**. Ce processus **lira et exécutera** les configurations indiquées dans les **plists ASEP** dans :

* `/Library/LaunchAgents` : Agents par utilisateur installés par l'administrateur
* `/Library/LaunchDaemons` : Daemons système installés par l'administrateur
* `/System/Library/LaunchAgents` : Agents par utilisateur fournis par Apple.
* `/System/Library/LaunchDaemons` : Daemons système fournis par Apple.

Lorsqu'un utilisateur se connecte, les plists situés dans `/Users/$USER/Library/LaunchAgents` et `/Users/$USER/Library/LaunchDemons` sont démarrés avec les **permissions des utilisateurs connectés**.

La **principale différence entre les agents et les daemons est que les agents sont chargés lorsque l'utilisateur se connecte et les daemons sont chargés au démarrage du système** (car il y a des services comme ssh qui doivent être exécutés avant que tout utilisateur n'accède au système). Les agents peuvent également utiliser l'interface graphique tandis que les daemons doivent s'exécuter en arrière-plan.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/username/malware</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```
Il y a des cas où un **agent doit être exécuté avant que l'utilisateur ne se connecte**, ceux-ci sont appelés **PreLoginAgents**. Par exemple, cela est utile pour fournir une technologie d'assistance à la connexion. Ils peuvent également être trouvés dans `/Library/LaunchAgents` (voir [**ici**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un exemple).

\{% hint style="info" %\} Les nouveaux fichiers de configuration de Daemons ou Agents seront **chargés après le prochain redémarrage ou en utilisant** `launchctl load <target.plist>` Il est **également possible de charger des fichiers .plist sans cette extension** avec `launchctl -F <file>` (cependant, ces fichiers plist ne seront pas automatiquement chargés après le redémarrage).\
Il est également possible de **décharger** avec `launchctl unload <target.plist>` (le processus pointé par celui-ci sera terminé),

Pour **s'assurer** qu'il n'y a **rien** (comme une substitution) **empêchant** un **Agent** ou un **Daemon** **de** **s'exécuter**, exécutez : `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist` \{% endhint %\}

Listez tous les agents et démons chargés par l'utilisateur actuel :
```bash
launchctl list
```
### Cron

Listez les tâches cron de l'**utilisateur actuel** avec:
```bash
crontab -l
```
Vous pouvez également voir toutes les tâches cron des utilisateurs dans **`/usr/lib/cron/tabs/`** et **`/var/at/tabs/`** (nécessite des privilèges root).

Dans MacOS, plusieurs dossiers exécutant des scripts avec **une certaine fréquence** peuvent être trouvés dans:
```bash
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Vous pouvez trouver les tâches **cron** régulières, les tâches **at** (peu utilisées) et les tâches **périodiques** (principalement utilisées pour nettoyer les fichiers temporaires). Les tâches périodiques quotidiennes peuvent être exécutées par exemple avec: `periodic daily`.

Les scripts périodiques (**`/etc/periodic`**) sont exécutés en raison des **daemons de lancement** configurés dans `/System/Library/LaunchDaemons/com.apple.periodic*`. Notez que si un script est stocké dans `/etc/periodic/` comme moyen d'**escalader les privilèges**, il sera **exécuté** en tant que **propriétaire du fichier**.
```bash
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist
```
### kext

Afin d'installer un KEXT en tant qu'élément de démarrage, il doit être **installé dans l'un des emplacements suivants** :

* `/System/Library/Extensions`
  * Fichiers KEXT intégrés au système d'exploitation OS X.
* `/Library/Extensions`
  * Fichiers KEXT installés par des logiciels tiers.

Vous pouvez lister les fichiers kext actuellement chargés avec :
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Pour plus d'informations sur les [**extensions de noyau, consultez cette section**](macos-security-and-privilege-escalation/mac-os-architecture#i-o-kit-drivers).

### **Éléments de connexion**

Dans Préférences Système -> Utilisateurs et groupes -> **Éléments de connexion**, vous pouvez trouver les **éléments à exécuter lorsque l'utilisateur se connecte**.\
Il est possible de les lister, d'en ajouter et d'en supprimer depuis la ligne de commande :
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}' 

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"' 
```
Ces éléments sont stockés dans le fichier /Users/\<username>/Library/Application Support/com.apple.backgroundtaskmanagementagent

### At

Les "tâches At" sont utilisées pour **planifier des tâches à des moments spécifiques**.\
Ces tâches diffèrent de cron en ce qu'elles sont des tâches ponctuelles qui sont supprimées après leur exécution. Cependant, elles **survivent à un redémarrage du système** et ne peuvent donc pas être exclues en tant que menace potentielle.

Par **défaut**, elles sont **désactivées**, mais l'utilisateur **root** peut les **activer** avec:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Cela créera un fichier à 13h37 :
```bash
echo hello > /tmp/hello | at 1337
```
Si les tâches AT ne sont pas activées, les tâches créées ne seront pas exécutées.

### Hooks de connexion/déconnexion

Ils sont obsolètes mais peuvent être utilisés pour exécuter des commandes lorsqu'un utilisateur se connecte.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
```
Cette configuration est stockée dans `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
    LoginHook = "/Users/username/hook.sh";
    MiniBuddyLaunch = 0;
    TALLogoutReason = "Shut Down";
    TALLogoutSavesState = 0;
    oneTimeSSMigrationComplete = 1;
}
```
Pour le supprimer :
```bash
defaults delete com.apple.loginwindow LoginHook
```
Dans l'exemple précédent, nous avons créé et supprimé un **LoginHook**, il est également possible de créer un **LogoutHook**.

Celui de l'utilisateur root est stocké dans `/private/var/root/Library/Preferences/com.apple.loginwindow.plist`

### Emond

Apple a introduit un mécanisme de journalisation appelé **emond**. Il semble qu'il n'ait jamais été entièrement développé et que le développement ait été **abandonné** par Apple au profit d'autres mécanismes, mais il reste **disponible**.

Ce service peu connu peut **ne pas être très utile pour un administrateur Mac**, mais pour un acteur de menace, une très bonne raison serait de l'utiliser comme un mécanisme de **persistance que la plupart des administrateurs macOS ne connaissent probablement pas**. Détecter l'utilisation malveillante d'emond ne devrait pas être difficile, car le System LaunchDaemon du service ne recherche des scripts à exécuter qu'à un seul endroit :
```bash
ls -l /private/var/db/emondClients
```
{% hint style="danger" %}
**Comme cela n'est pas beaucoup utilisé, tout ce qui se trouve dans ce dossier doit être considéré comme suspect**
{% endhint %}

### Éléments de démarrage

\{% hint style="danger" %\} **Ceci est obsolète, donc rien ne devrait être trouvé dans les répertoires suivants.** \{% endhint %\}

Un **élément de démarrage** est un **répertoire** qui est **placé** dans l'un de ces deux dossiers : `/Library/StartupItems/` ou `/System/Library/StartupItems/`

Après avoir placé un nouveau répertoire dans l'un de ces deux emplacements, **deux autres éléments** doivent être placés à l'intérieur de ce répertoire. Ces deux éléments sont un **script rc** et un **plist** qui contient quelques paramètres. Ce plist doit être appelé "**StartupParameters.plist**". 
{% endtab %}
{% tab title="StartupParameters.plist" %\}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
        <string>This is a description of this service</string>
    <key>OrderPreference</key>
        <string>None</string> <!--Other req services to execute before this -->
    <key>Provides</key>
    <array>
        <string>superservicename</string> <!--Name of the services provided by this file -->
    </array>
</dict>
</plist>
```
{% endtab %}

{% tab title="superservicename" %}

## Emplacement de démarrage automatique de macOS

### Emplacements de démarrage automatique

Les emplacements de démarrage automatique de macOS sont les suivants:

* `/Library/LaunchAgents/`
* `/Library/LaunchDaemons/`
* `/System/Library/LaunchAgents/`
* `/System/Library/LaunchDaemons/`
* `~/Library/LaunchAgents/`

Les deux premiers emplacements sont utilisés pour les services système, tandis que les deux derniers sont utilisés pour les services utilisateur.

### Comment fonctionnent les emplacements de démarrage automatique

Les emplacements de démarrage automatique contiennent des fichiers de configuration de service qui indiquent à macOS comment démarrer et gérer les services. Les fichiers de configuration peuvent être écrits en XML ou en format binaire.

Les fichiers de configuration de service peuvent être utilisés pour démarrer des programmes, des scripts ou des commandes au démarrage de macOS ou lorsqu'un utilisateur se connecte.

### Comment trouver les emplacements de démarrage automatique

Pour trouver les emplacements de démarrage automatique, vous pouvez utiliser la commande `launchctl`. Par exemple, pour lister tous les services en cours d'exécution, vous pouvez utiliser la commande suivante:

```bash
sudo launchctl list
```

Pour lister tous les services dans un emplacement de démarrage automatique spécifique, vous pouvez utiliser la commande suivante:

```bash
sudo launchctl list <emplacement>
```

### Comment désactiver les services de démarrage automatique

Pour désactiver un service de démarrage automatique, vous pouvez utiliser la commande `launchctl`. Par exemple, pour désactiver le service `com.apple.AirPlayXPCHelper`, vous pouvez utiliser la commande suivante:

```bash
sudo launchctl unload -w /System/Library/LaunchAgents/com.apple.AirPlayXPCHelper.plist
```

### Comment ajouter un service de démarrage automatique

Pour ajouter un service de démarrage automatique, vous devez créer un fichier de configuration de service dans l'un des emplacements de démarrage automatique et y ajouter les informations de configuration appropriées. Par exemple, pour créer un service de démarrage automatique qui exécute un script Python au démarrage de macOS, vous pouvez créer un fichier `com.example.myservice.plist` dans le dossier `~/Library/LaunchAgents/` avec le contenu suivant:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.myservice</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python</string>
        <string>/path/to/myscript.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

Une fois que vous avez créé le fichier de configuration de service, vous pouvez charger le service en utilisant la commande `launchctl`. Par exemple, pour charger le service `com.example.myservice`, vous pouvez utiliser la commande suivante:

```bash
launchctl load ~/Library/LaunchAgents/com.example.myservice.plist
```

### Conclusion

Les emplacements de démarrage automatique de macOS sont un moyen pratique de démarrer des services au démarrage de macOS ou lorsqu'un utilisateur se connecte. En comprenant comment fonctionnent les emplacements de démarrage automatique et comment les utiliser, vous pouvez personnaliser le comportement de macOS pour répondre à vos besoins.
```bash
#!/bin/sh
. /etc/rc.common

StartService(){
    touch /tmp/superservicestarted
}

StopService(){
    rm /tmp/superservicestarted
}

RestartService(){
    echo "Restarting"
}

RunService "$1"
```
{% endtab %}
{% endtabs %}

### /etc/rc.common

{% hint style="danger" %}
**Cela ne fonctionne pas dans les versions modernes de MacOS**
{% endhint %}

Il est également possible de placer ici **des commandes qui seront exécutées au démarrage.** Exemple de script rc.common régulier :
```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
    local test

    if [ -z "${NETWORKUP:=}" ]; then
	test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
	if [ "${test}" -gt 0 ]; then
	    NETWORKUP="-YES-"
	else
	    NETWORKUP="-NO-"
	fi
    fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
    local program="$1"
    local pidfile="${PIDFILE:=/var/run/${program}.pid}"
    local     pid=""

    if [ -f "${pidfile}" ]; then
	pid=$(head -1 "${pidfile}")
	if ! kill -0 "${pid}" 2> /dev/null; then
	    echo "Bad pid file $pidfile; deleting."
	    pid=""
	    rm -f "${pidfile}"
	fi
    fi

    if [ -n "${pid}" ]; then
	echo "${pid}"
	return 0
    else
	return 1
    fi
}

#
# Generic action handler
#
RunService ()
{
    case $1 in
      start  ) StartService   ;;
      stop   ) StopService    ;;
      restart) RestartService ;;
      *      ) echo "$0: unknown argument: $1";;
    esac
}
```
### Profils

Les profils de configuration peuvent forcer un utilisateur à utiliser certains paramètres de navigateur, des paramètres de proxy DNS ou des paramètres VPN. De nombreux autres payloads sont possibles, ce qui les rend propices à l'abus.

Vous pouvez les énumérer en exécutant:
```bash
ls -Rl /Library/Managed\ Preferences/
```
### Autres techniques et outils de persistance

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

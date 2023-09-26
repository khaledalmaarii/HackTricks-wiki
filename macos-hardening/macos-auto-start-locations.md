# Localizações de Inicialização Automática no macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Aqui estão as localizações no sistema que podem levar à **execução** de um binário **sem** **interação** **do usuário**.

### Launchd

**`launchd`** é o **primeiro** **processo** executado pelo kernel do macOS no início e o último a ser encerrado no desligamento. Ele deve sempre ter o **PID 1**. Esse processo irá **ler e executar** as configurações indicadas nos **plists** do **ASEP** em:

* `/Library/LaunchAgents`: Agentes por usuário instalados pelo administrador
* `/Library/LaunchDaemons`: Daemons em todo o sistema instalados pelo administrador
* `/System/Library/LaunchAgents`: Agentes por usuário fornecidos pela Apple.
* `/System/Library/LaunchDaemons`: Daemons em todo o sistema fornecidos pela Apple.

Quando um usuário faz login, os plists localizados em `/Users/$USER/Library/LaunchAgents` e `/Users/$USER/Library/LaunchDemons` são iniciados com as **permissões dos usuários logados**.

A **principal diferença entre agentes e daemons é que os agentes são carregados quando o usuário faz login e os daemons são carregados no início do sistema** (pois existem serviços como ssh que precisam ser executados antes que qualquer usuário acesse o sistema). Além disso, os agentes podem usar a GUI, enquanto os daemons precisam ser executados em segundo plano.
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
Existem casos em que um **agente precisa ser executado antes do login do usuário**, esses são chamados de **PreLoginAgents**. Por exemplo, isso é útil para fornecer tecnologia assistiva no momento do login. Eles também podem ser encontrados em `/Library/LaunchAgents` (veja [**aqui**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) um exemplo).

\{% hint style="info" %\} Os novos arquivos de configuração de Daemons ou Agents serão **carregados após a próxima reinicialização ou usando** `launchctl load <target.plist>`. Também é possível carregar arquivos .plist sem essa extensão com `launchctl -F <file>` (no entanto, esses arquivos plist não serão carregados automaticamente após a reinicialização).\
Também é possível **descarregar** com `launchctl unload <target.plist>` (o processo apontado por ele será encerrado).

Para **garantir** que não haja **nada** (como uma substituição) **impedindo** que um **Agente** ou **Daemon** **seja executado**, execute: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist` \{% endhint %\}

Liste todos os agentes e daemons carregados pelo usuário atual:
```bash
launchctl list
```
### Cron

Liste os trabalhos cron do **usuário atual** com:
```bash
crontab -l
```
Você também pode ver todos os trabalhos cron dos usuários em **`/usr/lib/cron/tabs/`** e **`/var/at/tabs/`** (necessita de privilégios de root).

No MacOS, várias pastas que executam scripts com **determinada frequência** podem ser encontradas em:
```bash
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Aqui você pode encontrar os **cron jobs** regulares, os **at jobs** (pouco utilizados) e os **periodic jobs** (principalmente usados para limpar arquivos temporários). Os periodic scripts podem ser executados diariamente, por exemplo, com o comando: `periodic daily`.

Os scripts periódicos (**`/etc/periodic`**) são executados por causa dos **launch daemons** configurados em `/System/Library/LaunchDaemons/com.apple.periodic*`. Note que se um script estiver armazenado em `/etc/periodic/` como uma forma de **elevar privilégios**, ele será **executado** como o **proprietário do arquivo**.
```bash
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist
```
### kext

Para instalar um KEXT como um item de inicialização, ele precisa ser **instalado em um dos seguintes locais**:

* `/System/Library/Extensions`
* Arquivos KEXT incorporados ao sistema operacional OS X.
* `/Library/Extensions`
* Arquivos KEXT instalados por software de terceiros

Você pode listar os arquivos kext atualmente carregados com:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Para mais informações sobre [**extensões de kernel, verifique esta seção**](macos-security-and-privilege-escalation/mac-os-architecture#i-o-kit-drivers).

### **Itens de Login**

Em Preferências do Sistema -> Usuários e Grupos -> **Itens de Login**, você pode encontrar **itens a serem executados quando o usuário fizer login**.\
É possível listá-los, adicionar e remover a partir da linha de comando:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Esses itens são armazenados no arquivo /Users/\<username>/Library/Application Support/com.apple.backgroundtaskmanagementagent

### ZIP como Item de Login

Se você armazenar um arquivo **ZIP** como um **Item de Login**, o **`Archive Utility`** irá abri-lo e, se o zip estiver armazenado, por exemplo, em **`~/Library`** e contiver a pasta **`LaunchAgents/file.plist`** com uma backdoor, essa pasta será criada (não é por padrão) e o plist será adicionado para que na próxima vez que o usuário fizer login, a **backdoor indicada no plist será executada**.

Outra opção seria criar os arquivos **`.bash_profile`** e **`.zshenv`** dentro do diretório HOME do usuário, para que, se a pasta LaunchAgents já existir, essa técnica ainda funcione.

### At

"As tarefas 'at' são usadas para **agendar tarefas em horários específicos**. Essas tarefas diferem do cron no sentido de que **são tarefas únicas** que são removidas após a execução. No entanto, elas **sobrevivem a uma reinicialização do sistema**, então não podem ser descartadas como uma ameaça potencial.

Por **padrão**, elas estão **desabilitadas**, mas o usuário **root** pode **habilitá-las** com:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Isso criará um arquivo às 13:37:
```bash
echo hello > /tmp/hello | at 1337
```
Se as tarefas AT não estiverem habilitadas, as tarefas criadas não serão executadas.

### Hooks de Login/Logout

Eles estão obsoletos, mas podem ser usados para executar comandos quando um usuário faz login.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
```
Essa configuração é armazenada em `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Para deletar:
```bash
defaults delete com.apple.loginwindow LoginHook
```
No exemplo anterior, criamos e excluímos um **LoginHook**, também é possível criar um **LogoutHook**.

O usuário root é armazenado em `/private/var/root/Library/Preferences/com.apple.loginwindow.plist`

### Preferências de Aplicativos

Em **`~/Library/Preferences`** são armazenadas as preferências do usuário nos aplicativos. Algumas dessas preferências podem conter uma configuração para **executar outros aplicativos/scripts**.

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

### Emond

A Apple introduziu um mecanismo de registro chamado **emond**. Parece que nunca foi totalmente desenvolvido e o desenvolvimento pode ter sido **abandonado** pela Apple em favor de outros mecanismos, mas ainda está **disponível**.

Esse serviço pouco conhecido pode **não ser muito útil para um administrador de Mac**, mas para um ator de ameaça, uma boa razão seria usá-lo como um **mecanismo de persistência que a maioria dos administradores do macOS provavelmente não conheceria**. Detectar o uso malicioso do emond não deve ser difícil, pois o System LaunchDaemon para o serviço procura scripts para serem executados apenas em um único local:
```bash
ls -l /private/var/db/emondClients
```
{% hint style="danger" %}
**Como isso não é muito usado, qualquer coisa nessa pasta deve ser suspeita**
{% endhint %}

### Itens de inicialização

{% hint style="danger" %}
**Isso está obsoleto, portanto, nada deve ser encontrado nos seguintes diretórios.**
{% endhint %}

Um **StartupItem** é um **diretório** que é **colocado** em uma dessas duas pastas: `/Library/StartupItems/` ou `/System/Library/StartupItems/`

Após colocar um novo diretório em uma dessas duas localizações, **mais dois itens** precisam ser colocados dentro desse diretório. Esses dois itens são um **script rc** e um **plist** que contém algumas configurações. Este plist deve ser chamado de "**StartupParameters.plist**".

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

# Localizações de Inicialização Automática do macOS

O macOS possui várias localizações onde os aplicativos podem ser configurados para iniciar automaticamente quando o sistema é inicializado. Essas localizações são usadas por aplicativos legítimos para fornecer funcionalidades adicionais ou para iniciar serviços em segundo plano.

No entanto, essas localizações também podem ser exploradas por atacantes para iniciar aplicativos maliciosos ou scripts de inicialização que podem comprometer a segurança do sistema.

Aqui estão algumas das principais localizações de inicialização automática do macOS:

## 1. LaunchAgents

Os LaunchAgents são arquivos de propriedade do usuário que são executados quando um usuário faz login. Eles são armazenados no diretório `~/Library/LaunchAgents` e têm a extensão `.plist`. Esses arquivos podem ser usados para iniciar aplicativos ou scripts de inicialização quando um usuário faz login.

## 2. LaunchDaemons

Os LaunchDaemons são arquivos de propriedade do sistema que são executados quando o sistema é inicializado. Eles são armazenados no diretório `/Library/LaunchDaemons` e têm a extensão `.plist`. Esses arquivos são usados para iniciar serviços em segundo plano que são executados independentemente de qualquer usuário fazer login.

## 3. Login Items

Os Login Items são aplicativos ou scripts que são configurados para iniciar automaticamente quando um usuário faz login. Eles são gerenciados nas preferências do sistema, na seção "Usuários e Grupos". Os Login Items podem ser usados para iniciar aplicativos ou scripts específicos para um usuário quando ele faz login.

## 4. Startup Items

Os Startup Items são aplicativos ou scripts que são configurados para iniciar automaticamente quando o sistema é inicializado. Eles são armazenados no diretório `/Library/StartupItems` e são executados antes que qualquer usuário faça login. No entanto, essa localização não é mais suportada nas versões mais recentes do macOS.

## 5. Cron Jobs

Os Cron Jobs são tarefas agendadas que são executadas em intervalos regulares. Eles são configurados usando o utilitário `cron` e podem ser usados para iniciar aplicativos ou scripts em horários específicos. Os Cron Jobs são armazenados no arquivo `/etc/crontab` e nos arquivos no diretório `/usr/lib/cron/tabs`.

## 6. LaunchAgents e LaunchDaemons de Terceiros

Além das localizações mencionadas acima, os aplicativos de terceiros também podem instalar seus próprios LaunchAgents e LaunchDaemons. Esses arquivos podem ser armazenados em diferentes diretórios, dependendo do aplicativo.

## Verificando e Removendo Inicializações Automáticas Indesejadas

Para verificar e remover inicializações automáticas indesejadas, você pode usar as seguintes abordagens:

- Verifique os arquivos nas localizações mencionadas acima e remova qualquer arquivo suspeito ou indesejado.
- Use utilitários de terceiros, como o `launchctl`, para listar e gerenciar os LaunchAgents e LaunchDaemons.
- Verifique as preferências do sistema para Login Items e remova qualquer aplicativo ou script indesejado.
- Verifique os Cron Jobs usando o utilitário `crontab` e remova qualquer tarefa indesejada.
- Use ferramentas de segurança, como antivírus ou ferramentas de detecção de malware, para verificar e remover qualquer aplicativo malicioso.

Ao verificar e remover inicializações automáticas indesejadas, é importante ter cuidado para não remover arquivos ou configurações legítimas que são necessários para o funcionamento adequado do sistema ou de aplicativos confiáveis.

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

### /etc/rc.common

{% hint style="danger" %}
**Isso não funciona nas versões modernas do MacOS**
{% endhint %}

Também é possível colocar aqui **comandos que serão executados na inicialização.** Exemplo de um script rc.common regular:
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
### Perfis

Os perfis de configuração podem forçar um usuário a usar determinadas configurações do navegador, configurações de proxy DNS ou configurações de VPN. Muitos outros payloads são possíveis, o que os torna propensos a abusos.

Você pode enumerá-los executando:
```bash
ls -Rl /Library/Managed\ Preferences/
```
### Outras técnicas e ferramentas de persistência

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

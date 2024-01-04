# Proteções de Segurança do macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Gatekeeper

Gatekeeper é geralmente usado para se referir à combinação de **Quarantine + Gatekeeper + XProtect**, 3 módulos de segurança do macOS que tentam **impedir que os usuários executem softwares potencialmente maliciosos baixados**.

Mais informações em:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Limitações de Processos

### SIP - Proteção de Integridade do Sistema

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

O Sandbox do MacOS **limita aplicações** que estão rodando dentro do sandbox às **ações permitidas especificadas no perfil do Sandbox** com o qual o app está executando. Isso ajuda a garantir que **a aplicação acessará apenas os recursos esperados**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparência, Consentimento e Controle**

**TCC (Transparência, Consentimento e Controle)** é um mecanismo no macOS para **limitar e controlar o acesso de aplicações a certas funcionalidades**, geralmente sob uma perspectiva de privacidade. Isso pode incluir coisas como serviços de localização, contatos, fotos, microfone, câmera, acessibilidade, acesso total ao disco e muito mais.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Restrições de Lançamento/Ambiente & Trust Cache

Restrições de lançamento no macOS são um recurso de segurança para **regular a iniciação de processos** definindo **quem pode lançar** um processo, **como** e **de onde**. Introduzidas no macOS Ventura, elas categorizam binários do sistema em categorias de restrições dentro de um **trust cache**. Cada binário executável tem **regras** definidas para seu **lançamento**, incluindo restrições de **si mesmo**, **pai** e **responsável**. Estendido para aplicativos de terceiros como Restrições de **Ambiente** no macOS Sonoma, esses recursos ajudam a mitigar possíveis explorações do sistema ao governar as condições de lançamento de processos.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Ferramenta de Remoção de Malware

A Ferramenta de Remoção de Malware (MRT) é outra parte da infraestrutura de segurança do macOS. Como o nome sugere, a principal função do MRT é **remover malware conhecido de sistemas infectados**.

Uma vez que o malware é detectado em um Mac (seja pelo XProtect ou por outros meios), o MRT pode ser usado para **remover automaticamente o malware**. O MRT opera silenciosamente em segundo plano e normalmente é executado sempre que o sistema é atualizado ou quando uma nova definição de malware é baixada (parece que as regras que o MRT tem para detectar malware estão dentro do binário).

Enquanto o XProtect e o MRT fazem parte das medidas de segurança do macOS, eles desempenham funções diferentes:

* **XProtect** é uma ferramenta preventiva. Ele **verifica arquivos à medida que são baixados** (através de certas aplicações), e se detectar algum tipo conhecido de malware, ele **impede a abertura do arquivo**, evitando assim que o malware infecte seu sistema em primeiro lugar.
* **MRT**, por outro lado, é uma **ferramenta reativa**. Ele opera após o malware ter sido detectado em um sistema, com o objetivo de remover o software ofensivo para limpar o sistema.

O aplicativo MRT está localizado em **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gerenciamento de Tarefas em Segundo Plano

**macOS** agora **alerta** toda vez que uma ferramenta usa uma técnica bem conhecida para **persistir na execução de código** (como Itens de Login, Daemons...), para que o usuário saiba melhor **qual software está persistindo**.

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

Isso funciona com um **daemon** localizado em `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` e o **agente** em `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

A maneira como **`backgroundtaskmanagementd`** sabe que algo está instalado em uma pasta persistente é **obtendo os FSEvents** e criando alguns **manipuladores** para esses.

Além disso, existe um arquivo plist que contém **aplicações bem conhecidas** que frequentemente persistem mantidas pela Apple localizado em: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeração

É possível **enumerar todos** os itens de fundo configurados executando a ferramenta de linha de comando da Apple:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Além disso, também é possível listar essas informações com [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
### Mexendo com o BTM

Quando uma nova persistência é encontrada, um evento do tipo **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** é gerado. Portanto, qualquer maneira de **prevenir** que esse **evento** seja enviado ou o **agente de alertar** o usuário ajudará um atacante a _**burlar**_ o BTM.

* **Redefinindo o banco de dados**: Executar o seguinte comando redefinirá o banco de dados (deverá reconstruí-lo do zero), no entanto, por algum motivo, após executar isso, **nenhuma nova persistência será alertada até que o sistema seja reiniciado**.
* **root** é necessário.
```bash
# Reset the database
sfltool resettbtm
```
* **Interromper o Agente**: É possível enviar um sinal de parada para o agente para que ele **não alerte o usuário** quando novas detecções forem encontradas.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Bug**: Se o **processo que criou a persistência existir rapidamente logo após**, o daemon tentará **obter informações** sobre ele, **falhará** e **não conseguirá enviar o evento** indicando que uma nova coisa está persistindo.

Referências e **mais informações sobre BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

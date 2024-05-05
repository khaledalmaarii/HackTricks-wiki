# Proteções de Segurança do macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

- Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
- Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Gatekeeper

Gatekeeper é geralmente usado para se referir à combinação de **Quarantine + Gatekeeper + XProtect**, 3 módulos de segurança do macOS que tentarão **impedir que os usuários executem software potencialmente malicioso baixado**.

Mais informações em:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Limitantes de Processos

### SIP - Proteção de Integridade do Sistema

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

O Sandbox do macOS **limita as aplicações** em execução dentro do sandbox às **ações permitidas especificadas no perfil do Sandbox** com o qual o aplicativo está sendo executado. Isso ajuda a garantir que **o aplicativo acesse apenas os recursos esperados**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparência, Consentimento e Controle**

**TCC (Transparência, Consentimento e Controle)** é um framework de segurança. Ele é projetado para **gerenciar as permissões** de aplicativos, especificamente regulando seu acesso a recursos sensíveis. Isso inclui elementos como **serviços de localização, contatos, fotos, microfone, câmera, acessibilidade e acesso total ao disco**. O TCC garante que os aplicativos só possam acessar esses recursos após obter o consentimento explícito do usuário, fortalecendo assim a privacidade e o controle sobre os dados pessoais.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Restrições de Inicialização/Ambiente e Cache de Confiança

As restrições de inicialização no macOS são um recurso de segurança para **regular a inicialização de processos** definindo **quem pode iniciar** um processo, **como** e **de onde**. Introduzidas no macOS Ventura, elas categorizam binários do sistema em categorias de restrição dentro de um **cache de confiança**. Cada binário executável tem **regras** definidas para sua **inicialização**, incluindo restrições **próprias**, do **pai** e **responsáveis**. Estendidas para aplicativos de terceiros como Restrições de **Ambiente** no macOS Sonoma, esses recursos ajudam a mitigar possíveis explorações do sistema ao governar as condições de inicialização do processo.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Ferramenta de Remoção de Malware

A Ferramenta de Remoção de Malware (MRT) é outra parte da infraestrutura de segurança do macOS. Como o nome sugere, a função principal do MRT é **remover malware conhecido de sistemas infectados**.

Uma vez que o malware é detectado em um Mac (seja pelo XProtect ou por outros meios), o MRT pode ser usado para **remover automaticamente o malware**. O MRT opera silenciosamente em segundo plano e geralmente é executado sempre que o sistema é atualizado ou quando uma nova definição de malware é baixada (parece que as regras que o MRT tem para detectar malware estão dentro do binário).

Enquanto tanto o XProtect quanto o MRT fazem parte das medidas de segurança do macOS, eles desempenham funções diferentes:

- **XProtect** é uma ferramenta preventiva. Ele **verifica arquivos conforme são baixados** (por meio de certos aplicativos) e, se detectar algum tipo conhecido de malware, **impede que o arquivo seja aberto**, evitando assim que o malware infecte seu sistema em primeiro lugar.
- **MRT**, por outro lado, é uma **ferramenta reativa**. Ele opera depois que o malware foi detectado em um sistema, com o objetivo de remover o software ofensivo para limpar o sistema.

O aplicativo MRT está localizado em **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gerenciamento de Tarefas em Segundo Plano

**macOS** agora **alerta** sempre que uma ferramenta usa uma **técnica conhecida para persistir a execução de código** (como Itens de Login, Daemons...), para que o usuário saiba melhor **qual software está persistindo**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Isso é executado com um **daemon** localizado em `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` e o **agente** em `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

A maneira como o **`backgroundtaskmanagementd`** sabe que algo está instalado em uma pasta persistente é **obtendo os FSEvents** e criando alguns **manipuladores** para eles.

Além disso, há um arquivo plist que contém **aplicativos conhecidos** que frequentemente persistem mantidos pela Apple localizados em: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

É possível **enumerar todos** os itens de plano de fundo configurados em execução usando a ferramenta de linha de comando da Apple:
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
Esta informação está armazenada em **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** e o Terminal precisa de FDA.

### Mexendo com o BTM

Quando uma nova persistência é encontrada, um evento do tipo **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Portanto, qualquer maneira de **prevenir** que este **evento** seja enviado ou o **agente de alerta** o usuário ajudará um atacante a _**burlar**_ o BTM.

* **Redefinindo o banco de dados**: Executar o seguinte comando irá redefinir o banco de dados (deve reconstruí-lo do zero), no entanto, por alguma razão, após executar isso, **nenhuma nova persistência será alertada até que o sistema seja reiniciado**.
* **root** é necessário.
```bash
# Reset the database
sfltool resettbtm
```
* **Parar o Agente**: É possível enviar um sinal de parada para o agente para que ele **não alerte o usuário** quando novas detecções são encontradas.
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
* **Bug**: Se o **processo que criou a persistência existir rapidamente logo após isso**, o daemon tentará **obter informações** sobre ele, **falhará** e **não conseguirá enviar o evento** indicando que algo novo está persistindo.

Referências e **mais informações sobre BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

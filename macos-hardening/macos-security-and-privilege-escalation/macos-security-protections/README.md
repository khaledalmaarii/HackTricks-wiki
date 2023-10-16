# Proteções de Segurança do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Gatekeeper

Gatekeeper é geralmente usado para se referir à combinação de **Quarantine + Gatekeeper + XProtect**, 3 módulos de segurança do macOS que tentarão **impedir que os usuários executem software potencialmente malicioso baixado**.

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

O Sandbox do macOS **limita as aplicações** em execução dentro do sandbox às **ações permitidas especificadas no perfil do Sandbox** com o qual o aplicativo está sendo executado. Isso ajuda a garantir que **o aplicativo acesse apenas os recursos esperados**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparência, Consentimento e Controle**

**TCC (Transparência, Consentimento e Controle)** é um mecanismo no macOS para **limitar e controlar o acesso do aplicativo a determinados recursos**, geralmente do ponto de vista da privacidade. Isso pode incluir coisas como serviços de localização, contatos, fotos, microfone, câmera, acessibilidade, acesso total ao disco e muito mais.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Restrições de Inicialização

As restrições de inicialização no macOS são um recurso de segurança para **regular a inicialização de processos**, definindo **quem pode iniciar** um processo, **como** e **de onde**. Introduzidas no macOS Ventura, elas categorizam os binários do sistema em categorias de restrição dentro de um **cache de confiança**. Cada binário executável tem **regras** definidas para sua **inicialização**, incluindo restrições **próprias**, **dos pais** e **responsáveis**. Estendidas para aplicativos de terceiros como Restrições de **Ambiente** no macOS Sonoma, esses recursos ajudam a mitigar possíveis explorações do sistema, governando as condições de inicialização do processo.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Ferramenta de Remoção de Malware

A Ferramenta de Remoção de Malware (MRT) é outra parte da infraestrutura de segurança do macOS. Como o nome sugere, a função principal do MRT é **remover malware conhecido de sistemas infectados**.

Uma vez que o malware é detectado em um Mac (seja pelo XProtect ou por outros meios), o MRT pode ser usado para **remover automaticamente o malware**. O MRT opera silenciosamente em segundo plano e geralmente é executado sempre que o sistema é atualizado ou quando uma nova definição de malware é baixada (parece que as regras que o MRT tem para detectar malware estão dentro do binário).

Embora tanto o XProtect quanto o MRT façam parte das medidas de segurança do macOS, eles desempenham funções diferentes:

* **XProtect** é uma ferramenta preventiva. Ele **verifica arquivos conforme são baixados** (por meio de determinados aplicativos) e, se detectar algum tipo conhecido de malware, **impede a abertura do arquivo**, evitando assim que o malware infecte o sistema em primeiro lugar.
* **MRT**, por outro lado, é uma ferramenta **reativa**. Ele opera depois que o malware foi detectado em um sistema, com o objetivo de remover o software ofensivo para limpar o sistema.

O aplicativo MRT está localizado em **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gerenciamento de Tarefas em Segundo Plano

O **macOS** agora **alerta** sempre que uma ferramenta usa uma **técnica conhecida para persistir a execução de código** (como Itens de Login, Daemons...), para que o usuário saiba melhor **qual software está persistindo**.

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

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

É possível **enumerar todos** os itens de plano de fundo configurados em execução na ferramenta de linha de comando da Apple:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Além disso, também é possível listar essas informações com o [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Essas informações estão sendo armazenadas em **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** e o Terminal precisa de FDA.

### Mexendo com o BTM

Quando uma nova persistência é encontrada, ocorre um evento do tipo **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Portanto, qualquer maneira de **prevenir** que esse **evento** seja enviado ou que o **agente alerte** o usuário ajudará um invasor a _**burlar**_ o BTM.

* **Redefinindo o banco de dados**: Executar o seguinte comando irá redefinir o banco de dados (deve reconstruí-lo do zero), no entanto, por algum motivo, após executar isso, **nenhuma nova persistência será alertada até que o sistema seja reiniciado**.
* É necessário ter **root**.
```bash
# Reset the database
sfltool resettbtm
```
* **Parar o Agente**: É possível enviar um sinal de parada para o agente, para que ele **não alerte o usuário** quando novas detecções forem encontradas.
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
* **Bug**: Se o **processo que criou a persistência** existir rapidamente logo após, o daemon tentará **obter informações** sobre ele, **falhará** e **não conseguirá enviar o evento** indicando que algo novo está persistindo.

Referências e **mais informações sobre BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo Telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

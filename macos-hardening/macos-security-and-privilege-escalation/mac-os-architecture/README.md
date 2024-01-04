# Kernel & Extensões de Sistema do macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kernel XNU

O **núcleo do macOS é o XNU**, que significa "X is Not Unix". Este kernel é composto fundamentalmente pelo **microkernel Mach** (que será discutido mais tarde), **e** elementos do Berkeley Software Distribution (**BSD**). O XNU também fornece uma plataforma para **drivers de kernel através de um sistema chamado I/O Kit**. O kernel XNU faz parte do projeto de código aberto Darwin, o que significa que **seu código-fonte é acessível gratuitamente**.

Do ponto de vista de um pesquisador de segurança ou desenvolvedor Unix, o **macOS** pode parecer bastante **semelhante** a um sistema **FreeBSD** com uma GUI elegante e um conjunto de aplicativos personalizados. A maioria dos aplicativos desenvolvidos para BSD compilará e funcionará no macOS sem necessidade de modificações, pois as ferramentas de linha de comando familiares aos usuários Unix estão todas presentes no macOS. No entanto, como o kernel XNU incorpora o Mach, existem algumas diferenças significativas entre um sistema tradicional semelhante ao Unix e o macOS, e essas diferenças podem causar problemas potenciais ou fornecer vantagens únicas.

Versão de código aberto do XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach é um **microkernel** projetado para ser **compatível com UNIX**. Um de seus princípios de design chave era **minimizar** a quantidade de **código** executado no espaço do **kernel** e, em vez disso, permitir que muitas funções típicas do kernel, como sistema de arquivos, rede e I/O, **executassem como tarefas no nível do usuário**.

No XNU, o Mach é **responsável por muitas das operações de baixo nível críticas** que um kernel normalmente lida, como agendamento de processador, multitarefa e gerenciamento de memória virtual.

### BSD

O **kernel XNU** também **incorpora** uma quantidade significativa de código derivado do projeto **FreeBSD**. Este código **executa como parte do kernel junto com o Mach**, no mesmo espaço de endereçamento. No entanto, o código do FreeBSD dentro do XNU pode diferir substancialmente do código original do FreeBSD porque foram necessárias modificações para garantir sua compatibilidade com o Mach. O FreeBSD contribui para muitas operações do kernel, incluindo:

* Gerenciamento de processos
* Manipulação de sinais
* Mecanismos de segurança básicos, incluindo gerenciamento de usuários e grupos
* Infraestrutura de chamadas de sistema
* Pilha TCP/IP e soquetes
* Firewall e filtragem de pacotes

Entender a interação entre BSD e Mach pode ser complexo, devido aos seus diferentes quadros conceituais. Por exemplo, o BSD usa processos como sua unidade de execução fundamental, enquanto o Mach opera com base em threads. Essa discrepância é reconciliada no XNU **associando cada processo BSD a uma tarefa Mach** que contém exatamente uma thread Mach. Quando a chamada de sistema fork() do BSD é usada, o código BSD dentro do kernel usa funções Mach para criar uma tarefa e uma estrutura de thread.

Além disso, **Mach e BSD mantêm modelos de segurança diferentes**: o modelo de segurança do **Mach** é baseado em **direitos de porta**, enquanto o modelo de segurança do BSD opera com base na **propriedade do processo**. Disparidades entre esses dois modelos ocasionalmente resultaram em vulnerabilidades de escalonamento de privilégios locais. Além das chamadas de sistema típicas, também existem **armadilhas Mach que permitem que programas no espaço do usuário interajam com o kernel**. Esses diferentes elementos juntos formam a arquitetura híbrida e multifacetada do kernel do macOS.

### I/O Kit - Drivers

I/O Kit é o framework de **drivers de dispositivos**, orientado a objetos e de código aberto, no kernel XNU e é responsável pela adição e gerenciamento de **drivers de dispositivos carregados dinamicamente**. Esses drivers permitem que código modular seja adicionado dinamicamente ao kernel para uso com diferentes hardwares, por exemplo.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Comunicação Interprocessos

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

O **kernelcache** é uma **versão pré-compilada e pré-linkada do kernel XNU**, juntamente com **drivers** essenciais e **extensões de kernel**. Ele é armazenado em um formato **comprimido** e é descomprimido na memória durante o processo de inicialização. O kernelcache facilita um **tempo de inicialização mais rápido** ao ter uma versão pronta para execução do kernel e drivers cruciais disponíveis, reduzindo o tempo e os recursos que de outra forma seriam gastos carregando e vinculando dinamicamente esses componentes no momento da inicialização.

No iOS, está localizado em **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** no macOS você pode encontrá-lo com **`find / -name kernelcache 2>/dev/null`**

#### IMG4

O formato de arquivo IMG4 é um formato de contêiner usado pela Apple em seus dispositivos iOS e macOS para armazenar e verificar de forma segura componentes de firmware (como **kernelcache**). O formato IMG4 inclui um cabeçalho e várias tags que encapsulam diferentes pedaços de dados, incluindo o payload real (como um kernel ou bootloader), uma assinatura e um conjunto de propriedades do manifesto. O formato suporta verificação criptográfica, permitindo que o dispositivo confirme a autenticidade e integridade do componente de firmware antes de executá-lo.

Geralmente é composto pelos seguintes componentes:

* **Payload (IM4P)**:
* Frequentemente comprimido (LZFSE4, LZSS, …)
* Opcionalmente criptografado
* **Manifesto (IM4M)**:
* Contém Assinatura
* Dicionário adicional de Chave/Valor
* **Informações de Restauração (IM4R)**:
* Também conhecido como APNonce
* Impede a repetição de algumas atualizações
* OPCIONAL: Geralmente isso não é encontrado

Descomprimir o Kernelcache:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Símbolos do Kernelcache

Às vezes, a Apple lança **kernelcache** com **símbolos**. Você pode baixar alguns firmwares com símbolos seguindo os links em [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

Estes são os **firmwares** da Apple que você pode baixar de [**https://ipsw.me/**](https://ipsw.me/). Entre outros arquivos, ele conterá o **kernelcache**.\
Para **extrair** os arquivos, você pode simplesmente **descompactar**.

Após extrair o firmware, você obterá um arquivo como: **`kernelcache.release.iphone14`**. Está no formato **IMG4**, você pode extrair as informações relevantes com:

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
Você pode verificar o kernelcache extraído para símbolos com: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Com isso, podemos agora **extrair todas as extensões** ou **a que você está interessado:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Extensões do Kernel do macOS

O macOS é **extremamente restritivo para carregar Extensões do Kernel** (.kext) devido aos altos privilégios com os quais o código será executado. Na verdade, por padrão é praticamente impossível (a menos que seja encontrado um bypass).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Extensões do Sistema macOS

Em vez de usar Extensões do Kernel, o macOS criou as Extensões do Sistema, que oferecem APIs em nível de usuário para interagir com o kernel. Desta forma, os desenvolvedores podem evitar o uso de extensões do kernel.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Referências

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

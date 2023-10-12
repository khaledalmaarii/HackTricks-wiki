# Kernel e Extensões do Sistema macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kernel XNU

O **núcleo do macOS é o XNU**, que significa "X is Not Unix" (X não é Unix). Este kernel é fundamentalmente composto pelo **microkernel Mach** (a ser discutido posteriormente) e **elementos do Berkeley Software Distribution (BSD)**. O XNU também fornece uma plataforma para **drivers de kernel por meio de um sistema chamado I/O Kit**. O kernel XNU faz parte do projeto de código aberto Darwin, o que significa que **seu código-fonte é livremente acessível**.

Do ponto de vista de um pesquisador de segurança ou de um desenvolvedor Unix, o macOS pode parecer bastante **similar** a um sistema **FreeBSD** com uma GUI elegante e uma série de aplicativos personalizados. A maioria dos aplicativos desenvolvidos para o BSD irá compilar e executar no macOS sem precisar de modificações, pois as ferramentas de linha de comando familiares aos usuários do Unix estão todas presentes no macOS. No entanto, devido ao fato de o kernel XNU incorporar o Mach, existem algumas diferenças significativas entre um sistema semelhante ao Unix tradicional e o macOS, e essas diferenças podem causar problemas potenciais ou fornecer vantagens únicas.

Versão de código aberto do XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

O Mach é um **microkernel** projetado para ser **compatível com o UNIX**. Um de seus princípios de design chave foi **minimizar** a quantidade de **código** em execução no **espaço do kernel** e, em vez disso, permitir que muitas funções típicas do kernel, como sistema de arquivos, rede e E/S, sejam executadas como tarefas de nível de usuário.

No XNU, o Mach é **responsável por muitas das operações críticas de baixo nível** que um kernel normalmente manipula, como escalonamento de processador, multitarefa e gerenciamento de memória virtual.

### BSD

O kernel XNU também **incorpora** uma quantidade significativa de código derivado do projeto **FreeBSD**. Esse código **é executado como parte do kernel junto com o Mach**, no mesmo espaço de endereço. No entanto, o código do FreeBSD dentro do XNU pode diferir substancialmente do código original do FreeBSD, pois foram necessárias modificações para garantir sua compatibilidade com o Mach. O FreeBSD contribui para muitas operações do kernel, incluindo:

* Gerenciamento de processos
* Manipulação de sinais
* Mecanismos básicos de segurança, incluindo gerenciamento de usuário e grupo
* Infraestrutura de chamada de sistema
* Pilha TCP/IP e sockets
* Firewall e filtragem de pacotes

Compreender a interação entre o BSD e o Mach pode ser complexo, devido aos seus diferentes frameworks conceituais. Por exemplo, o BSD usa processos como sua unidade fundamental de execução, enquanto o Mach opera com base em threads. Essa discrepância é conciliada no XNU **associando cada processo BSD a uma tarefa Mach** que contém exatamente uma thread Mach. Quando a chamada de sistema fork() do BSD é usada, o código do BSD dentro do kernel usa funções do Mach para criar uma tarefa e uma estrutura de thread.

Além disso, **o Mach e o BSD mantêm modelos de segurança diferentes**: o modelo de segurança do Mach é baseado em **direitos de porta**, enquanto o modelo de segurança do BSD opera com base na **propriedade do processo**. Disparidades entre esses dois modelos ocasionalmente resultaram em vulnerabilidades de escalonamento de privilégios locais. Além das chamadas de sistema típicas, também existem **armadilhas do Mach que permitem que programas de espaço de usuário interajam com o kernel**. Esses diferentes elementos juntos formam a arquitetura multifacetada e híbrida do kernel macOS.

### I/O Kit - Drivers

O I/O Kit é o framework de **drivers de dispositivo orientado a objetos** de código aberto no kernel XNU e é responsável pela adição e gerenciamento de **drivers de dispositivo carregados dinamicamente**. Esses drivers permitem que código modular seja adicionado ao kernel dinamicamente para uso com diferentes hardwares, por exemplo.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Comunicação Interprocesso

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

O **kernelcache** é uma versão **pré-compilada e pré-linkada do kernel XNU**, juntamente com drivers de dispositivo essenciais e extensões do kernel. Ele é armazenado em um formato **compactado** e é descompactado na memória durante o processo de inicialização. O kernelcache facilita um **tempo de inicialização mais rápido** ao ter uma versão pronta para ser executada do kernel e drivers essenciais disponíveis, reduzindo o tempo e os recursos que seriam gastos no carregamento e vinculação dinâmica desses componentes durante a inicialização.

No iOS, ele está localizado em **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**. No macOS, você pode encontrá-lo com o comando **`find / -name kernelcache 2>/dev/null`**.
#### IMG4

O formato de arquivo IMG4 é um formato de contêiner usado pela Apple em seus dispositivos iOS e macOS para armazenar e verificar com segurança componentes de firmware (como o kernelcache). O formato IMG4 inclui um cabeçalho e várias tags que encapsulam diferentes partes de dados, incluindo a carga útil real (como um kernel ou bootloader), uma assinatura e um conjunto de propriedades de manifesto. O formato suporta verificação criptográfica, permitindo que o dispositivo confirme a autenticidade e integridade do componente de firmware antes de executá-lo.

Geralmente é composto pelos seguintes componentes:

* **Carga útil (IM4P)**:
* Frequentemente compactado (LZFSE4, LZSS, ...)
* Opcionalmente criptografado
* **Manifesto (IM4M)**:
* Contém assinatura
* Dicionário adicional de chave/valor
* **Informações de restauração (IM4R)**:
* Também conhecido como APNonce
* Impede a reprodução de algumas atualizações
* OPCIONAL: Geralmente isso não é encontrado

Descompacte o Kernelcache:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Símbolos do Kernelcache

Às vezes, a Apple lança **kernelcache** com **símbolos**. Você pode baixar alguns firmwares com símbolos seguindo os links em [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

Esses são os **firmwares** da Apple que você pode baixar em [**https://ipsw.me/**](https://ipsw.me/). Entre outros arquivos, ele conterá o **kernelcache**.\
Para **extrair** os arquivos, você pode simplesmente **descompactá-lo**.

Após extrair o firmware, você obterá um arquivo como: **`kernelcache.release.iphone14`**. Está no formato **IMG4**, você pode extrair as informações interessantes com:

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
Você pode verificar os símbolos extraídos do kernelcache com: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Com isso, agora podemos **extrair todas as extensões** ou a **que você está interessado em:**
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
## Extensões de Kernel do macOS

O macOS é **extremamente restritivo para carregar Extensões de Kernel** (.kext) devido aos altos privilégios com os quais o código será executado. Na verdade, por padrão, é praticamente impossível (a menos que seja encontrada uma forma de contornar isso).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Extensões de Sistema do macOS

Em vez de usar Extensões de Kernel, o macOS criou as Extensões de Sistema, que oferecem APIs de nível de usuário para interagir com o kernel. Dessa forma, os desenvolvedores podem evitar o uso de extensões de kernel.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Referências

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

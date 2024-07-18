# Kernel e Extensões do Sistema macOS

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Kernel XNU

O **núcleo do macOS é o XNU**, que significa "X is Not Unix". Esse kernel é fundamentalmente composto pelo **micronúcleo Mach** (a ser discutido posteriormente), **e** elementos do Berkeley Software Distribution (**BSD**). O XNU também fornece uma plataforma para **drivers de kernel por meio de um sistema chamado I/O Kit**. O kernel XNU faz parte do projeto de código aberto Darwin, o que significa que **seu código-fonte é livremente acessível**.

Do ponto de vista de um pesquisador de segurança ou de um desenvolvedor Unix, o **macOS** pode parecer bastante **similar** a um sistema **FreeBSD** com uma GUI elegante e uma série de aplicativos personalizados. A maioria dos aplicativos desenvolvidos para o BSD compilará e será executada no macOS sem a necessidade de modificações, pois as ferramentas de linha de comando familiares aos usuários Unix estão todas presentes no macOS. No entanto, como o kernel XNU incorpora o Mach, existem algumas diferenças significativas entre um sistema semelhante a Unix tradicional e o macOS, e essas diferenças podem causar problemas potenciais ou fornecer vantagens únicas.

Versão de código aberto do XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach é um **micronúcleo** projetado para ser **compatível com o UNIX**. Um de seus princípios de design chave foi **minimizar** a quantidade de **código** em execução no **espaço do kernel** e, em vez disso, permitir que muitas funções típicas do kernel, como sistema de arquivos, rede e E/S, sejam **executadas como tarefas em nível de usuário**.

No XNU, o Mach é **responsável por muitas das operações críticas de baixo nível** que um kernel normalmente manipula, como escalonamento de processador, multitarefa e gerenciamento de memória virtual.

### BSD

O **kernel** XNU também **incorpora** uma quantidade significativa de código derivado do projeto **FreeBSD**. Esse código **é executado como parte do kernel junto com o Mach**, no mesmo espaço de endereço. No entanto, o código do FreeBSD dentro do XNU pode diferir substancialmente do código original do FreeBSD porque foram necessárias modificações para garantir sua compatibilidade com o Mach. O FreeBSD contribui para muitas operações de kernel, incluindo:

* Gerenciamento de processos
* Manipulação de sinais
* Mecanismos básicos de segurança, incluindo gerenciamento de usuário e grupo
* Infraestrutura de chamada de sistema
* Pilha TCP/IP e soquetes
* Firewall e filtragem de pacotes

Compreender a interação entre BSD e Mach pode ser complexo, devido aos seus diferentes frameworks conceituais. Por exemplo, o BSD usa processos como sua unidade fundamental de execução, enquanto o Mach opera com base em threads. Essa discrepância é conciliada no XNU **associando cada processo BSD a uma tarefa Mach** que contém exatamente uma thread Mach. Quando a chamada de sistema fork() do BSD é usada, o código do BSD dentro do kernel usa funções do Mach para criar uma estrutura de tarefa e uma thread.

Além disso, **Mach e BSD mantêm modelos de segurança diferentes**: o modelo de segurança do **Mach** é baseado em **direitos de porta**, enquanto o modelo de segurança do BSD opera com base na **propriedade do processo**. Disparidades entre esses dois modelos ocasionalmente resultaram em vulnerabilidades de escalonamento de privilégios locais. Além das chamadas de sistema típicas, também existem **armadilhas do Mach que permitem que programas em espaço de usuário interajam com o kernel**. Esses elementos diferentes juntos formam a arquitetura híbrida e multifacetada do kernel macOS.

### I/O Kit - Drivers

O I/O Kit é um **framework de driver de dispositivo orientado a objetos de código aberto** no kernel XNU, que lida com **drivers de dispositivo carregados dinamicamente**. Ele permite que código modular seja adicionado ao kernel dinamicamente, suportando hardware diversificado.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Comunicação entre Processos

{% content-ref url="../macos-proces-abuse/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../macos-proces-abuse/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

O **kernelcache** é uma versão **pré-compilada e pré-linkada do kernel XNU**, juntamente com drivers de dispositivo essenciais e **extensões de kernel**. Ele é armazenado em um formato **compactado** e é descompactado na memória durante o processo de inicialização. O kernelcache facilita um **tempo de inicialização mais rápido** ao ter uma versão pronta para ser executada do kernel e drivers essenciais disponíveis, reduzindo o tempo e os recursos que seriam gastos dinamicamente carregando e vinculando esses componentes no momento da inicialização.

No iOS, ele está localizado em **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** no macOS você pode encontrá-lo com **`find / -name kernelcache 2>/dev/null`** ou **`mdfind kernelcache | grep kernelcache`**

É possível executar **`kextstat`** para verificar as extensões de kernel carregadas.

#### IMG4

O formato de arquivo IMG4 é um formato de contêiner usado pela Apple em seus dispositivos iOS e macOS para **armazenar e verificar com segurança** componentes de firmware (como **kernelcache**). O formato IMG4 inclui um cabeçalho e várias tags que encapsulam diferentes partes de dados, incluindo a carga útil real (como um kernel ou bootloader), uma assinatura e um conjunto de propriedades de manifesto. O formato suporta verificação criptográfica, permitindo que o dispositivo confirme a autenticidade e integridade do componente de firmware antes de executá-lo.

Geralmente é composto pelos seguintes componentes:

* **Carga útil (IM4P)**:
* Frequentemente comprimido (LZFSE4, LZSS, ...)
* Opcionalmente criptografado
* **Manifesto (IM4M)**:
* Contém Assinatura
* Dicionário Adicional Chave/Valor
* **Informações de Restauração (IM4R)**:
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

Às vezes a Apple lança o **kernelcache** com **símbolos**. Você pode baixar alguns firmwares com símbolos seguindo os links em [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

Estes são **firmwares** da Apple que você pode baixar em [**https://ipsw.me/**](https://ipsw.me/). Entre outros arquivos, ele conterá o **kernelcache**.\
Para **extrair** os arquivos, você pode simplesmente **descompactá-lo**.

Após extrair o firmware, você obterá um arquivo como: **`kernelcache.release.iphone14`**. Está em formato **IMG4**, você pode extrair as informações interessantes com:

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

O macOS é **super restritivo ao carregar Extensões de Kernel** (.kext) devido aos altos privilégios que o código terá ao ser executado. Na verdade, por padrão, é virtualmente impossível (a menos que seja encontrada uma forma de contornar).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Extensões de Sistema do macOS

Em vez de usar Extensões de Kernel, o macOS criou as Extensões de Sistema, que oferecem APIs em nível de usuário para interagir com o kernel. Dessa forma, os desenvolvedores podem evitar o uso de extensões de kernel.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Referências

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{% hint style="success" %}
Aprenda e pratique Hacking em AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking em GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

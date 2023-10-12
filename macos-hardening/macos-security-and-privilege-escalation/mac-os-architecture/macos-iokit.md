# macOS IOKit

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised on HackTricks**? Or do you want to have access to the **latest version of PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our exclusive collection of [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the official [**PEASS and HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the [**telegram group**](https://t.me/peass) or **follow me** on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Share your hacking tricks by sending PR to** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações básicas

O I/O Kit é o framework de **drivers de dispositivo** de código aberto, orientado a objetos, no kernel XNU e é responsável pela adição e gerenciamento de **drivers de dispositivo carregados dinamicamente**. Esses drivers permitem que código modular seja adicionado ao kernel dinamicamente para uso com diferentes hardwares, por exemplo.

Os drivers do IOKit basicamente **exportam funções do kernel**. Esses tipos de parâmetros de função são **predefinidos** e verificados. Além disso, assim como o XPC, o IOKit é apenas mais uma camada **sobre as mensagens Mach**.

O código do kernel IOKit XNU é de código aberto pela Apple em [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Além disso, os componentes do IOKit no espaço do usuário também são de código aberto [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

No entanto, **nenhum driver do IOKit** é de código aberto. De qualquer forma, de tempos em tempos, um lançamento de um driver pode vir com símbolos que facilitam a depuração. Verifique como [**obter as extensões do driver do firmware aqui**](./#ipsw)**.**

Ele é escrito em **C++**. Você pode obter símbolos C++ desembaralhados com:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
As funções expostas do IOKit podem realizar verificações de segurança adicionais quando um cliente tenta chamar uma função, mas observe que os aplicativos geralmente são limitados pelo sandbox com o qual as funções do IOKit podem interagir.
{% endhint %}

## Drivers

No macOS, eles estão localizados em:

* **`/System/Library/Extensions`**
* Arquivos KEXT incorporados ao sistema operacional OS X.
* **`/Library/Extensions`**
* Arquivos KEXT instalados por software de terceiros

No iOS, eles estão localizados em:

* **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
Até o número 9, os drivers listados são **carregados no endereço 0**. Isso significa que eles não são drivers reais, mas **parte do kernel e não podem ser descarregados**.

Para encontrar extensões específicas, você pode usar:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Para carregar e descarregar extensões de kernel, faça o seguinte:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

O **IORegistry** é uma parte crucial do framework IOKit no macOS e iOS, que serve como um banco de dados para representar a configuração e estado do hardware do sistema. É uma **coleção hierárquica de objetos que representam todo o hardware e drivers** carregados no sistema, e suas relações entre si.&#x20;

Você pode obter o IORegistry usando o comando **`ioreg`** para inspecioná-lo a partir do console (especialmente útil para iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Você pode baixar o **`IORegistryExplorer`** nas **Ferramentas Adicionais do Xcode** em [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) e inspecionar o **IORegistry do macOS** por meio de uma interface **gráfica**.

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

No IORegistryExplorer, "planos" são usados para organizar e exibir as relações entre diferentes objetos no IORegistry. Cada plano representa um tipo específico de relação ou uma visualização particular da configuração de hardware e driver do sistema. Aqui estão alguns dos planos comuns que você pode encontrar no IORegistryExplorer:

1. **Plano IOService**: Este é o plano mais geral, exibindo os objetos de serviço que representam drivers e nubs (canais de comunicação entre drivers). Ele mostra as relações entre provedores e clientes entre esses objetos.
2. **Plano IODeviceTree**: Este plano representa as conexões físicas entre dispositivos à medida que são conectados ao sistema. É frequentemente usado para visualizar a hierarquia de dispositivos conectados por meio de barramentos como USB ou PCI.
3. **Plano IOPower**: Exibe objetos e suas relações em termos de gerenciamento de energia. Pode mostrar quais objetos estão afetando o estado de energia de outros, útil para depurar problemas relacionados à energia.
4. **Plano IOUSB**: Especificamente focado em dispositivos USB e suas relações, mostrando a hierarquia de hubs USB e dispositivos conectados.
5. **Plano IOAudio**: Este plano é para representar dispositivos de áudio e suas relações dentro do sistema.
6. ...

## Exemplo de Código de Comunicação do Driver

O código a seguir se conecta ao serviço IOKit `"SeuNomeDeServiçoAqui"` e chama a função dentro do seletor 0. Para isso:

* primeiro chama **`IOServiceMatching`** e **`IOServiceGetMatchingServices`** para obter o serviço.
* Em seguida, estabelece uma conexão chamando **`IOServiceOpen`**.
* E finalmente chama uma função com **`IOConnectCallScalarMethod`** indicando o seletor 0 (o seletor é o número atribuído à função que você deseja chamar).
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
Existem **outras** funções que podem ser usadas para chamar funções do IOKit além de **`IOConnectCallScalarMethod`** como **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Revertendo o ponto de entrada do driver

Você pode obter essas funções, por exemplo, de uma [**imagem de firmware (ipsw)**](./#ipsw). Em seguida, carregue-a no seu descompilador favorito.

Você pode começar a descompilar a função **`externalMethod`**, pois esta é a função do driver que receberá a chamada e chamará a função correta:

<figure><img src="../../../.gitbook/assets/image (696).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

Aquela chamada desmascarada horrível significa:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Observe como na definição anterior o parâmetro **`self`** está faltando, a definição correta seria:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Na verdade, você pode encontrar a definição real em [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Com essas informações, você pode reescrever Ctrl+Right -> `Editar assinatura da função` e definir os tipos conhecidos:

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

O novo código descompilado ficará assim:

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

Para a próxima etapa, precisamos ter definida a estrutura **`IOExternalMethodDispatch2022`**. Ela é de código aberto em [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), você pode defini-la:

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

Agora, seguindo o `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, você pode ver muitos dados:

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

Altere o Tipo de Dados para **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

após a alteração:

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

E como agora sabemos que temos um **array de 7 elementos** (verifique o código descompilado final), clique para criar um array de 7 elementos:

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

Depois que o array for criado, você pode ver todas as funções exportadas:

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Se você se lembra, para **chamar** uma função **exportada** do espaço do usuário, não precisamos chamar o nome da função, mas o **número do seletor**. Aqui você pode ver que o seletor **0** é a função **`initializeDecoder`**, o seletor **1** é **`startDecoder`**, o seletor **2** é **`initializeEncoder`**...
{% endhint %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

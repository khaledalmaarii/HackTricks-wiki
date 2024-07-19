# macOS IOKit

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Información Básica

El I/O Kit es un **framework de controladores de dispositivos** de código abierto y orientado a objetos en el núcleo XNU, que maneja **controladores de dispositivos cargados dinámicamente**. Permite que se agregue código modular al núcleo sobre la marcha, soportando hardware diverso.

Los controladores de IOKit básicamente **exportan funciones del núcleo**. Los **tipos** de parámetros de estas funciones son **predefinidos** y son verificados. Además, similar a XPC, IOKit es solo otra capa **sobre los mensajes Mach**.

El **código del núcleo IOKit XNU** es de código abierto por Apple en [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Además, los componentes de IOKit en el espacio de usuario también son de código abierto [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Sin embargo, **ningún controlador de IOKit** es de código abierto. De todos modos, de vez en cuando, un lanzamiento de un controlador puede venir con símbolos que facilitan su depuración. Consulta cómo [**obtener las extensiones del controlador del firmware aquí**](./#ipsw)**.**

Está escrito en **C++**. Puedes obtener símbolos C++ demangled con:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
Las **funciones expuestas** de IOKit podrían realizar **verificaciones de seguridad adicionales** cuando un cliente intenta llamar a una función, pero ten en cuenta que las aplicaciones suelen estar **limitadas** por el **sandbox** con el que pueden interactuar las funciones de IOKit.
{% endhint %}

## Controladores

En macOS se encuentran en:

* **`/System/Library/Extensions`**
* Archivos KEXT integrados en el sistema operativo OS X.
* **`/Library/Extensions`**
* Archivos KEXT instalados por software de terceros

En iOS se encuentran en:

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
Hasta el número 9, los controladores listados están **cargados en la dirección 0**. Esto significa que no son controladores reales, sino **parte del núcleo y no se pueden descargar**.

Para encontrar extensiones específicas, puedes usar:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Para cargar y descargar extensiones del kernel, haz lo siguiente:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

El **IORegistry** es una parte crucial del marco IOKit en macOS e iOS que sirve como una base de datos para representar la configuración y el estado del hardware del sistema. Es una **colección jerárquica de objetos que representan todo el hardware y los controladores** cargados en el sistema, y sus relaciones entre sí.

Puedes obtener el IORegistry usando la cli **`ioreg`** para inspeccionarlo desde la consola (especialmente útil para iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Podrías descargar **`IORegistryExplorer`** de **Xcode Additional Tools** desde [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) e inspeccionar el **macOS IORegistry** a través de una interfaz **gráfica**.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

En IORegistryExplorer, se utilizan "planos" para organizar y mostrar las relaciones entre diferentes objetos en el IORegistry. Cada plano representa un tipo específico de relación o una vista particular de la configuración de hardware y controladores del sistema. Aquí hay algunos de los planos comunes que podrías encontrar en IORegistryExplorer:

1. **IOService Plane**: Este es el plano más general, que muestra los objetos de servicio que representan controladores y nubs (canales de comunicación entre controladores). Muestra las relaciones proveedor-cliente entre estos objetos.
2. **IODeviceTree Plane**: Este plano representa las conexiones físicas entre dispositivos a medida que están conectados al sistema. A menudo se utiliza para visualizar la jerarquía de dispositivos conectados a través de buses como USB o PCI.
3. **IOPower Plane**: Muestra objetos y sus relaciones en términos de gestión de energía. Puede mostrar qué objetos están afectando el estado de energía de otros, útil para depurar problemas relacionados con la energía.
4. **IOUSB Plane**: Enfocado específicamente en dispositivos USB y sus relaciones, mostrando la jerarquía de hubs USB y dispositivos conectados.
5. **IOAudio Plane**: Este plano es para representar dispositivos de audio y sus relaciones dentro del sistema.
6. ...

## Ejemplo de Código de Comunicación de Controladores

El siguiente código se conecta al servicio IOKit `"YourServiceNameHere"` y llama a la función dentro del selector 0. Para ello:

* primero llama a **`IOServiceMatching`** y **`IOServiceGetMatchingServices`** para obtener el servicio.
* Luego establece una conexión llamando a **`IOServiceOpen`**.
* Y finalmente llama a una función con **`IOConnectCallScalarMethod`** indicando el selector 0 (el selector es el número que se le ha asignado a la función que deseas llamar).
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
Hay **otras** funciones que se pueden usar para llamar a funciones de IOKit además de **`IOConnectCallScalarMethod`** como **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Invirtiendo el punto de entrada del controlador

Podrías obtener estos, por ejemplo, de una [**imagen de firmware (ipsw)**](./#ipsw). Luego, cárgalo en tu desensamblador favorito.

Podrías comenzar a desensamblar la función **`externalMethod`** ya que esta es la función del controlador que recibirá la llamada y llamará a la función correcta:

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

Esa horrible llamada desmanglada significa:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Nota cómo en la definición anterior falta el parámetro **`self`**, la buena definición sería:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

En realidad, puedes encontrar la definición real en [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Con esta información puedes reescribir Ctrl+Right -> `Edit function signature` y establecer los tipos conocidos:

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

El nuevo código decompilado se verá así:

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

Para el siguiente paso necesitamos tener definida la estructura **`IOExternalMethodDispatch2022`**. Es de código abierto en [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), podrías definirla:

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

Ahora, siguiendo el `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` puedes ver muchos datos:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Cambia el tipo de dato a **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

después del cambio:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Y como ahora sabemos que hay un **array de 7 elementos** (verifica el código decompilado final), haz clic para crear un array de 7 elementos:

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Después de que se crea el array, puedes ver todas las funciones exportadas:

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Si recuerdas, para **llamar** a una función **exportada** desde el espacio de usuario no necesitamos llamar al nombre de la función, sino al **número de selector**. Aquí puedes ver que el selector **0** es la función **`initializeDecoder`**, el selector **1** es **`startDecoder`**, el selector **2** **`initializeEncoder`**...
{% endhint %}

{% hint style="success" %}
Aprende y practica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}

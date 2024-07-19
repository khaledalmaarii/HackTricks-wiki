# macOS Launch/Environment Constraints & Trust Cache

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

Las restricciones de lanzamiento en macOS se introdujeron para mejorar la seguridad al **regular cómo, quién y desde dónde se puede iniciar un proceso**. Iniciadas en macOS Ventura, proporcionan un marco que categoriza **cada binario del sistema en distintas categorías de restricción**, que se definen dentro de la **caché de confianza**, una lista que contiene binarios del sistema y sus respectivos hashes. Estas restricciones se extienden a cada binario ejecutable dentro del sistema, implicando un conjunto de **reglas** que delinean los requisitos para **lanzar un binario particular**. Las reglas abarcan restricciones propias que un binario debe satisfacer, restricciones parentales que deben ser cumplidas por su proceso padre, y restricciones responsables que deben ser respetadas por otras entidades relevantes.

El mecanismo se extiende a aplicaciones de terceros a través de **Restricciones de Entorno**, comenzando desde macOS Sonoma, permitiendo a los desarrolladores proteger sus aplicaciones especificando un **conjunto de claves y valores para las restricciones de entorno.**

Definís **restricciones de entorno de lanzamiento y de biblioteca** en diccionarios de restricciones que guardás en **archivos de lista de propiedades de `launchd`**, o en **archivos de lista de propiedades** separados que usás en la firma de código.

Hay 4 tipos de restricciones:

* **Restricciones Propias**: Restricciones aplicadas al **binario en ejecución**.
* **Proceso Padre**: Restricciones aplicadas al **padre del proceso** (por ejemplo, **`launchd`** ejecutando un servicio XPC).
* **Restricciones Responsables**: Restricciones aplicadas al **proceso que llama al servicio** en una comunicación XPC.
* **Restricciones de carga de biblioteca**: Usá restricciones de carga de biblioteca para describir selectivamente el código que puede ser cargado.

Así que cuando un proceso intenta lanzar otro proceso — llamando a `execve(_:_:_:)` o `posix_spawn(_:_:_:_:_:_:)` — el sistema operativo verifica que el archivo **ejecutable** **satisface** su **propia restricción propia**. También verifica que el **ejecutable** del **proceso padre** **satisface** la **restricción de padre** del ejecutable, y que el **ejecutable** del **proceso responsable** **satisface la restricción del proceso responsable** del ejecutable. Si alguna de estas restricciones de lanzamiento no se satisface, el sistema operativo no ejecuta el programa.

Si al cargar una biblioteca, alguna parte de la **restricción de biblioteca no es verdadera**, tu proceso **no carga** la biblioteca.

## Categorías de LC

Un LC está compuesto por **hechos** y **operaciones lógicas** (y, o...) que combinan hechos.

Los [**hechos que un LC puede usar están documentados**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). Por ejemplo:

* is-init-proc: Un valor booleano que indica si el ejecutable debe ser el proceso de inicialización del sistema operativo (`launchd`).
* is-sip-protected: Un valor booleano que indica si el ejecutable debe ser un archivo protegido por la Protección de Integridad del Sistema (SIP).
* `on-authorized-authapfs-volume:` Un valor booleano que indica si el sistema operativo cargó el ejecutable desde un volumen APFS autorizado y autenticado.
* `on-authorized-authapfs-volume`: Un valor booleano que indica si el sistema operativo cargó el ejecutable desde un volumen APFS autorizado y autenticado.
* Volumen de Cryptexes
* `on-system-volume:` Un valor booleano que indica si el sistema operativo cargó el ejecutable desde el volumen del sistema actualmente iniciado.
* Dentro de /System...
* ...

Cuando un binario de Apple es firmado, se **asigna a una categoría de LC** dentro de la **caché de confianza**.

* Las **categorías de LC de iOS 16** fueron [**invertidas y documentadas aquí**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* Las **categorías de LC actuales (macOS 14 - Sonoma)** han sido invertidas y sus [**descripciones se pueden encontrar aquí**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Por ejemplo, la Categoría 1 es:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: Debe estar en el volumen del sistema o Cryptexes.
* `launch-type == 1`: Debe ser un servicio del sistema (plist en LaunchDaemons).
* `validation-category == 1`: Un ejecutable del sistema operativo.
* `is-init-proc`: Launchd

### Reversing LC Categories

Tienes más información [**sobre esto aquí**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), pero básicamente, están definidos en **AMFI (AppleMobileFileIntegrity)**, así que necesitas descargar el Kernel Development Kit para obtener el **KEXT**. Los símbolos que comienzan con **`kConstraintCategory`** son los **interesantes**. Al extraerlos obtendrás un flujo codificado DER (ASN.1) que necesitarás decodificar con [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) o la biblioteca python-asn1 y su script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) que te dará una cadena más comprensible.

## Environment Constraints

Estas son las Launch Constraints configuradas en **aplicaciones de terceros**. El desarrollador puede seleccionar los **hechos** y **operandos lógicos a utilizar** en su aplicación para restringir el acceso a sí mismo.

Es posible enumerar las Environment Constraints de una aplicación con:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

En **macOS** hay algunos cachés de confianza:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

Y en iOS parece que está en **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

{% hint style="warning" %}
En macOS que se ejecuta en dispositivos Apple Silicon, si un binario firmado por Apple no está en el caché de confianza, AMFI se negará a cargarlo.
{% endhint %}

### Enumerating Trust Caches

Los archivos de caché de confianza anteriores están en formato **IMG4** y **IM4P**, siendo IM4P la sección de carga útil de un formato IMG4.

Puedes usar [**pyimg4**](https://github.com/m1stadev/PyIMG4) para extraer la carga útil de las bases de datos:

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

(Otra opción podría ser usar la herramienta [**img4tool**](https://github.com/tihmstar/img4tool), que funcionará incluso en M1 aunque la versión sea antigua y para x86\_64 si la instalas en las ubicaciones adecuadas).

Ahora puedes usar la herramienta [**trustcache**](https://github.com/CRKatri/trustcache) para obtener la información en un formato legible:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
El caché de confianza sigue la siguiente estructura, así que la **categoría LC es la 4ª columna**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Then, you could use a script such as [**this one**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) to extract data.

From that data you can check the Apps with a **launch constraints value of `0`**, which are the ones that aren't constrained ([**check here**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) for what each value is).

## Mitigaciones de Ataques

Las restricciones de lanzamiento habrían mitigado varios ataques antiguos al **asegurar que el proceso no se ejecute en condiciones inesperadas:** Por ejemplo, desde ubicaciones inesperadas o siendo invocado por un proceso padre inesperado (si solo launchd debería estar lanzándolo).

Además, las restricciones de lanzamiento también **mitigan ataques de degradación.**

Sin embargo, **no mitigan abusos comunes de XPC**, **inyecciones de código de Electron** o **inyecciones de dylib** sin validación de biblioteca (a menos que se conozcan los IDs de equipo que pueden cargar bibliotecas).

### Protección del Daemon XPC

En la versión Sonoma, un punto notable es la **configuración de responsabilidad** del servicio daemon XPC. El servicio XPC es responsable de sí mismo, a diferencia del cliente que se conecta que es responsable. Esto está documentado en el informe de retroalimentación FB13206884. Esta configuración puede parecer defectuosa, ya que permite ciertas interacciones con el servicio XPC:

- **Lanzamiento del Servicio XPC**: Si se asume que es un error, esta configuración no permite iniciar el servicio XPC a través del código del atacante.
- **Conexión a un Servicio Activo**: Si el servicio XPC ya está en funcionamiento (posiblemente activado por su aplicación original), no hay barreras para conectarse a él.

Si bien implementar restricciones en el servicio XPC podría ser beneficioso al **reducir la ventana para ataques potenciales**, no aborda la preocupación principal. Asegurar la seguridad del servicio XPC requiere fundamentalmente **validar efectivamente al cliente que se conecta**. Este sigue siendo el único método para fortalecer la seguridad del servicio. También vale la pena señalar que la configuración de responsabilidad mencionada está actualmente operativa, lo que podría no alinearse con el diseño previsto.

### Protección de Electron

Incluso si se requiere que la aplicación sea **abierta por LaunchService** (en las restricciones de los padres). Esto se puede lograr utilizando **`open`** (que puede establecer variables de entorno) o utilizando la **API de Launch Services** (donde se pueden indicar variables de entorno).

## Referencias

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

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

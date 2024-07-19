# Network Namespace

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

Un namespace de red es una característica del núcleo de Linux que proporciona aislamiento de la pila de red, permitiendo que **cada namespace de red tenga su propia configuración de red independiente**, interfaces, direcciones IP, tablas de enrutamiento y reglas de firewall. Este aislamiento es útil en varios escenarios, como la contenedorización, donde cada contenedor debe tener su propia configuración de red, independiente de otros contenedores y del sistema host.

### Cómo funciona:

1. Cuando se crea un nuevo namespace de red, comienza con una **pila de red completamente aislada**, con **ninguna interfaz de red** excepto la interfaz de loopback (lo). Esto significa que los procesos que se ejecutan en el nuevo namespace de red no pueden comunicarse con procesos en otros namespaces o con el sistema host por defecto.
2. **Interfaces de red virtuales**, como pares veth, pueden ser creadas y movidas entre namespaces de red. Esto permite establecer conectividad de red entre namespaces o entre un namespace y el sistema host. Por ejemplo, un extremo de un par veth puede colocarse en el namespace de red de un contenedor, y el otro extremo puede conectarse a un **puente** u otra interfaz de red en el namespace del host, proporcionando conectividad de red al contenedor.
3. Las interfaces de red dentro de un namespace pueden tener sus **propias direcciones IP, tablas de enrutamiento y reglas de firewall**, independientes de otros namespaces. Esto permite que los procesos en diferentes namespaces de red tengan diferentes configuraciones de red y operen como si estuvieran ejecutándose en sistemas de red separados.
4. Los procesos pueden moverse entre namespaces utilizando la llamada al sistema `setns()`, o crear nuevos namespaces utilizando las llamadas al sistema `unshare()` o `clone()` con la bandera `CLONE_NEWNET`. Cuando un proceso se mueve a un nuevo namespace o crea uno, comenzará a usar la configuración de red y las interfaces asociadas con ese namespace.

## Laboratorio:

### Crear diferentes Namespaces

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, aseguras que el nuevo espacio de montaje tenga una **vista precisa y aislada de la información del proceso específica de ese espacio de nombres**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres de PID (Identificación de Proceso). Los detalles clave y la solución se describen a continuación:

1. **Explicación del Problema**:
- El núcleo de Linux permite a un proceso crear nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres de PID (denominado "proceso unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos hijos.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el espacio de nombres de PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que PID 1 tiene el papel especial de adoptar procesos huérfanos. El núcleo de Linux deshabilitará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:
- La salida de PID 1 en un nuevo espacio de nombres conduce a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` no puede asignar un nuevo PID al crear un nuevo proceso, produciendo el error "Cannot allocate memory".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` cree un nuevo proceso después de crear el nuevo espacio de nombres de PID.
- Ejecutar `%unshare -fp /bin/bash%` asegura que el comando `unshare` se convierta en PID 1 en el nuevo espacio de nombres. `/bin/bash` y sus procesos hijos están entonces contenidos de manera segura dentro de este nuevo espacio de nombres, previniendo la salida prematura de PID 1 y permitiendo la asignación normal de PID.

Al asegurarte de que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres de PID se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos operen sin encontrar el error de asignación de memoria.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;Verifica en qué namespace está tu proceso
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Encontrar todos los espacios de nombres de red

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrar dentro de un espacio de nombres de red
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
También, solo puedes **entrar en otro espacio de nombres de proceso si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/net`).

## Referencias
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

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

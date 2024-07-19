# PID Namespace

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
{% endhint %}

## Información Básica

El espacio de nombres PID (Identificador de Proceso) es una característica en el núcleo de Linux que proporciona aislamiento de procesos al permitir que un grupo de procesos tenga su propio conjunto de PIDs únicos, separado de los PIDs en otros espacios de nombres. Esto es particularmente útil en la contenedorización, donde el aislamiento de procesos es esencial para la seguridad y la gestión de recursos.

Cuando se crea un nuevo espacio de nombres PID, el primer proceso en ese espacio de nombres se le asigna el PID 1. Este proceso se convierte en el proceso "init" del nuevo espacio de nombres y es responsable de gestionar otros procesos dentro del espacio de nombres. Cada proceso subsiguiente creado dentro del espacio de nombres tendrá un PID único dentro de ese espacio de nombres, y estos PIDs serán independientes de los PIDs en otros espacios de nombres.

Desde la perspectiva de un proceso dentro de un espacio de nombres PID, solo puede ver otros procesos en el mismo espacio de nombres. No es consciente de los procesos en otros espacios de nombres y no puede interactuar con ellos utilizando herramientas tradicionales de gestión de procesos (por ejemplo, `kill`, `wait`, etc.). Esto proporciona un nivel de aislamiento que ayuda a prevenir que los procesos interfieran entre sí.

### Cómo funciona:

1. Cuando se crea un nuevo proceso (por ejemplo, utilizando la llamada al sistema `clone()`), el proceso puede ser asignado a un nuevo espacio de nombres PID o a uno existente. **Si se crea un nuevo espacio de nombres, el proceso se convierte en el proceso "init" de ese espacio de nombres**.
2. El **núcleo** mantiene un **mapeo entre los PIDs en el nuevo espacio de nombres y los PIDs correspondientes** en el espacio de nombres padre (es decir, el espacio de nombres del cual se creó el nuevo espacio de nombres). Este mapeo **permite que el núcleo traduzca PIDs cuando sea necesario**, como al enviar señales entre procesos en diferentes espacios de nombres.
3. **Los procesos dentro de un espacio de nombres PID solo pueden ver e interactuar con otros procesos en el mismo espacio de nombres**. No son conscientes de los procesos en otros espacios de nombres, y sus PIDs son únicos dentro de su espacio de nombres.
4. Cuando un **espacio de nombres PID es destruido** (por ejemplo, cuando el proceso "init" del espacio de nombres sale), **todos los procesos dentro de ese espacio de nombres son terminados**. Esto asegura que todos los recursos asociados con el espacio de nombres se limpien adecuadamente.

## Laboratorio:

### Crear diferentes Espacios de Nombres

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Cuando se ejecuta `unshare` sin la opción `-f`, se encuentra un error debido a la forma en que Linux maneja los nuevos espacios de nombres PID (ID de Proceso). Los detalles clave y la solución se describen a continuación:

1. **Explicación del Problema**:
- El núcleo de Linux permite que un proceso cree nuevos espacios de nombres utilizando la llamada al sistema `unshare`. Sin embargo, el proceso que inicia la creación de un nuevo espacio de nombres PID (denominado "proceso unshare") no entra en el nuevo espacio de nombres; solo lo hacen sus procesos hijos.
- Ejecutar `%unshare -p /bin/bash%` inicia `/bin/bash` en el mismo proceso que `unshare`. En consecuencia, `/bin/bash` y sus procesos hijos están en el espacio de nombres PID original.
- El primer proceso hijo de `/bin/bash` en el nuevo espacio de nombres se convierte en PID 1. Cuando este proceso sale, desencadena la limpieza del espacio de nombres si no hay otros procesos, ya que PID 1 tiene el papel especial de adoptar procesos huérfanos. El núcleo de Linux deshabilitará entonces la asignación de PID en ese espacio de nombres.

2. **Consecuencia**:
- La salida de PID 1 en un nuevo espacio de nombres conduce a la limpieza de la bandera `PIDNS_HASH_ADDING`. Esto resulta en que la función `alloc_pid` falla al intentar asignar un nuevo PID al crear un nuevo proceso, produciendo el error "Cannot allocate memory".

3. **Solución**:
- El problema se puede resolver utilizando la opción `-f` con `unshare`. Esta opción hace que `unshare` cree un nuevo proceso después de crear el nuevo espacio de nombres PID.
- Ejecutar `%unshare -fp /bin/bash%` asegura que el comando `unshare` se convierta en PID 1 en el nuevo espacio de nombres. `/bin/bash` y sus procesos hijos están entonces contenidos de manera segura dentro de este nuevo espacio de nombres, previniendo la salida prematura de PID 1 y permitiendo la asignación normal de PID.

Al asegurarse de que `unshare` se ejecute con la bandera `-f`, el nuevo espacio de nombres PID se mantiene correctamente, permitiendo que `/bin/bash` y sus subprocesos operen sin encontrar el error de asignación de memoria.

</details>

Al montar una nueva instancia del sistema de archivos `/proc` si usas el parámetro `--mount-proc`, aseguras que el nuevo espacio de nombres de montaje tenga una **vista precisa y aislada de la información del proceso específica para ese espacio de nombres**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Ver en qué namespace se encuentra tu proceso
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Encuentra todos los espacios de nombres PID

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Tenga en cuenta que el usuario root del espacio de nombres PID inicial (predeterminado) puede ver todos los procesos, incluso los que están en nuevos espacios de nombres PID, por eso podemos ver todos los espacios de nombres PID.

### Entrar dentro de un espacio de nombres PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Cuando entras dentro de un espacio de nombres PID desde el espacio de nombres predeterminado, aún podrás ver todos los procesos. Y el proceso de ese espacio de nombres PID podrá ver el nuevo bash en el espacio de nombres PID.

Además, solo puedes **entrar en otro espacio de nombres PID de proceso si eres root**. Y **no puedes** **entrar** en otro espacio de nombres **sin un descriptor** que apunte a él (como `/proc/self/ns/pid`)

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
</details>
{% endhint %}

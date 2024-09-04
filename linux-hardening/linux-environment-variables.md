# Variables de Entorno de Linux

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

## Variables globales

Las variables globales **serán** heredadas por **procesos hijos**.

Puedes crear una variable global para tu sesión actual haciendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Esta variable será accesible por tus sesiones actuales y sus procesos hijos.

Puedes **eliminar** una variable haciendo:
```bash
unset MYGLOBAL
```
## Variables locales

Las **variables locales** solo pueden ser **accedidas** por el **shell/script actual**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Listar variables actuales
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Variables comunes

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – la pantalla utilizada por **X**. Esta variable generalmente se establece en **:0.0**, lo que significa la primera pantalla en la computadora actual.
* **EDITOR** – el editor de texto preferido del usuario.
* **HISTFILESIZE** – el número máximo de líneas contenidas en el archivo de historial.
* **HISTSIZE** – Número de líneas añadidas al archivo de historial cuando el usuario termina su sesión.
* **HOME** – tu directorio personal.
* **HOSTNAME** – el nombre del host de la computadora.
* **LANG** – tu idioma actual.
* **MAIL** – la ubicación de la cola de correo del usuario. Generalmente **/var/spool/mail/USER**.
* **MANPATH** – la lista de directorios para buscar páginas de manual.
* **OSTYPE** – el tipo de sistema operativo.
* **PS1** – el aviso predeterminado en bash.
* **PATH** – almacena la ruta de todos los directorios que contienen archivos binarios que deseas ejecutar solo especificando el nombre del archivo y no por ruta relativa o absoluta.
* **PWD** – el directorio de trabajo actual.
* **SHELL** – la ruta al shell de comandos actual (por ejemplo, **/bin/bash**).
* **TERM** – el tipo de terminal actual (por ejemplo, **xterm**).
* **TZ** – tu zona horaria.
* **USER** – tu nombre de usuario actual.

## Variables interesantes para hacking

### **HISTFILESIZE**

Cambia el **valor de esta variable a 0**, para que cuando **termines tu sesión** el **archivo de historial** (\~/.bash\_history) **sea eliminado**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia el **valor de esta variable a 0**, para que cuando **termines tu sesión** cualquier comando se agregue al **archivo de historial** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Los procesos utilizarán el **proxy** declarado aquí para conectarse a internet a través de **http o https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Los procesos confiarán en los certificados indicados en **estas variables de entorno**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Cambia cómo se ve tu aviso.

[**Este es un ejemplo**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

Usuario regular:

![](<../.gitbook/assets/image (740).png>)

Uno, dos y tres trabajos en segundo plano:

![](<../.gitbook/assets/image (145).png>)

Un trabajo en segundo plano, uno detenido y el último comando no terminó correctamente:

![](<../.gitbook/assets/image (715).png>)


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

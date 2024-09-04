# Ataques Físicos

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}

## Recuperación de Contraseña de BIOS y Seguridad del Sistema

**Restablecer la BIOS** se puede lograr de varias maneras. La mayoría de las placas base incluyen una **batería** que, al ser retirada durante aproximadamente **30 minutos**, restablecerá la configuración de la BIOS, incluida la contraseña. Alternativamente, se puede ajustar un **puente en la placa base** para restablecer estas configuraciones conectando pines específicos.

Para situaciones donde los ajustes de hardware no son posibles o prácticos, las **herramientas de software** ofrecen una solución. Ejecutar un sistema desde un **Live CD/USB** con distribuciones como **Kali Linux** proporciona acceso a herramientas como **_killCmos_** y **_CmosPWD_**, que pueden ayudar en la recuperación de la contraseña de la BIOS.

En casos donde la contraseña de la BIOS es desconocida, ingresarla incorrectamente **tres veces** generalmente resultará en un código de error. Este código se puede usar en sitios web como [https://bios-pw.org](https://bios-pw.org) para potencialmente recuperar una contraseña utilizable.

### Seguridad UEFI

Para sistemas modernos que utilizan **UEFI** en lugar de la BIOS tradicional, se puede utilizar la herramienta **chipsec** para analizar y modificar configuraciones de UEFI, incluida la desactivación de **Secure Boot**. Esto se puede lograr con el siguiente comando:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Análisis de RAM y Ataques de Arranque en Frío

La RAM retiene datos brevemente después de que se corta la energía, generalmente durante **1 a 2 minutos**. Esta persistencia se puede extender a **10 minutos** aplicando sustancias frías, como nitrógeno líquido. Durante este período extendido, se puede crear un **volcado de memoria** utilizando herramientas como **dd.exe** y **volatility** para su análisis.

### Ataques de Acceso Directo a la Memoria (DMA)

**INCEPTION** es una herramienta diseñada para **manipulación de memoria física** a través de DMA, compatible con interfaces como **FireWire** y **Thunderbolt**. Permite eludir procedimientos de inicio de sesión parcheando la memoria para aceptar cualquier contraseña. Sin embargo, es ineficaz contra sistemas **Windows 10**.

### Live CD/USB para Acceso al Sistema

Cambiar binarios del sistema como **_sethc.exe_** o **_Utilman.exe_** con una copia de **_cmd.exe_** puede proporcionar un símbolo del sistema con privilegios de sistema. Herramientas como **chntpw** se pueden usar para editar el archivo **SAM** de una instalación de Windows, permitiendo cambios de contraseña.

**Kon-Boot** es una herramienta que facilita el inicio de sesión en sistemas Windows sin conocer la contraseña al modificar temporalmente el núcleo de Windows o UEFI. Más información se puede encontrar en [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Manejo de Características de Seguridad de Windows

#### Atajos de Arranque y Recuperación

- **Supr**: Acceder a la configuración de la BIOS.
- **F8**: Entrar en modo de recuperación.
- Presionar **Shift** después del banner de Windows puede eludir el inicio de sesión automático.

#### Dispositivos BAD USB

Dispositivos como **Rubber Ducky** y **Teensyduino** sirven como plataformas para crear dispositivos **bad USB**, capaces de ejecutar cargas útiles predefinidas al conectarse a una computadora objetivo.

#### Copia de Sombra de Volumen

Los privilegios de administrador permiten la creación de copias de archivos sensibles, incluido el archivo **SAM**, a través de PowerShell.

### Eludir la Encriptación BitLocker

La encriptación BitLocker puede potencialmente ser eludida si se encuentra la **contraseña de recuperación** dentro de un archivo de volcado de memoria (**MEMORY.DMP**). Herramientas como **Elcomsoft Forensic Disk Decryptor** o **Passware Kit Forensic** pueden ser utilizadas para este propósito.

### Ingeniería Social para Adición de Clave de Recuperación

Se puede agregar una nueva clave de recuperación de BitLocker a través de tácticas de ingeniería social, convenciendo a un usuario para que ejecute un comando que añade una nueva clave de recuperación compuesta de ceros, simplificando así el proceso de descifrado.

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}

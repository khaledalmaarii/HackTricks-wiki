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

Los siguientes pasos se recomiendan para modificar las configuraciones de inicio del dispositivo y los bootloaders como U-boot:

1. **Acceder a la Shell del Intérprete del Bootloader**:
- Durante el arranque, presione "0", espacio u otros "códigos mágicos" identificados para acceder a la shell del intérprete del bootloader.

2. **Modificar los Argumentos de Arranque**:
- Ejecute los siguientes comandos para agregar '`init=/bin/sh`' a los argumentos de arranque, permitiendo la ejecución de un comando de shell:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Configurar un Servidor TFTP**:
- Configure un servidor TFTP para cargar imágenes a través de una red local:
%%%
#setenv ipaddr 192.168.2.2 #IP local del dispositivo
#setenv serverip 192.168.2.1 #IP del servidor TFTP
#saveenv
#reset
#ping 192.168.2.1 #verificar acceso a la red
#tftp ${loadaddr} uImage-3.6.35 #loadaddr toma la dirección para cargar el archivo y el nombre del archivo de la imagen en el servidor TFTP
%%%

4. **Utilizar `ubootwrite.py`**:
- Use `ubootwrite.py` para escribir la imagen de U-boot y cargar un firmware modificado para obtener acceso root.

5. **Verificar Características de Depuración**:
- Verifique si las características de depuración como el registro detallado, la carga de núcleos arbitrarios o el arranque desde fuentes no confiables están habilitadas.

6. **Interferencia de Hardware Cautelosa**:
- Tenga cuidado al conectar un pin a tierra e interactuar con chips SPI o NAND flash durante la secuencia de arranque del dispositivo, particularmente antes de que el kernel se descomprima. Consulte la hoja de datos del chip NAND flash antes de hacer cortocircuito en los pines.

7. **Configurar un Servidor DHCP Malicioso**:
- Configure un servidor DHCP malicioso con parámetros dañinos para que un dispositivo los ingiera durante un arranque PXE. Utilice herramientas como el servidor auxiliar DHCP de Metasploit (MSF). Modifique el parámetro 'FILENAME' con comandos de inyección de comandos como `'a";/bin/sh;#'` para probar la validación de entrada en los procedimientos de inicio del dispositivo.

**Nota**: Los pasos que implican interacción física con los pines del dispositivo (*marcados con asteriscos) deben abordarse con extrema precaución para evitar dañar el dispositivo.


## Referencias
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)


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

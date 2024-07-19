# SPI

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

SPI (Interfaz Periférica Serial) es un Protocolo de Comunicación Serial Sincrónica utilizado en sistemas embebidos para comunicación a corta distancia entre ICs (Circuitos Integrados). El Protocolo de Comunicación SPI utiliza la arquitectura maestro-esclavo, que es orquestada por la señal de Reloj y la señal de Selección de Chip. Una arquitectura maestro-esclavo consiste en un maestro (generalmente un microprocesador) que gestiona periféricos externos como EEPROM, sensores, dispositivos de control, etc., que se consideran esclavos.

Se pueden conectar múltiples esclavos a un maestro, pero los esclavos no pueden comunicarse entre sí. Los esclavos son administrados por dos pines, reloj y selección de chip. Como SPI es un protocolo de comunicación sincrónica, los pines de entrada y salida siguen las señales de reloj. La selección de chip es utilizada por el maestro para seleccionar un esclavo e interactuar con él. Cuando la selección de chip está alta, el dispositivo esclavo no está seleccionado, mientras que cuando está baja, el chip ha sido seleccionado y el maestro interactuaría con el esclavo.

El MOSI (Master Out, Slave In) y MISO (Master In, Slave Out) son responsables de enviar y recibir datos. Los datos se envían al dispositivo esclavo a través del pin MOSI mientras la selección de chip se mantiene baja. Los datos de entrada contienen instrucciones, direcciones de memoria o datos según la hoja de datos del proveedor del dispositivo esclavo. Tras una entrada válida, el pin MISO es responsable de transmitir datos al maestro. Los datos de salida se envían exactamente en el siguiente ciclo de reloj después de que finaliza la entrada. El pin MISO transmite datos hasta que los datos se transmiten completamente o el maestro establece el pin de selección de chip en alto (en ese caso, el esclavo dejaría de transmitir y el maestro no escucharía después de ese ciclo de reloj).

## Volcado de Firmware desde EEPROMs

Volcar firmware puede ser útil para analizar el firmware y encontrar vulnerabilidades en él. A menudo, el firmware no está disponible en internet o es irrelevante debido a variaciones de factores como el número de modelo, versión, etc. Por lo tanto, extraer el firmware directamente del dispositivo físico puede ser útil para ser específico al buscar amenazas.

Obtener la Consola Serial puede ser útil, pero a menudo sucede que los archivos son de solo lectura. Esto limita el análisis por diversas razones. Por ejemplo, las herramientas que se requieren para enviar y recibir paquetes no estarían en el firmware. Por lo tanto, extraer los binarios para ingeniería inversa no es factible. Por lo tanto, tener todo el firmware volcado en el sistema y extraer los binarios para análisis puede ser muy útil.

Además, durante el red teaming y al obtener acceso físico a los dispositivos, volcar el firmware puede ayudar a modificar los archivos o inyectar archivos maliciosos y luego volver a flashearlos en la memoria, lo que podría ser útil para implantar una puerta trasera en el dispositivo. Por lo tanto, hay numerosas posibilidades que se pueden desbloquear con el volcado de firmware.

### Programador y Lector de EEPROM CH341A

Este dispositivo es una herramienta económica para volcar firmwares desde EEPROMs y también volver a flashearlos con archivos de firmware. Ha sido una opción popular para trabajar con chips BIOS de computadoras (que son solo EEPROMs). Este dispositivo se conecta a través de USB y necesita herramientas mínimas para comenzar. Además, generalmente realiza la tarea rápidamente, por lo que también puede ser útil en el acceso físico a dispositivos.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

Conecte la memoria EEPROM con el Programador CH341a y conecte el dispositivo a la computadora. En caso de que el dispositivo no sea detectado, intente instalar controladores en la computadora. Además, asegúrese de que la EEPROM esté conectada en la orientación correcta (generalmente, coloque el pin VCC en orientación inversa al conector USB) o de lo contrario, el software no podrá detectar el chip. Consulte el diagrama si es necesario:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Finalmente, use software como flashrom, G-Flash (GUI), etc. para volcar el firmware. G-Flash es una herramienta GUI mínima que es rápida y detecta automáticamente la EEPROM. Esto puede ser útil si el firmware necesita ser extraído rápidamente, sin mucho ajuste con la documentación.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Después de volcar el firmware, se puede realizar el análisis en los archivos binarios. Herramientas como strings, hexdump, xxd, binwalk, etc. se pueden usar para extraer mucha información sobre el firmware así como sobre todo el sistema de archivos también.

Para extraer los contenidos del firmware, se puede usar binwalk. Binwalk analiza las firmas hexadecimales e identifica los archivos en el archivo binario y es capaz de extraerlos.
```
binwalk -e <filename>
```
El puede ser .bin o .rom según las herramientas y configuraciones utilizadas.

{% hint style="danger" %}
Tenga en cuenta que la extracción de firmware es un proceso delicado y requiere mucha paciencia. Cualquier manejo inadecuado puede potencialmente corromper el firmware o incluso borrarlo por completo y hacer que el dispositivo sea inutilizable. Se recomienda estudiar el dispositivo específico antes de intentar extraer el firmware.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Tenga en cuenta que incluso si el PINOUT del Pirate Bus indica pines para **MOSI** y **MISO** para conectarse a SPI, sin embargo, algunos SPIs pueden indicar pines como DI y DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

En Windows o Linux, puede usar el programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para volcar el contenido de la memoria flash ejecutando algo como:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
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

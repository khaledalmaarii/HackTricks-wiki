# Infrarrojo

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

## Cómo funciona el Infrarrojo <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La luz infrarroja es invisible para los humanos**. La longitud de onda IR es de **0.7 a 1000 micrones**. Los controles remotos domésticos utilizan una señal IR para la transmisión de datos y operan en el rango de longitud de onda de 0.75..1.4 micrones. Un microcontrolador en el control remoto hace que un LED infrarrojo parpadee con una frecuencia específica, convirtiendo la señal digital en una señal IR.

Para recibir señales IR se utiliza un **fotoreceptor**. Este **convierte la luz IR en pulsos de voltaje**, que ya son **señales digitales**. Por lo general, hay un **filtro de luz oscura dentro del receptor**, que deja **pasar solo la longitud de onda deseada** y elimina el ruido.

### Variedad de Protocolos IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Los protocolos IR difieren en 3 factores:

* codificación de bits
* estructura de datos
* frecuencia portadora — a menudo en el rango de 36..38 kHz

#### Formas de codificación de bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codificación por Distancia de Pulso**

Los bits se codifican modulando la duración del espacio entre pulsos. El ancho del pulso en sí es constante.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Codificación por Ancho de Pulso**

Los bits se codifican mediante la modulación del ancho del pulso. El ancho del espacio después de la ráfaga de pulso es constante.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Codificación por Fase**

También se conoce como codificación Manchester. El valor lógico se define por la polaridad de la transición entre la ráfaga de pulso y el espacio. "Espacio a ráfaga de pulso" denota lógica "0", "ráfaga de pulso a espacio" denota lógica "1".

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinación de las anteriores y otras exóticas**

{% hint style="info" %}
Existen protocolos IR que están **tratando de volverse universales** para varios tipos de dispositivos. Los más famosos son RC5 y NEC. Desafortunadamente, el más famoso **no significa el más común**. En mi entorno, solo encontré dos controles remotos NEC y ninguno RC5.

A los fabricantes les encanta usar sus propios protocolos IR únicos, incluso dentro de la misma gama de dispositivos (por ejemplo, cajas de TV). Por lo tanto, los controles remotos de diferentes empresas y a veces de diferentes modelos de la misma empresa, no pueden trabajar con otros dispositivos del mismo tipo.
{% endhint %}

### Explorando una señal IR

La forma más confiable de ver cómo se ve la señal IR del control remoto es usar un osciloscopio. No demodula ni invierte la señal recibida, simplemente se muestra "tal cual". Esto es útil para pruebas y depuración. Mostraré la señal esperada con el ejemplo del protocolo IR NEC.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

Por lo general, hay un preámbulo al comienzo de un paquete codificado. Esto permite al receptor determinar el nivel de ganancia y el fondo. También hay protocolos sin preámbulo, por ejemplo, Sharp.

Luego se transmiten los datos. La estructura, el preámbulo y el método de codificación de bits son determinados por el protocolo específico.

El **protocolo IR NEC** contiene un comando corto y un código de repetición, que se envía mientras se presiona el botón. Tanto el comando como el código de repetición tienen el mismo preámbulo al principio.

El **comando NEC**, además del preámbulo, consiste en un byte de dirección y un byte de número de comando, por el cual el dispositivo entiende qué debe realizar. Los bytes de dirección y número de comando se duplican con valores inversos, para verificar la integridad de la transmisión. Hay un bit de parada adicional al final del comando.

El **código de repetición** tiene un "1" después del preámbulo, que es un bit de parada.

Para **lógica "0" y "1"** NEC utiliza Codificación por Distancia de Pulso: primero, se transmite una ráfaga de pulso después de la cual hay una pausa, cuya longitud establece el valor del bit.

### Aires Acondicionados

A diferencia de otros controles remotos, **los aires acondicionados no transmiten solo el código del botón presionado**. También **transmiten toda la información** cuando se presiona un botón para asegurar que la **máquina de aire acondicionado y el control remoto estén sincronizados**.\
Esto evitará que una máquina configurada a 20ºC se aumente a 21ºC con un control remoto, y luego cuando se use otro control remoto, que aún tiene la temperatura en 20ºC, para aumentar más la temperatura, se "aumente" a 21ºC (y no a 22ºC pensando que está en 21ºC).

### Ataques

Puedes atacar el Infrarrojo con Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Referencias

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

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

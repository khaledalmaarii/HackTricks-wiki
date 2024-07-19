# FZ - Infrarrojo

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

## Introducción <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para más información sobre cómo funciona el infrarrojo, consulta:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Receptor de Señal IR en Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper utiliza un receptor de señal IR digital TSOP, que **permite interceptar señales de controles remotos IR**. Hay algunos **smartphones** como Xiaomi, que también tienen un puerto IR, pero ten en cuenta que **la mayoría de ellos solo pueden transmitir** señales y son **incapaces de recibir**.

El receptor infrarrojo de Flipper **es bastante sensible**. Incluso puedes **captar la señal** mientras te mantienes **en algún lugar entre** el control remoto y la TV. No es necesario apuntar el control remoto directamente al puerto IR de Flipper. Esto es útil cuando alguien está cambiando de canal mientras está cerca de la TV, y tanto tú como Flipper están a cierta distancia.

Como la **decodificación de la señal infrarroja** ocurre del lado del **software**, Flipper Zero potencialmente soporta la **recepción y transmisión de cualquier código de control remoto IR**. En el caso de protocolos **desconocidos** que no se pueden reconocer, **graba y reproduce** la señal en bruto exactamente como se recibió.

## Acciones

### Controles Remotos Universales

Flipper Zero puede ser utilizado como un **control remoto universal para controlar cualquier TV, aire acondicionado o centro de medios**. En este modo, Flipper **fuerza por prueba** todos los **códigos conocidos** de todos los fabricantes soportados **de acuerdo con el diccionario de la tarjeta SD**. No necesitas elegir un control remoto particular para apagar la TV de un restaurante.

Es suficiente con presionar el botón de encendido en el modo de Control Remoto Universal, y Flipper **enviará secuencialmente los comandos "Apagar"** de todas las TVs que conoce: Sony, Samsung, Panasonic... y así sucesivamente. Cuando la TV recibe su señal, reaccionará y se apagará.

Tal fuerza bruta toma tiempo. Cuanto más grande sea el diccionario, más tiempo tomará terminar. Es imposible averiguar qué señal exactamente reconoció la TV ya que no hay retroalimentación de la TV.

### Aprender Nuevo Control Remoto

Es posible **capturar una señal infrarroja** con Flipper Zero. Si **encuentra la señal en la base de datos**, Flipper automáticamente **sabrà qué dispositivo es** y te permitirá interactuar con él.\
Si no lo encuentra, Flipper puede **almacenar** la **señal** y te permitirá **reproducirla**.

## Referencias

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

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

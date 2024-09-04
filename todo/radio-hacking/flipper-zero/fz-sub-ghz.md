# FZ - Sub-GHz

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


## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero puede **recibir y transmitir frecuencias de radio en el rango de 300-928 MHz** con su módulo integrado, que puede leer, guardar y emular controles remotos. Estos controles se utilizan para interactuar con puertas, barreras, cerraduras de radio, interruptores de control remoto, timbres inalámbricos, luces inteligentes y más. Flipper Zero puede ayudarte a aprender si tu seguridad está comprometida.

<figure><img src="../../../.gitbook/assets/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero tiene un módulo sub-1 GHz integrado basado en un [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[chip CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) y una antena de radio (el rango máximo es de 50 metros). Tanto el chip CC1101 como la antena están diseñados para operar en las bandas de frecuencias de 300-348 MHz, 387-464 MHz y 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (923).png" alt=""><figcaption></figcaption></figure>

## Acciones

### Analizador de Frecuencia

{% hint style="info" %}
Cómo encontrar qué frecuencia está usando el control remoto
{% endhint %}

Al analizar, Flipper Zero está escaneando la intensidad de las señales (RSSI) en todas las frecuencias disponibles en la configuración de frecuencia. Flipper Zero muestra la frecuencia con el valor RSSI más alto, con una intensidad de señal superior a -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Para determinar la frecuencia del control remoto, haz lo siguiente:

1. Coloca el control remoto muy cerca a la izquierda de Flipper Zero.
2. Ve a **Menú Principal** **→ Sub-GHz**.
3. Selecciona **Analizador de Frecuencia**, luego presiona y mantén presionado el botón en el control remoto que deseas analizar.
4. Revisa el valor de frecuencia en la pantalla.

### Leer

{% hint style="info" %}
Encuentra información sobre la frecuencia utilizada (también otra forma de encontrar qué frecuencia se usa)
{% endhint %}

La opción **Leer** **escucha en la frecuencia configurada** en la modulación indicada: 433.92 AM por defecto. Si **se encuentra algo** al leer, **se proporciona información** en la pantalla. Esta información podría usarse para replicar la señal en el futuro.

Mientras se usa Leer, es posible presionar el **botón izquierdo** y **configurarlo**.\
En este momento tiene **4 modulaciones** (AM270, AM650, FM328 y FM476), y **varias frecuencias relevantes** almacenadas:

<figure><img src="../../../.gitbook/assets/image (947).png" alt=""><figcaption></figcaption></figure>

Puedes establecer **cualquiera que te interese**, sin embargo, si **no estás seguro de qué frecuencia** podría ser la utilizada por el control remoto que tienes, **configura Hopping en ON** (Apagado por defecto), y presiona el botón varias veces hasta que Flipper la capture y te dé la información que necesitas para establecer la frecuencia.

{% hint style="danger" %}
Cambiar entre frecuencias toma algo de tiempo, por lo tanto, las señales transmitidas en el momento del cambio pueden perderse. Para una mejor recepción de señal, establece una frecuencia fija determinada por el Analizador de Frecuencia.
{% endhint %}

### **Leer Crudo**

{% hint style="info" %}
Robar (y reproducir) una señal en la frecuencia configurada
{% endhint %}

La opción **Leer Crudo** **graba señales** enviadas en la frecuencia de escucha. Esto puede usarse para **robar** una señal y **repetirla**.

Por defecto, **Leer Crudo también está en 433.92 en AM650**, pero si con la opción Leer encontraste que la señal que te interesa está en una **frecuencia/modulación diferente, también puedes modificar eso** presionando izquierda (mientras estás dentro de la opción Leer Crudo).

### Fuerza Bruta

Si conoces el protocolo utilizado, por ejemplo, por la puerta del garaje, es posible **generar todos los códigos y enviarlos con el Flipper Zero.** Este es un ejemplo que soporta tipos comunes de garajes: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Agregar Manualmente

{% hint style="info" %}
Agregar señales de una lista configurada de protocolos
{% endhint %}

#### Lista de [protocolos soportados](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (funciona con la mayoría de los sistemas de código estático) | 433.92 | Estático  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | Estático  |
| Nice Flo 24bit\_433                                             | 433.92 | Estático  |
| CAME 12bit\_433                                                 | 433.92 | Estático  |
| CAME 24bit\_433                                                 | 433.92 | Estático  |
| Linear\_300                                                     | 300.00 | Estático  |
| CAME TWEE                                                       | 433.92 | Estático  |
| Gate TX\_433                                                    | 433.92 | Estático  |
| DoorHan\_315                                                    | 315.00 | Dinámico |
| DoorHan\_433                                                    | 433.92 | Dinámico |
| LiftMaster\_315                                                 | 315.00 | Dinámico |
| LiftMaster\_390                                                 | 390.00 | Dinámico |
| Security+2.0\_310                                               | 310.00 | Dinámico |
| Security+2.0\_315                                               | 315.00 | Dinámico |
| Security+2.0\_390                                               | 390.00 | Dinámico |

### Vendedores Sub-GHz soportados

Revisa la lista en [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Frecuencias soportadas por región

Revisa la lista en [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Prueba

{% hint style="info" %}
Obtén dBms de las frecuencias guardadas
{% endhint %}

## Referencia

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

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

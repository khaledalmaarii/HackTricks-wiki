# Hardware Hacking

{% hint style="success" %}
Aprende y practica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}

## JTAG

JTAG permite realizar un escaneo de límites. El escaneo de límites analiza ciertos circuitos, incluidos los celdas y registros de escaneo de límites integrados para cada pin.

El estándar JTAG define **comandos específicos para realizar escaneos de límites**, incluidos los siguientes:

* **BYPASS** te permite probar un chip específico sin la sobrecarga de pasar por otros chips.
* **SAMPLE/PRELOAD** toma una muestra de los datos que entran y salen del dispositivo cuando está en su modo de funcionamiento normal.
* **EXTEST** establece y lee los estados de los pines.

También puede soportar otros comandos como:

* **IDCODE** para identificar un dispositivo
* **INTEST** para la prueba interna del dispositivo

Puedes encontrar estas instrucciones cuando uses una herramienta como el JTAGulator.

### El Puerto de Acceso de Prueba

Los escaneos de límites incluyen pruebas del **Puerto de Acceso de Prueba (TAP)** de cuatro hilos, un puerto de propósito general que proporciona **acceso a las funciones de soporte de prueba JTAG** integradas en un componente. TAP utiliza las siguientes cinco señales:

* Entrada de reloj de prueba (**TCK**) El TCK es el **reloj** que define con qué frecuencia el controlador TAP tomará una acción única (en otras palabras, saltar al siguiente estado en la máquina de estados).
* Entrada de selección de modo de prueba (**TMS**) El TMS controla la **máquina de estados finita**. En cada pulso del reloj, el controlador TAP JTAG del dispositivo verifica el voltaje en el pin TMS. Si el voltaje está por debajo de un cierto umbral, la señal se considera baja e interpretada como 0, mientras que si el voltaje está por encima de un cierto umbral, la señal se considera alta e interpretada como 1.
* Entrada de datos de prueba (**TDI**) TDI es el pin que envía **datos al chip a través de las celdas de escaneo**. Cada proveedor es responsable de definir el protocolo de comunicación a través de este pin, porque JTAG no lo define.
* Salida de datos de prueba (**TDO**) TDO es el pin que envía **datos fuera del chip**.
* Entrada de reinicio de prueba (**TRST**) El TRST opcional reinicia la máquina de estados finita **a un estado conocido bueno**. Alternativamente, si el TMS se mantiene en 1 durante cinco ciclos de reloj consecutivos, invoca un reinicio, de la misma manera que lo haría el pin TRST, razón por la cual TRST es opcional.

A veces podrás encontrar esos pines marcados en el PCB. En otras ocasiones, puede que necesites **encontrarlos**.

### Identificando pines JTAG

La forma más rápida pero más cara de detectar puertos JTAG es utilizando el **JTAGulator**, un dispositivo creado específicamente para este propósito (aunque también puede **detectar salidas de UART**).

Tiene **24 canales** a los que puedes conectar los pines de las placas. Luego realiza un **ataque BF** de todas las combinaciones posibles enviando comandos de escaneo de límites **IDCODE** y **BYPASS**. Si recibe una respuesta, muestra el canal correspondiente a cada señal JTAG.

Una forma más barata pero mucho más lenta de identificar salidas JTAG es utilizando el [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) cargado en un microcontrolador compatible con Arduino.

Usando **JTAGenum**, primero **definirías los pines del dispositivo de sondeo** que usarás para la enumeración. Tendrías que referenciar el diagrama de pines del dispositivo y luego conectar estos pines con los puntos de prueba en tu dispositivo objetivo.

Una **tercera forma** de identificar pines JTAG es **inspeccionando el PCB** en busca de uno de los diagramas de pines. En algunos casos, los PCBs pueden proporcionar convenientemente la **interfaz Tag-Connect**, que es una clara indicación de que la placa también tiene un conector JTAG. Puedes ver cómo se ve esa interfaz en [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Además, inspeccionar las **hojas de datos de los chipsets en el PCB** podría revelar diagramas de pines que apuntan a interfaces JTAG.

## SDW

SWD es un protocolo específico de ARM diseñado para depuración.

La interfaz SWD requiere **dos pines**: una señal bidireccional **SWDIO**, que es el equivalente de los pines **TDI y TDO de JTAG** y un reloj, y **SWCLK**, que es el equivalente de **TCK** en JTAG. Muchos dispositivos soportan el **Puerto de Depuración de Cable Serial o JTAG (SWJ-DP)**, una interfaz combinada de JTAG y SWD que te permite conectar un sondeo SWD o JTAG al objetivo.

{% hint style="success" %}
Aprende y practica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}

# iButton

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

## Intro

iButton es un nombre genérico para una clave de identificación electrónica empaquetada en un **contenedor metálico en forma de moneda**. También se le llama **Dallas Touch** Memory o memoria de contacto. Aunque a menudo se le llama erróneamente "clave magnética", **no hay nada magnético** en ella. De hecho, un **microchip** completo que opera en un protocolo digital está oculto en su interior.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### ¿Qué es iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Por lo general, iButton implica la forma física de la clave y el lector: una moneda redonda con dos contactos. Para el marco que la rodea, hay muchas variaciones, desde el soporte de plástico más común con un agujero hasta anillos, colgantes, etc.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Cuando la clave llega al lector, los **contactos se tocan** y la clave se alimenta para **transmitir** su ID. A veces, la clave **no se lee** de inmediato porque el **PSD de contacto de un intercomunicador es más grande** de lo que debería ser. Así que los contornos exteriores de la clave y el lector no podrían tocarse. Si ese es el caso, tendrás que presionar la clave contra una de las paredes del lector.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocolo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Las claves Dallas intercambian datos utilizando el protocolo 1-wire. Con solo un contacto para la transferencia de datos (!!) en ambas direcciones, de maestro a esclavo y viceversa. El protocolo 1-wire funciona según el modelo Maestro-Esclavo. En esta topología, el Maestro siempre inicia la comunicación y el Esclavo sigue sus instrucciones.

Cuando la clave (Esclavo) contacta con el intercomunicador (Maestro), el chip dentro de la clave se enciende, alimentado por el intercomunicador, y la clave se inicializa. A continuación, el intercomunicador solicita la ID de la clave. A continuación, examinaremos este proceso con más detalle.

Flipper puede funcionar tanto en modos Maestro como Esclavo. En el modo de lectura de claves, Flipper actúa como un lector, es decir, funciona como un Maestro. Y en el modo de emulación de clave, el Flipper finge ser una clave, está en modo Esclavo.

### Claves Dallas, Cyfral y Metakom

Para información sobre cómo funcionan estas claves, consulta la página [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Ataques

Los iButtons pueden ser atacados con Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Referencias

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

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

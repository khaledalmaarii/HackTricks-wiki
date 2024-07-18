# FZ - NFC

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

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Para información sobre RFID y NFC consulta la siguiente página:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Tarjetas NFC soportadas <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Aparte de las tarjetas NFC, Flipper Zero soporta **otro tipo de tarjetas de alta frecuencia** como varias **Mifare** Classic y Ultralight y **NTAG**.
{% endhint %}

Se agregarán nuevos tipos de tarjetas NFC a la lista de tarjetas soportadas. Flipper Zero soporta los siguientes **tipos de tarjetas NFC A** (ISO 14443A):

* ﻿**Tarjetas bancarias (EMV)** — solo lee UID, SAK y ATQA sin guardar.
* ﻿**Tarjetas desconocidas** — lee (UID, SAK, ATQA) y emula un UID.

Para **tarjetas NFC tipo B, tipo F y tipo V**, Flipper Zero puede leer un UID sin guardarlo.

### Tarjetas NFC tipo A <a href="#uvusf" id="uvusf"></a>

#### Tarjeta bancaria (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero solo puede leer un UID, SAK, ATQA y datos almacenados en tarjetas bancarias **sin guardar**.

Pantalla de lectura de tarjeta bancaria. Para tarjetas bancarias, Flipper Zero solo puede leer datos **sin guardar y emularlos**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Tarjetas desconocidas <a href="#id-37eo8" id="id-37eo8"></a>

Cuando Flipper Zero es **incapaz de determinar el tipo de tarjeta NFC**, solo se puede **leer y guardar un UID, SAK y ATQA**.

Pantalla de lectura de tarjeta desconocida. Para tarjetas NFC desconocidas, Flipper Zero solo puede emular un UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Tarjetas NFC tipos B, F y V <a href="#wyg51" id="wyg51"></a>

Para **tarjetas NFC tipos B, F y V**, Flipper Zero solo puede **leer y mostrar un UID** sin guardarlo.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Acciones

Para una introducción sobre NFC [**lee esta página**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Leer

Flipper Zero puede **leer tarjetas NFC**, sin embargo, **no entiende todos los protocolos** que se basan en ISO 14443. Sin embargo, dado que **UID es un atributo de bajo nivel**, podrías encontrarte en una situación en la que **el UID ya ha sido leído, pero el protocolo de transferencia de datos de alto nivel sigue siendo desconocido**. Puedes leer, emular e ingresar manualmente el UID usando Flipper para los lectores primitivos que utilizan UID para autorización.

#### Lectura del UID VS Lectura de los Datos Internos <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

En Flipper, la lectura de etiquetas de 13.56 MHz se puede dividir en dos partes:

* **Lectura de bajo nivel** — solo lee el UID, SAK y ATQA. Flipper intenta adivinar el protocolo de alto nivel basado en estos datos leídos de la tarjeta. No puedes estar 100% seguro de esto, ya que es solo una suposición basada en ciertos factores.
* **Lectura de alto nivel** — lee los datos de la memoria de la tarjeta utilizando un protocolo de alto nivel específico. Eso sería leer los datos en un Mifare Ultralight, leer los sectores de un Mifare Classic, o leer los atributos de la tarjeta de PayPass/Apple Pay.

### Leer Específico

En caso de que Flipper Zero no sea capaz de encontrar el tipo de tarjeta a partir de los datos de bajo nivel, en `Acciones Extra` puedes seleccionar `Leer Tipo de Tarjeta Específico` y **indicar manualmente** **el tipo de tarjeta que te gustaría leer**.

#### Tarjetas Bancarias EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Aparte de simplemente leer el UID, puedes extraer muchos más datos de una tarjeta bancaria. Es posible **obtener el número completo de la tarjeta** (los 16 dígitos en el frente de la tarjeta), **fecha de validez**, y en algunos casos incluso el **nombre del propietario** junto con una lista de las **transacciones más recientes**.\
Sin embargo, **no puedes leer el CVV de esta manera** (los 3 dígitos en la parte posterior de la tarjeta). Además, **las tarjetas bancarias están protegidas contra ataques de repetición**, por lo que copiarla con Flipper y luego intentar emularla para pagar algo no funcionará.

## Referencias

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

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

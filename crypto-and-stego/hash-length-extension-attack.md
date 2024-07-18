# Hash Length Extension Attack

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

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) es un motor de búsqueda alimentado por la **dark-web** que ofrece funcionalidades **gratuitas** para verificar si una empresa o sus clientes han sido **comprometidos** por **malwares robadores**.

Su objetivo principal de WhiteIntel es combatir la toma de cuentas y los ataques de ransomware resultantes de malware que roba información.

Puedes visitar su sitio web y probar su motor de forma **gratuita** en:

{% embed url="https://whiteintel.io" %}

***

## Resumen del ataque

Imagina un servidor que está **firmando** algunos **datos** al **agregar** un **secreto** a algunos datos de texto claro conocidos y luego hasheando esos datos. Si sabes:

* **La longitud del secreto** (esto también se puede forzar a partir de un rango de longitud dado)
* **Los datos de texto claro**
* **El algoritmo (y es vulnerable a este ataque)**
* **El padding es conocido**
* Usualmente se usa uno por defecto, así que si se cumplen los otros 3 requisitos, esto también se cumple
* El padding varía dependiendo de la longitud del secreto + datos, por eso se necesita la longitud del secreto

Entonces, es posible que un **atacante** **agregue** **datos** y **genere** una **firma** válida para los **datos anteriores + datos agregados**.

### ¿Cómo?

Básicamente, los algoritmos vulnerables generan los hashes primero **hasheando un bloque de datos**, y luego, **a partir** del **hash** (estado) **creado previamente**, **agregan el siguiente bloque de datos** y **lo hashean**.

Entonces, imagina que el secreto es "secreto" y los datos son "datos", el MD5 de "secretodata" es 6036708eba0d11f6ef52ad44e8b74d5b.\
Si un atacante quiere agregar la cadena "agregar", puede:

* Generar un MD5 de 64 "A"s
* Cambiar el estado del hash previamente inicializado a 6036708eba0d11f6ef52ad44e8b74d5b
* Agregar la cadena "agregar"
* Terminar el hash y el hash resultante será un **válido para "secreto" + "datos" + "padding" + "agregar"**

### **Herramienta**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Referencias

Puedes encontrar este ataque bien explicado en [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) es un motor de búsqueda alimentado por la **dark-web** que ofrece funcionalidades **gratuitas** para verificar si una empresa o sus clientes han sido **comprometidos** por **malwares robadores**.

Su objetivo principal de WhiteIntel es combatir la toma de cuentas y los ataques de ransomware resultantes de malware que roba información.

Puedes visitar su sitio web y probar su motor de forma **gratuita** en:

{% embed url="https://whiteintel.io" %}

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

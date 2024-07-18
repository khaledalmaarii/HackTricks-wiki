{% hint style="success" %}
Aprende y practica AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

# Resumen del ataque

Imagina un servidor que está **firmando** algunos **datos** al **añadir** un **secreto** a algunos datos de texto claro conocidos y luego hasheando esos datos. Si conoces:

* **La longitud del secreto** (esto también se puede encontrar por fuerza bruta dentro de un rango de longitudes dados)
* **Los datos de texto claro**
* **El algoritmo (y que sea vulnerable a este ataque)**
* **El relleno es conocido**
* Usualmente se usa uno por defecto, por lo que si se cumplen los otros 3 requisitos, este también lo está
* El relleno varía dependiendo de la longitud del secreto+datos, por eso se necesita la longitud del secreto

Entonces, es posible para un **atacante** **añadir** **datos** y **generar** una **firma válida** para los **datos anteriores + datos añadidos**.

## ¿Cómo?

Básicamente, los algoritmos vulnerables generan los hashes primero al **hashear un bloque de datos**, y luego, **a partir** del **hash creado previamente** (estado), **añaden el siguiente bloque de datos** y lo **hashean**.

Entonces, imagina que el secreto es "secreto" y los datos son "datos", el MD5 de "secretodata" es 6036708eba0d11f6ef52ad44e8b74d5b.\
Si un atacante quiere añadir la cadena "añadir" puede:

* Generar un MD5 de 64 "A"s
* Cambiar el estado del hash inicializado previamente a 6036708eba0d11f6ef52ad44e8b74d5b
* Añadir la cadena "añadir"
* Finalizar el hash y el hash resultante será uno **válido para "secreto" + "datos" + "relleno" + "añadir"**

## **Herramienta**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Referencias

Puedes encontrar este ataque bien explicado en [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


{% hint style="success" %}
Aprende y practica AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

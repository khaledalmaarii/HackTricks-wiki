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


# Identificación de binarios empaquetados

* **falta de cadenas**: Es común encontrar que los binarios empaquetados no tienen casi ninguna cadena.
* Muchas **cadenas no utilizadas**: Además, cuando un malware utiliza algún tipo de empaquetador comercial, es común encontrar muchas cadenas sin referencias cruzadas. Incluso si estas cadenas existen, eso no significa que el binario no esté empaquetado.
* También puedes usar algunas herramientas para intentar encontrar qué empaquetador se utilizó para empaquetar un binario:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Recomendaciones Básicas

* **Comienza** a analizar el binario empaquetado **desde abajo en IDA y sube**. Los desempaquetadores salen una vez que el código desempaquetado sale, por lo que es poco probable que el desempaquetador pase la ejecución al código desempaquetado al principio.
* Busca **JMP's** o **CALLs** a **registros** o **regiones** de **memoria**. También busca **funciones que empujan argumentos y una dirección de dirección y luego llaman a `retn`**, porque el retorno de la función en ese caso puede llamar a la dirección que se acaba de empujar a la pila antes de llamarla.
* Coloca un **punto de interrupción** en `VirtualAlloc`, ya que esto asigna espacio en memoria donde el programa puede escribir código desempaquetado. Usa "run to user code" o F8 para **obtener el valor dentro de EAX** después de ejecutar la función y "**seguir esa dirección en el volcado**". Nunca sabes si esa es la región donde se va a guardar el código desempaquetado.
* **`VirtualAlloc`** con el valor "**40**" como argumento significa Leer+Escribir+Ejecutar (algún código que necesita ejecución se va a copiar aquí).
* **Mientras desempaquetas** código, es normal encontrar **varias llamadas** a **operaciones aritméticas** y funciones como **`memcopy`** o **`Virtual`**`Alloc`. Si te encuentras en una función que aparentemente solo realiza operaciones aritméticas y tal vez algún `memcopy`, la recomendación es intentar **encontrar el final de la función** (tal vez un JMP o llamada a algún registro) **o** al menos la **llamada a la última función** y correr hasta allí, ya que el código no es interesante.
* Mientras desempaquetas código, **anota** cada vez que **cambies de región de memoria**, ya que un cambio de región de memoria puede indicar el **inicio del código desempaquetado**. Puedes volcar fácilmente una región de memoria usando Process Hacker (proceso --> propiedades --> memoria).
* Mientras intentas desempaquetar código, una buena manera de **saber si ya estás trabajando con el código desempaquetado** (para que puedas simplemente volcarlo) es **verificar las cadenas del binario**. Si en algún momento realizas un salto (tal vez cambiando la región de memoria) y notas que **se añadieron muchas más cadenas**, entonces puedes saber **que estás trabajando con el código desempaquetado**.\
Sin embargo, si el empaquetador ya contiene muchas cadenas, puedes ver cuántas cadenas contienen la palabra "http" y ver si este número aumenta.
* Cuando vuelques un ejecutable desde una región de memoria, puedes corregir algunos encabezados usando [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).


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

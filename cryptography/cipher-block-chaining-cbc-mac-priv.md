{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Entrenamiento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Entrenamiento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* ¡Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}


# CBC

Si la **cookie** es **solo** el **nombre de usuario** (o la primera parte de la cookie es el nombre de usuario) y deseas hacerse pasar por el nombre de usuario "**admin**". Entonces, puedes crear el nombre de usuario **"bdmin"** y **bruteforce** el **primer byte** de la cookie.

# CBC-MAC

**Código de autenticación de mensajes de encadenamiento de bloques** (**CBC-MAC**) es un método utilizado en criptografía. Funciona tomando un mensaje y cifrándolo bloque por bloque, donde la cifra de cada bloque está vinculada a la del bloque anterior. Este proceso crea una **cadena de bloques**, asegurando que cambiar incluso un solo bit del mensaje original llevará a un cambio impredecible en el último bloque de datos cifrados. Para realizar o revertir dicho cambio, se requiere la clave de cifrado, garantizando la seguridad.

Para calcular el CBC-MAC del mensaje m, se cifra m en modo CBC con un vector de inicialización cero y se conserva el último bloque. La siguiente figura esquematiza el cálculo del CBC-MAC de un mensaje que comprende bloques ![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) utilizando una clave secreta k y un cifrado de bloques E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Vulnerabilidad

Con CBC-MAC, por lo general, el **IV utilizado es 0**.\
Esto es un problema porque 2 mensajes conocidos (`m1` y `m2`) generarán 2 firmas (`s1` y `s2`) de forma independiente. Entonces:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Luego, un mensaje compuesto por m1 y m2 concatenados (m3) generará 2 firmas (s31 y s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Lo cual es posible de calcular sin conocer la clave del cifrado.**

Imagina que estás cifrando el nombre **Administrador** en bloques de **8 bytes**:

* `Administ`
* `rator\00\00\00`

Puedes crear un nombre de usuario llamado **Administ** (m1) y recuperar la firma (s1).\
Luego, puedes crear un nombre de usuario llamado el resultado de `rator\00\00\00 XOR s1`. Esto generará `E(m2 XOR s1 XOR 0)` que es s32.\
Ahora, puedes usar s32 como la firma del nombre completo **Administrador**.

### Resumen

1. Obtén la firma del nombre de usuario **Administ** (m1) que es s1
2. Obtén la firma del nombre de usuario **rator\x00\x00\x00 XOR s1 XOR 0** que es s32**.**
3. Establece la cookie como s32 y será una cookie válida para el usuario **Administrador**.

# Ataque Controlando el IV

Si puedes controlar el IV utilizado, el ataque podría ser muy fácil.\
Si las cookies son solo el nombre de usuario cifrado, para hacerse pasar por el usuario "**administrador**" puedes crear el usuario "**Administrator**" y obtendrás su cookie.\
Ahora, si puedes controlar el IV, puedes cambiar el primer byte del IV para que **IV\[0] XOR "A" == IV'\[0] XOR "a"** y regenerar la cookie para el usuario **Administrator**. Esta cookie será válida para **hacerse pasar** por el usuario **administrador** con el IV inicial.

## Referencias

Más información en [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Entrenamiento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Entrenamiento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* ¡Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

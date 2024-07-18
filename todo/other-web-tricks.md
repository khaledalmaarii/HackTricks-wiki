# Otros Trucos en la Web

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Entrenamiento de HackTricks para Expertos en Equipo Rojo de AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Entrenamiento de HackTricks para Expertos en Equipo Rojo de GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ayuda a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

### Encabezado de Host

En varias ocasiones, el back-end confía en el **encabezado de Host** para realizar algunas acciones. Por ejemplo, podría usar su valor como el **dominio para enviar un restablecimiento de contraseña**. Por lo tanto, cuando reciba un correo electrónico con un enlace para restablecer su contraseña, el dominio que se está utilizando es el que colocó en el encabezado de Host. Entonces, puedes solicitar el restablecimiento de contraseña de otros usuarios y cambiar el dominio a uno controlado por ti para robar sus códigos de restablecimiento de contraseña. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Ten en cuenta que es posible que ni siquiera necesites esperar a que el usuario haga clic en el enlace de restablecimiento de contraseña para obtener el token, ya que tal vez incluso **los filtros de spam u otros dispositivos/bots intermedios hagan clic en él para analizarlo**.
{% endhint %}

### Booleanos de Sesión

A veces, cuando completas alguna verificación correctamente, el back-end **simplemente agrega un booleano con el valor "True" a un atributo de seguridad de tu sesión**. Luego, un punto final diferente sabrá si pasaste esa verificación con éxito.\
Sin embargo, si **pasas la verificación** y tu sesión recibe ese valor "True" en el atributo de seguridad, puedes intentar **acceder a otros recursos** que **dependen del mismo atributo** pero a los que **no deberías tener permisos** para acceder. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funcionalidad de Registro

Intenta registrarte como un usuario que ya existe. También intenta usar caracteres equivalentes (puntos, muchos espacios y Unicode).

### Toma de correos electrónicos

Registra un correo electrónico, antes de confirmarlo cambia el correo electrónico, luego, si el nuevo correo de confirmación se envía al primer correo registrado, puedes tomar cualquier correo electrónico. O si puedes habilitar el segundo correo confirmando el primero, también puedes tomar cualquier cuenta.

### Acceso al servicio de asistencia interna de empresas que utilizan Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Método TRACE

Los desarrolladores pueden olvidar deshabilitar varias opciones de depuración en el entorno de producción. Por ejemplo, el método `TRACE` de HTTP está diseñado con fines de diagnóstico. Si está habilitado, el servidor web responderá a las solicitudes que utilicen el método `TRACE` repitiendo en la respuesta la solicitud exacta que se recibió. Este comportamiento suele ser inofensivo, pero ocasionalmente puede llevar a la divulgación de información, como el nombre de los encabezados de autenticación internos que pueden agregarse a las solicitudes por parte de proxies inversos.![Imagen para publicación](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Imagen para publicación](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Entrenamiento de HackTricks para Expertos en Equipo Rojo de AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Entrenamiento de HackTricks para Expertos en Equipo Rojo de GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ayuda a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

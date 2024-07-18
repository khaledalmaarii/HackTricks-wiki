{% hint style="success" %}
Aprende y practica AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line"> [**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte) <img src="/.gitbook/assets/arte.png" alt="" data-size="line"> \
Aprende y practica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line"> [**HackTricks Training GCP Red Team Expert (GRTE)** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* ¡Consulta los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

# Baseline

Un baseline consiste en tomar una instantánea de ciertas partes de un sistema para **compararla con un estado futuro y resaltar los cambios**.

Por ejemplo, puedes calcular y almacenar el hash de cada archivo del sistema de archivos para poder averiguar qué archivos fueron modificados.\
Esto también se puede hacer con las cuentas de usuario creadas, procesos en ejecución, servicios en ejecución y cualquier otra cosa que no debería cambiar mucho, o en absoluto.

## Monitoreo de Integridad de Archivos

El Monitoreo de Integridad de Archivos (FIM) es una técnica de seguridad crítica que protege los entornos de TI y los datos mediante el seguimiento de los cambios en los archivos. Involucra dos pasos clave:

1. **Comparación de Baseline:** Establecer un baseline utilizando atributos de archivo o sumas de verificación criptográficas (como MD5 o SHA-2) para comparaciones futuras y detectar modificaciones.
2. **Notificación de Cambios en Tiempo Real:** Recibir alertas instantáneas cuando los archivos son accedidos o alterados, típicamente a través de extensiones del kernel del sistema operativo.

## Herramientas

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Referencias

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


{% hint style="success" %}
Aprende y practica AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line"> [**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte) <img src="/.gitbook/assets/arte.png" alt="" data-size="line"> \
Aprende y practica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line"> [**HackTricks Training GCP Red Team Expert (GRTE)** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* ¡Consulta los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

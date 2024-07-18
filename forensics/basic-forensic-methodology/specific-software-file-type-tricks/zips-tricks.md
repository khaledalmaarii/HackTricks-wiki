# Trucos con archivos ZIP

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Entrenamiento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Entrenamiento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoia a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

Las **herramientas de línea de comandos** para gestionar **archivos ZIP** son esenciales para diagnosticar, reparar y crackear archivos ZIP. Aquí tienes algunas utilidades clave:

- **`unzip`**: Revela por qué un archivo ZIP puede no descomprimirse.
- **`zipdetails -v`**: Ofrece un análisis detallado de los campos del formato de archivo ZIP.
- **`zipinfo`**: Lista el contenido de un archivo ZIP sin extraerlo.
- **`zip -F input.zip --out output.zip`** y **`zip -FF input.zip --out output.zip`**: Intenta reparar archivos ZIP corruptos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Una herramienta para crackear por fuerza bruta contraseñas de archivos ZIP, efectiva para contraseñas de hasta alrededor de 7 caracteres.

La [especificación del formato de archivo ZIP](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) proporciona detalles completos sobre la estructura y estándares de los archivos ZIP.

Es crucial tener en cuenta que los archivos ZIP protegidos con contraseña **no cifran los nombres de archivo ni los tamaños de archivo** en su interior, una falla de seguridad que no comparten los archivos RAR o 7z, que cifran esta información. Además, los archivos ZIP cifrados con el antiguo método ZipCrypto son vulnerables a un **ataque de texto plano** si hay una copia sin cifrar de un archivo comprimido disponible. Este ataque aprovecha el contenido conocido para crackear la contraseña del ZIP, una vulnerabilidad detallada en [el artículo de HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) y explicada más detalladamente en [este artículo académico](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Sin embargo, los archivos ZIP asegurados con cifrado **AES-256** son inmunes a este ataque de texto plano, lo que destaca la importancia de elegir métodos de cifrado seguros para datos sensibles.

## Referencias
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

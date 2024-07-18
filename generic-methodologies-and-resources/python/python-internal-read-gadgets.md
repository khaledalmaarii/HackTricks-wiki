# Gadgets de Lectura Interna de Python

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Información Básica

Diferentes vulnerabilidades como [**Cadenas de Formato en Python**](bypass-python-sandboxes/#python-format-string) o [**Contaminación de Clases**](class-pollution-pythons-prototype-pollution.md) podrían permitirte **leer datos internos de Python pero no ejecutar código**. Por lo tanto, un pentester necesitará aprovechar al máximo estos permisos de lectura para **obtener privilegios sensibles y escalar la vulnerabilidad**.

### Flask - Leer clave secreta

La página principal de una aplicación Flask probablemente tendrá el objeto global **`app`** donde se configura este **secreto**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
En este caso es posible acceder a este objeto simplemente utilizando cualquier gadget para **acceder a objetos globales** desde la [**página de Bypass Python sandboxes**](bypass-python-sandboxes/).

En el caso en el que **la vulnerabilidad se encuentre en un archivo Python diferente**, necesitas un gadget para atravesar archivos y llegar al principal para **acceder al objeto global `app.secret_key`** y cambiar la clave secreta de Flask y poder [**escalar privilegios** conociendo esta clave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Una carga útil como esta [de este writeup](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Utilice este payload para **cambiar `app.secret_key`** (el nombre en su aplicación puede ser diferente) para poder firmar nuevas y más privilegiadas cookies de flask.

### Werkzeug - machine\_id y node uuid

[**Utilizando este payload de este informe**](https://vozec.fr/writeups/tweedle-dum-dee/) podrá acceder al **machine\_id** y al nodo **uuid**, que son los **secretos principales** que necesita para [**generar el pin de Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) que puede usar para acceder a la consola de Python en `/console` si el **modo de depuración está habilitado:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Ten en cuenta que puedes obtener la **ruta local de los servidores al `app.py`** generando algún **error** en la página web que te **proporcione la ruta**.
{% endhint %}

Si la vulnerabilidad está en un archivo python diferente, revisa el truco anterior de Flask para acceder a los objetos desde el archivo python principal.

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos en** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

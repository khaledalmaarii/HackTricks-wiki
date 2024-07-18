# Python Internele Lees Gadgets

{% hint style="success" %}
Leer & oefen AWS Hack: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

## Basiese Inligting

Verskillende kwesbaarhede soos [**Python Formaat Strings**](bypass-python-sandboxes/#python-format-string) of [**Klas Besoedeling**](class-pollution-pythons-prototype-pollution.md) mag jou in staat stel om **Python interne data te lees, maar sal nie toelaat dat jy kode uitvoer nie**. Daarom sal 'n pentester die meeste moet maak van hierdie leesregte om **sensitiewe voorregte te verkry en die kwesbaarheid te eskaleer**.

### Flask - Lees geheime sleutel

Die hoofbladsy van 'n Flask-aansoek sal waarskynlik die **`app`** globale objek hê waar hierdie **geheime ingestel is**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In hierdie geval is dit moontlik om toegang tot hierdie objek te verkry deur net enige gadget te gebruik om **globale objekte te benader** vanaf die [**Bypass Python sandboxes page**](bypass-python-sandboxes/).

In die geval waar **die kwesbaarheid in 'n ander Python-lêer is**, het jy 'n gadget nodig om deur lêers te navigeer om by die hooflêer te kom om die **globale objek `app.secret_key`** te benader om die Flask-geheim sleutel te verander en in staat te wees om [**privileges te eskaleer** deur hierdie sleutel te ken](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

'n Lading soos hierdie een [van hierdie skryfstuk](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Gebruik hierdie ladingstuk om **`app.secret_key` te verander** (die naam in jou app kan verskil) sodat jy nuwe en meer voorregte flask-koekies kan teken.

### Werkzeug - machine\_id en node uuid

[**Deur hierdie ladingstuk van hierdie skryfstuk te gebruik**](https://vozec.fr/writeups/tweedle-dum-dee/) sal jy in staat wees om die **machine\_id** en die **uuid** node te ontsluit, wat die **hoofgeheime** is wat jy nodig het om die [**Werkzeug-speld te genereer**](../../network-services-pentesting/pentesting-web/werkzeug.md) wat jy kan gebruik om toegang tot die python-konsole in `/console` te verkry as die **foutopsporingsmodus geaktiveer is:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Let wel dat jy die **bedieners se plaaslike pad na die `app.py`** kan kry deur 'n **fout** op die webbladsy te veroorsaak wat jou die pad sal **gee**.
{% endhint %}

As die kwesbaarheid in 'n ander Python-lêer is, kyk na die vorige Flask-truuk om toegang tot die voorwerpe van die hoof-Python-lêer te verkry.

{% hint style="success" %}
Leer & oefen AWS-hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

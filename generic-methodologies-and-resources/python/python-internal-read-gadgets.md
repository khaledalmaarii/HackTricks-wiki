# Python Interne Lees Gadgets

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

Verskillende kwesbaarhede soos [**Python-formaatreekse**](bypass-python-sandboxes/#python-format-string) of [**Klasverontreiniging**](class-pollution-pythons-prototype-pollution.md) mag jou in staat stel om **Python interne data te lees, maar sal nie toelaat dat jy kode uitvoer nie**. Daarom sal 'n pentester die meeste uit hierdie leesregte moet maak om **gevoelige bevoegdhede te verkry en die kwesbaarheid te eskaleer**.

### Flask - Lees geheime sleutel

Die hoofbladsy van 'n Flask-toepassing sal waarskynlik die **`app`** globale objek hê waarin hierdie **geheime sleutel gekonfigureer** is.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In hierdie geval is dit moontlik om toegang tot hierdie objek te verkry deur enige gadget te gebruik om **globale objekte te benader** vanaf die [**Bypass Python sandboxes page**](bypass-python-sandboxes/).

In die geval waar **die kwesbaarheid in 'n ander Python-lêer is**, het jy 'n gadget nodig om deur lêers te blaai om by die hooflêer te kom om die globale objek `app.secret_key` te **benader** om die Flask-geheime sleutel te verander en in staat te wees om [**voorregte te verhoog** deur hierdie sleutel te ken](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

'n Payload soos hierdie een [vanaf hierdie writeup](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Gebruik hierdie payload om die `app.secret_key` (die naam in jou app mag verskil) te **verander** sodat jy nuwe en meer bevoegdhede flask koekies kan onderteken.

### Werkzeug - machine\_id en node uuid

[**Deur hierdie payload van hierdie writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) te gebruik, sal jy toegang hê tot die **machine\_id** en die **uuid** node, wat die **hoofgeheime** is wat jy nodig het om die [**Werkzeug pin te genereer**](../../network-services-pentesting/pentesting-web/werkzeug.md) wat jy kan gebruik om toegang te verkry tot die python-konsole in `/console` as die **foutopsporingsmodus geaktiveer is:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Let daarop dat jy die **bedieners se plaaslike pad na die `app.py`** kan kry deur 'n **fout** op die webblad te genereer wat jou die pad sal gee.
{% endhint %}

As die kwesbaarheid in 'n ander Python-lêer is, kyk na die vorige Flask-truuk om toegang tot die voorwerpe van die hoof-Python-lêer te verkry.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

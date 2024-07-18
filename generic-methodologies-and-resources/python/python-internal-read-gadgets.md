# Python Interni Čitački Gadgeti

{% hint style="success" %}
Naučite i vežbajte AWS hakovanje:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte GCP hakovanje: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Osnovne Informacije

Različite ranjivosti poput [**Python Format Stringova**](bypass-python-sandboxes/#python-format-string) ili [**Zagađenje Klasa**](class-pollution-pythons-prototype-pollution.md) mogu vam omogućiti da **čitate interne podatke Pythona ali vam neće dozvoliti izvršavanje koda**. Stoga, pentester će morati maksimalno iskoristiti ova dozvola za čitanje kako bi **dobio osetljive privilegije i eskalirao ranjivost**.

### Flask - Čitanje tajnog ključa

Glavna stranica Flask aplikacije verovatno će imati **`app`** globalni objekat gde je ovaj **tajni ključ konfigurisan**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
U ovom slučaju moguće je pristupiti ovom objektu koristeći bilo koji gedžet za **pristup globalnim objektima** sa [**Bypass Python sandboxes stranice**](bypass-python-sandboxes/).

U slučaju kada je **ranjivost u drugom Python fajlu**, potreban vam je gedžet za pretragu fajlova kako biste došli do glavnog fajla i **pristupili globalnom objektu `app.secret_key`** kako biste promenili Flask tajni ključ i bili u mogućnosti da [**dignete privilegije** znajući ovaj ključ](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload poput ovog [iz ovog writeupa](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Koristite ovaj payload da **promenite `app.secret_key`** (naziv u vašoj aplikaciji može biti drugačiji) kako biste mogli da potpišete nove i privilegovane flask kolačiće.

### Werkzeug - machine\_id i node uuid

[**Koristeći ovaj payload iz ovog writeupa**](https://vozec.fr/writeups/tweedle-dum-dee/) bićete u mogućnosti da pristupite **machine\_id**-u i **uuid** nodu, koji su **glavne tajne** koje su vam potrebne da [**generišete Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) koji možete koristiti da pristupite python konzoli na `/console` ako je **omogućen debug režim:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Imajte na umu da možete dobiti **lokalnu putanju servera do `app.py`** generišući neku **grešku** na veb stranici koja će vam **omogućiti pristup putanji**.
{% endhint %}

Ako je ranjivost u drugom Python fajlu, proverite prethodni trik sa Flask-om kako biste pristupili objektima iz glavnog Python fajla.

{% hint style="success" %}
Učite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

# Vifaa vya Kusoma vya Ndani ya Python

{% hint style="success" %}
Jifunze na zoezi la Kuvamia AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la Kuvamia GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Taarifa Msingi

Mazingira tofauti ya udhaifu kama [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) au [**Uchafuzi wa Darasa**](class-pollution-pythons-prototype-pollution.md) yanaweza kukuruhusu **kusoma data ya ndani ya python lakini haitakuruhusu kutekeleza nambari**. Hivyo, mchunguzi wa mtandao atahitaji kutumia vibali hivi vya kusoma ili **kupata mamlaka nyeti na kukuza udhaifu**.

### Flask - Soma funguo ya siri

Ukurasa mkuu wa programu ya Flask labda utakuwa na **`app`** kifaa cha jumla ambapo hii **siri imewekwa**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Katika kesi hii ni rahisi kupata ufikiaji wa kipengee hiki kwa kutumia kifaa chochote cha **kufikia vitu vya ulimwengu** kutoka kwenye [**Ukurasa wa Kupitisha Mchanga wa Python**](bypass-python-sandboxes/).

Katika kesi ambapo **uwazi upo kwenye faili tofauti ya python**, unahitaji kifaa cha kupita faili ili ufikie faili kuu ili **kupata kipengee cha ulimwengu `app.secret_key`** kubadilisha funguo ya siri ya Flask na kuweza [**kupandisha vyeo** ukiwa na funguo hii](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Mzigo kama huu [kutoka kwenye andiko hili](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Tumia mzigo huu wa **kubadilisha `app.secret_key`** (jina katika programu yako linaweza kuwa tofauti) ili uweze kusaini vidakuzi vya flask vipya na vyenye mamlaka zaidi.

### Werkzeug - machine\_id na uuid ya node

[Kutumia mzigo huu kutoka kwenye andiko hili](https://vozec.fr/writeups/tweedle-dum-dee/) utaweza kupata **machine\_id** na **uuid** ya node, ambayo ni **siri kuu** unayohitaji [**kuunda pin ya Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) unayoweza kutumia kufikia konsoli ya python katika `/console` ikiwa **hali ya kurekebisha makosa imewezeshwa:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Tafadhali kumbuka unaweza kupata **njia ya seva ya ndani kwa `app.py`** kwa kuzalisha **kosa** fulani kwenye ukurasa wa wavuti ambao utakupa **njia hiyo**.
{% endhint %}

Ikiwa udhaifu uko kwenye faili tofauti ya python, angalia hila ya awali ya Flask ya kupata vitu kutoka kwa faili kuu ya python.

{% hint style="success" %}
Jifunze & jifunze AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & jifunze GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

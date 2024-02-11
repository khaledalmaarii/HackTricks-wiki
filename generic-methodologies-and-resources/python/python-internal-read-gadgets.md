# Vifaa vya Kusoma vya Ndani ya Python

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

Mambo tofauti ya udhaifu kama [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) au [**Uchafuzi wa Darasa**](class-pollution-pythons-prototype-pollution.md) inaweza kukuruhusu **kusoma data ya ndani ya python lakini hautakuruhusu kutekeleza nambari**. Kwa hivyo, mtaalamu wa kudukua atahitaji kutumia vibali hivi vya kusoma ili **kupata mamlaka nyeti na kuongeza udhaifu**.

### Flask - Soma funguo za siri

Ukurasa mkuu wa programu ya Flask labda utakuwa na kifaa cha kawaida cha **`app`** ambapo **siri hii imepangwa**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Katika kesi hii, niwezekana kupata kifaa chochote cha **kufikia vitu vya kimataifa** kutoka kwenye [**ukurasa wa Kuepuka sanduku za mchanga za Python**](bypass-python-sandboxes/).

Katika kesi ambapo **hitilafu iko kwenye faili tofauti ya python**, unahitaji kifaa cha kusafiri kwenye faili ili kupata faili kuu ili **kufikia kifaa cha kimataifa `app.secret_key`** ili kubadilisha Flask secret key na kuweza [**kuongeza mamlaka** kwa kujua funguo hizi](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload kama hii [kutoka kwenye andiko hili](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Tumia mzigo huu kubadilisha `app.secret_key` (jina katika programu yako linaweza kuwa tofauti) ili uweze kusaini kuki za flask zenye mamlaka zaidi.

### Werkzeug - machine\_id na node uuid

[Kwa kutumia mzigo huu kutoka kwenye andiko hili](https://vozec.fr/writeups/tweedle-dum-dee/) utaweza kupata **machine\_id** na **uuid** node, ambazo ni **siri kuu** unazohitaji [**kuunda pini ya Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) unayoweza kutumia kufikia konsoli ya python kwenye `/console` ikiwa **debug mode imeamilishwa:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Tafadhali kumbuka kuwa unaweza kupata **njia ya seva ya ndani kwa `app.py`** kwa kuzalisha **kosa** fulani kwenye ukurasa wa wavuti ambao utakupa **njia hiyo**.
{% endhint %}

Ikiwa udhaifu uko kwenye faili tofauti ya python, angalia mbinu ya Flask ya awali ya kupata vitu kutoka kwenye faili kuu ya python.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

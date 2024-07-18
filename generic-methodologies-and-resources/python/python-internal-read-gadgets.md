# Wewnętrzne Gadżety Pythona

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępniaj sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}

## Podstawowe Informacje

Różne podatności takie jak [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) lub [**Zanieczyszczenie Klasy**](class-pollution-pythons-prototype-pollution.md) mogą umożliwić Ci **odczytanie wewnętrznych danych Pythona, ale nie pozwolą na wykonanie kodu**. Dlatego pentester będzie musiał jak najlepiej wykorzystać te uprawnienia do **uzyskania poufnych przywilejów i eskalacji podatności**.

### Flask - Odczytaj klucz tajny

Główna strona aplikacji Flask prawdopodobnie będzie zawierać obiekt globalny **`app`**, w którym jest skonfigurowany ten **tajny klucz**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
W tym przypadku możliwe jest uzyskanie dostępu do tego obiektu za pomocą dowolnego gadżetu do **dostępu do obiektów globalnych** z [strony **Omijanie piaskownic Pythona**](bypass-python-sandboxes/).

W przypadku, gdy **podatność znajduje się w innym pliku pythona**, potrzebujesz gadżetu do przeglądania plików, aby dotrzeć do głównego pliku i **uzyskać dostęp do globalnego obiektu `app.secret_key`** w celu zmiany klucza sekretnego Flask i możliwości [**eskalacji uprawnień** znając ten klucz](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload taki jak ten [z tego opisu](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Użyj tego ładunku, aby **zmienić `app.secret_key`** (nazwa w Twojej aplikacji może być inna), aby móc podpisywać nowe i bardziej uprzywilejowane pliki cookie flask.

### Werkzeug - machine\_id i node uuid

[Z**a pomocą tych ładunków z tego opisu**](https://vozec.fr/writeups/tweedle-dum-dee/) będziesz mógł uzyskać dostęp do **machine\_id** i **uuid** node, które są **głównymi sekretami**, których potrzebujesz do [**generowania pinu Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md), który możesz użyć do uzyskania dostępu do konsoli pythona w `/console`, jeśli **tryb debugowania jest włączony:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Zauważ, że możesz uzyskać **lokalną ścieżkę serwera do pliku `app.py`** generując **błąd** na stronie internetowej, co spowoduje, że **otrzymasz ścieżkę**.
{% endhint %}

Jeśli podatność znajduje się w innym pliku pythona, sprawdź poprzedni trik Flask, aby uzyskać dostęp do obiektów z głównego pliku pythona.

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępniaj sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}

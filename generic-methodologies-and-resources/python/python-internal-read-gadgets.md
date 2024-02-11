# Wewnętrzne narzędzia do odczytu w Pythonie

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowe informacje

Różne podatności, takie jak [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) lub [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), mogą umożliwić **odczyt danych wewnętrznych Pythona, ale nie pozwolą na wykonanie kodu**. Dlatego pentester będzie musiał jak najlepiej wykorzystać te uprawnienia do odczytu, aby **uzyskać poufne uprawnienia i eskalować podatność**.

### Flask - Odczytaj tajny klucz

Główna strona aplikacji Flask prawdopodobnie będzie miała obiekt globalny **`app`**, w którym jest skonfigurowany ten **tajny klucz**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
W tym przypadku możliwe jest uzyskanie dostępu do tego obiektu za pomocą dowolnego gadżetu do **dostępu do globalnych obiektów** z [strony **Omijanie piaskownic Pythona**](bypass-python-sandboxes/).

W przypadku, gdy **podatność występuje w innym pliku Pythona**, potrzebujesz gadżetu do przeglądania plików, aby dotrzeć do głównego pliku i **uzyskać dostęp do globalnego obiektu `app.secret_key`**, aby zmienić klucz tajny Flask i móc [**zwiększyć uprawnienia**, znając ten klucz](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload taki jak ten [z tego opisu](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Użyj tego payloadu, aby **zmienić `app.secret_key`** (nazwa w Twojej aplikacji może być inna), aby móc podpisywać nowe i bardziej uprzywilejowane ciasteczka flask.

### Werkzeug - machine\_id i node uuid

[**Korzystając z tego payloadu z tego writeupu**](https://vozec.fr/writeups/tweedle-dum-dee/) będziesz mógł uzyskać dostęp do **machine\_id** i **uuid** node, które są **głównymi sekretami**, których potrzebujesz do [**wygenerowania pinu Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md), który możesz użyć do uzyskania dostępu do konsoli pythona w `/console`, jeśli **tryb debugowania jest włączony:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Zauważ, że możesz uzyskać **lokalną ścieżkę serwera do pliku `app.py`** generując **błąd** na stronie internetowej, co **uda ci się podać ścieżkę**.
{% endhint %}

Jeśli podatność znajduje się w innym pliku pythona, sprawdź poprzedni trik Flask, aby uzyskać dostęp do obiektów z głównego pliku pythona.

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

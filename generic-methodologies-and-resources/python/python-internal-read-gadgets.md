# Внутрішні гаджети Python

{% hint style="success" %}
Вивчайте та практикуйте хакінг AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте хакінг GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

## Основна інформація

Різні вразливості, такі як [**Рядки формату Python**](bypass-python-sandboxes/#python-format-string) або [**Забруднення класу**](class-pollution-pythons-prototype-pollution.md) можуть дозволити вам **читати внутрішні дані Python, але не дозволять виконувати код**. Тому пентестеру потрібно максимально використовувати ці дозволи на читання, щоб **отримати чутливі привілеї та ескалювати вразливість**.

### Flask - Читання секретного ключа

На головній сторінці додатка Flask, ймовірно, буде **глобальний об'єкт `app`, де цей **секрет налаштований**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
У цьому випадку можливий доступ до цього об'єкту, просто використовуючи будь-який гаджет для **доступу до глобальних об'єктів** зі сторінки [**Bypass Python sandboxes**](bypass-python-sandboxes/).

У випадку, коли **вразливість знаходиться в іншому файлі Python**, вам потрібен гаджет для переходу між файлами, щоб отримати доступ до основного, щоб **отримати доступ до глобального об'єкту `app.secret_key`** для зміни секретного ключа Flask і мати можливість [**підвищення привілеїв** знавши цей ключ](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Пейлоад, подібний до цього [з цього опису](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Використовуйте цей вразливий код для **зміни `app.secret_key`** (назва в вашому додатку може бути іншою), щоб мати можливість підписувати нові та більш привілейовані куки flask.

### Werkzeug - machine\_id та node uuid

[**Використовуючи цей вразливий код з цього опису**](https://vozec.fr/writeups/tweedle-dum-dee/), ви зможете отримати доступ до **machine\_id** та **uuid** вузла, які є **основними секретами**, необхідними для [**генерації піна Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md), який можна використовувати для доступу до консолі Python у `/console`, якщо **увімкнений режим налагодження:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Зверніть увагу, що ви можете отримати **локальний шлях сервера до `app.py`**, спровокувавши деяку **помилку** на веб-сторінці, яка **поверне вам шлях**.
{% endhint %}

Якщо вразливість знаходиться в іншому файлі Python, перевірте попередній трюк Flask для доступу до об'єктів з основного файлу Python.

{% hint style="success" %}
Вивчайте та практикуйте взлом AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте взлом GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

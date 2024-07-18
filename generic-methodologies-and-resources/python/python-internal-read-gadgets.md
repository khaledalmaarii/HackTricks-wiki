# Python Interne Lese-Gadgets

{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
{% endhint %}

## Grundlegende Informationen

Verschiedene Schwachstellen wie [**Python-Formatzeichenfolgen**](bypass-python-sandboxes/#python-format-string) oder [**Klassenverschmutzung**](class-pollution-pythons-prototype-pollution.md) könnten es Ihnen ermöglichen, **interne Python-Daten zu lesen, aber nicht, Code auszuführen**. Daher muss ein Pentester diese Leseberechtigungen bestmöglich nutzen, um **sensible Berechtigungen zu erhalten und die Schwachstelle zu eskalieren**.

### Flask - Geheimen Schlüssel lesen

Die Hauptseite einer Flask-Anwendung wird wahrscheinlich das **`app`**-globale Objekt haben, in dem dieser **Geheimschlüssel konfiguriert ist**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In diesem Fall ist es möglich, auf dieses Objekt zuzugreifen, indem einfach ein Gadget verwendet wird, um **globale Objekte zuzugreifen** von der [**Bypass Python sandboxes page**](bypass-python-sandboxes/).

Im Fall, dass **die Schwachstelle in einer anderen Python-Datei liegt**, benötigen Sie ein Gadget, um Dateien zu durchsuchen, um zur Hauptdatei zu gelangen, um auf das globale Objekt `app.secret_key` zuzugreifen, um den Flask Secret Key zu ändern und in der Lage zu sein, [**Berechtigungen zu eskalieren** und diesen Schlüssel zu kennen](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Ein Payload wie dieser [aus diesem Writeup](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Verwenden Sie dieses Payload, um `app.secret_key` (der Name in Ihrer App könnte anders sein) zu ändern, um neue und mehr Berechtigungen für Flask-Cookies signieren zu können.

### Werkzeug - machine\_id und node uuid

[**Verwenden Sie diese Payload aus diesem Writeup**](https://vozec.fr/writeups/tweedle-dum-dee/), um auf die **machine\_id** und den **uuid**-Knoten zuzugreifen, die die **Hauptgeheimnisse** sind, die Sie benötigen, um [**den Werkzeug-Pin zu generieren**](../../network-services-pentesting/pentesting-web/werkzeug.md), den Sie verwenden können, um auf die Python-Konsole in `/console` zuzugreifen, wenn der **Debug-Modus aktiviert ist:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Beachten Sie, dass Sie den **lokalen Pfad des Servers zur `app.py`** erhalten können, indem Sie auf der Webseite einen **Fehler** erzeugen, der Ihnen den **Pfad gibt**.
{% endhint %}

Wenn die Schwachstelle in einer anderen Python-Datei liegt, überprüfen Sie den vorherigen Flask-Trick, um auf die Objekte aus der Haupt-Python-Datei zuzugreifen.

{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
{% endhint %}

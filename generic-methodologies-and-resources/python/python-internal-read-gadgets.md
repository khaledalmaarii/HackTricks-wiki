# Gadget di Lettura Interna di Python

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

## Informazioni di Base

Diverse vulnerabilità come [**Stringhe di Formato Python**](bypass-python-sandboxes/#python-format-string) o [**Inquinamento di Classe**](class-pollution-pythons-prototype-pollution.md) potrebbero permetterti di **leggere dati interni di Python ma non eseguire codice**. Pertanto, un pentester dovrà sfruttare al massimo queste autorizzazioni di lettura per **ottenere privilegi sensibili ed escalare la vulnerabilità**.

### Flask - Leggere la chiave segreta

La pagina principale di un'applicazione Flask probabilmente avrà l'oggetto globale **`app`** dove questa **chiave segreta è configurata**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In questo caso è possibile accedere a questo oggetto utilizzando qualsiasi gadget per **accedere agli oggetti globali** dalla pagina [**Bypass Python sandboxes**](bypass-python-sandboxes/).

Nel caso in cui **la vulnerabilità si trovi in un file Python diverso**, è necessario un gadget per attraversare i file per arrivare a quello principale e **accedere all'oggetto globale `app.secret_key`** per cambiare la chiave segreta di Flask e poter così [**aumentare i privilegi** conoscendo questa chiave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload come questo [da questo articolo](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Utilizza questo payload per **cambiare `app.secret_key`** (il nome nella tua app potrebbe essere diverso) per poter firmare cookie flask con nuovi e più privilegi.

### Werkzeug - machine\_id e node uuid

[**Utilizzando questi payload da questo articolo**](https://vozec.fr/writeups/tweedle-dum-dee/) sarai in grado di accedere al **machine\_id** e al nodo **uuid**, che sono i **segnreti principali** di cui hai bisogno per [**generare il pin Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) che puoi utilizzare per accedere alla console python in `/console` se la **modalità debug è abilitata:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Nota che puoi ottenere il **percorso locale dei server per il file `app.py`** generando qualche **errore** nella pagina web che ti **fornirà il percorso**.
{% endhint %}

Se la vulnerabilità si trova in un file Python diverso, controlla il trucco Flask precedente per accedere agli oggetti dal file Python principale.

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}

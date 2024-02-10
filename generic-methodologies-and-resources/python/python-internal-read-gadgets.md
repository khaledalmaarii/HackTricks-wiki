# Gadget per la lettura interna di Python

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informazioni di base

Diverse vulnerabilità come [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) o [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) potrebbero consentirti di **leggere i dati interni di Python ma non eseguire il codice**. Pertanto, un pentester dovrà sfruttare al massimo queste autorizzazioni di lettura per **ottenere privilegi sensibili ed elevare la vulnerabilità**.

### Flask - Leggi la chiave segreta

La pagina principale di un'applicazione Flask probabilmente avrà l'oggetto globale **`app`** dove questa **chiave segreta è configurata**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In questo caso è possibile accedere a questo oggetto utilizzando qualsiasi gadget per **accedere agli oggetti globali** dalla [pagina **Bypass Python sandboxes**](bypass-python-sandboxes/).

Nel caso in cui **la vulnerabilità si trovi in un file Python diverso**, è necessario un gadget per attraversare i file e raggiungere quello principale per **accedere all'oggetto globale `app.secret_key`** e cambiare la chiave segreta di Flask, così da poter [**aumentare i privilegi** conoscendo questa chiave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload come questo [da questo writeup](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Utilizza questo payload per **cambiare `app.secret_key`** (il nome nella tua app potrebbe essere diverso) per poter firmare nuovi e più privilegiati cookie flask.

### Werkzeug - machine\_id e node uuid

[**Utilizzando questi payload da questo writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) sarai in grado di accedere al **machine\_id** e all'**uuid** del nodo, che sono i **segnreti principali** di cui hai bisogno per [**generare il pin Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) che puoi utilizzare per accedere alla console python in `/console` se la **modalità di debug è abilitata:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Nota che puoi ottenere il **percorso locale del server per `app.py`** generando qualche **errore** nella pagina web che ti **fornirà il percorso**.
{% endhint %}

Se la vulnerabilità si trova in un file Python diverso, controlla il trucco Flask precedente per accedere agli oggetti dal file Python principale.

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

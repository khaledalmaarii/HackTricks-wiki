# Gadgets de Lecture Interne Python

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Informations de Base

Différentes vulnérabilités telles que les [**Chaines de Format Python**](bypass-python-sandboxes/#python-format-string) ou la [**Pollution de Classe**](class-pollution-pythons-prototype-pollution.md) pourraient vous permettre de **lire des données internes de Python mais ne vous permettront pas d'exécuter du code**. Par conséquent, un testeur d'intrusion devra tirer le meilleur parti de ces autorisations de lecture pour **obtenir des privilèges sensibles et escalader la vulnérabilité**.

### Flask - Lire la clé secrète

La page principale d'une application Flask aura probablement l'objet global **`app`** où ce **secret est configuré**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Dans ce cas, il est possible d'accéder à cet objet en utilisant simplement n'importe quel gadget pour **accéder aux objets globaux** de la [**page de contournement des sandbox Python**](bypass-python-sandboxes/).

Dans le cas où **la vulnérabilité se trouve dans un fichier Python différent**, vous avez besoin d'un gadget pour parcourir les fichiers pour accéder à celui principal afin de **accéder à l'objet global `app.secret_key`** pour changer la clé secrète de Flask et être en mesure de [**escalader les privilèges** en connaissant cette clé](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Une charge utile comme celle-ci [de ce writeup](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Utilisez cette charge utile pour **changer `app.secret_key`** (le nom dans votre application peut être différent) afin de pouvoir signer de nouveaux cookies flask avec plus de privilèges.

### Werkzeug - machine\_id et node uuid

[**En utilisant cette charge utile de ce writeup**](https://vozec.fr/writeups/tweedle-dum-dee/), vous pourrez accéder à **machine\_id** et à l'**uuid** du nœud, qui sont les **secrets principaux** dont vous avez besoin pour [**générer le code pin Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) que vous pouvez utiliser pour accéder à la console Python dans `/console` si le **mode de débogage est activé:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Notez que vous pouvez obtenir le **chemin local des serveurs vers le fichier `app.py`** en générant une **erreur** sur la page web qui vous **donnera le chemin**.
{% endhint %}

Si la vulnérabilité se trouve dans un fichier python différent, vérifiez l'astuce Flask précédente pour accéder aux objets depuis le fichier python principal.

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

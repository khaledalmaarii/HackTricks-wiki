# Gadgets de Leitura Interna do Python

{% hint style="success" %}
Aprenda e pratique Hacking na AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Treinamento AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking no GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Treinamento GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Informações Básicas

Diferentes vulnerabilidades como [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) ou [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) podem permitir que você **leia dados internos do Python, mas não permitirão que você execute código**. Portanto, um pentester precisará aproveitar ao máximo essas permissões de leitura para **obter privilégios sensíveis e escalar a vulnerabilidade**.

### Flask - Ler chave secreta

A página principal de uma aplicação Flask provavelmente terá o objeto global **`app`** onde esta **chave secreta é configurada**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Neste caso, é possível acessar este objeto apenas usando qualquer gadget para **acessar objetos globais** da página [**Bypass Python sandboxes**](bypass-python-sandboxes/).

No caso em que **a vulnerabilidade está em um arquivo Python diferente**, você precisa de um gadget para percorrer arquivos para chegar ao principal e **acessar o objeto global `app.secret_key`** para alterar a chave secreta do Flask e ser capaz de [**elevar privilégios** conhecendo esta chave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Uma carga útil como esta [deste artigo](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Use este payload para **alterar `app.secret_key`** (o nome em seu aplicativo pode ser diferente) para poder assinar novos e mais privilégios cookies flask.

### Werkzeug - machine\_id e node uuid

[**Usando este payload deste artigo**](https://vozec.fr/writeups/tweedle-dum-dee/) você será capaz de acessar o **machine\_id** e o nó **uuid**, que são os **segredos principais** que você precisa para [**gerar o pin Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) que você pode usar para acessar o console python em `/console` se o **modo de depuração estiver habilitado:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Note que você pode obter o **caminho local dos servidores para o `app.py`** gerando algum **erro** na página da web que irá **mostrar o caminho**.
{% endhint %}

Se a vulnerabilidade estiver em um arquivo Python diferente, verifique o truque anterior do Flask para acessar os objetos do arquivo Python principal.

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

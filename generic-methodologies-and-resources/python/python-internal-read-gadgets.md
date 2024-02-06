# Gadgets de Leitura Interna do Python

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

## Informações Básicas

Diferentes vulnerabilidades como [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) ou [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) podem permitir que você **leia dados internos do Python, mas não permitirão que você execute código**. Portanto, um pentester precisará aproveitar ao máximo essas permissões de leitura para **obter privilégios sensíveis e escalar a vulnerabilidade**.

### Flask - Ler chave secreta

A página principal de uma aplicação Flask provavelmente terá o objeto global **`app`** onde este **segredo é configurado**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Neste caso, é possível acessar este objeto apenas usando qualquer gadget para **acessar objetos globais** da página [**Bypass Python sandboxes**](bypass-python-sandboxes/).

No caso em que **a vulnerabilidade está em um arquivo Python diferente**, você precisa de um gadget para percorrer os arquivos e chegar ao principal para **acessar o objeto global `app.secret_key`** para alterar a chave secreta do Flask e ser capaz de [**escalar privilégios** conhecendo essa chave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Uma carga útil como esta [deste writeup](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Use este payload para **alterar `app.secret_key`** (o nome em seu aplicativo pode ser diferente) para poder assinar novos e mais privilégios cookies flask.

### Werkzeug - machine\_id e node uuid

[**Usando esses payloads deste writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) você será capaz de acessar o **machine\_id** e o nó **uuid**, que são os **segredos principais** que você precisa para [**gerar o pin Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) que você pode usar para acessar o console python em `/console` se o **modo de depuração estiver habilitado:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Note que você pode obter o **caminho local dos servidores para o `app.py`** gerando algum **erro** na página da web que irá **mostrar o caminho**.
{% endhint %}

Se a vulnerabilidade estiver em um arquivo Python diferente, verifique o truque anterior do Flask para acessar os objetos do arquivo Python principal.

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

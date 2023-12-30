# Python Internal Read Gadgets

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

Diferentes vulnerabilidades como [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) ou [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) podem permitir que você **leia dados internos do Python, mas não permitirão que você execute código**. Portanto, um pentester precisará aproveitar ao máximo essas permissões de leitura para **obter privilégios sensíveis e escalar a vulnerabilidade**.

### Flask - Ler chave secreta

A página principal de uma aplicação Flask provavelmente terá o objeto global **`app`** onde essa **chave secreta é configurada**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Neste caso, é possível acessar este objeto apenas usando qualquer gadget para **acessar objetos globais** da [**página Bypass Python sandboxes**](bypass-python-sandboxes/).

No caso em que **a vulnerabilidade está em um arquivo python diferente**, você precisa de um gadget para percorrer arquivos até chegar ao principal para **acessar o objeto global `app.secret_key`** para alterar a chave secreta do Flask e poder [**escalar privilégios conhecendo esta chave**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Um payload como este [deste writeup](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Use este payload para **alterar `app.secret_key`** (o nome em seu aplicativo pode ser diferente) para poder assinar novos cookies flask com mais privilégios.

### Werkzeug - machine\_id e node uuid

[**Usando estes payloads deste artigo**](https://vozec.fr/writeups/tweedle-dum-dee/) você poderá acessar o **machine\_id** e o **uuid** do nó, que são os **principais segredos** necessários para [**gerar o pin do Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) que você pode usar para acessar o console python em `/console` se o **modo de depuração estiver ativado:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Observe que você pode obter o **caminho local do servidor para o `app.py`** gerando algum **erro** na página web que irá **fornecer o caminho**.
{% endhint %}

Se a vulnerabilidade estiver em um arquivo python diferente, verifique o truque anterior do Flask para acessar os objetos do arquivo python principal.

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

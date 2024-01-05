# Bypasses do Sandbox do macOS Office

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Bypass do Sandbox do Word via Launch Agents

O aplicativo usa um **Sandbox personalizado** com o entitlement **`com.apple.security.temporary-exception.sbpl`** e este sandbox personalizado permite escrever arquivos em qualquer lugar, desde que o nome do arquivo comece com `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Portanto, a fuga foi tão fácil quanto **escrever um `plist`** LaunchAgent em `~/Library/LaunchAgents/~$escape.plist`.

Confira o [**relatório original aqui**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Bypass do Sandbox do Word via Login Items e zip

Lembre-se que, a partir da primeira fuga, o Word pode escrever arquivos arbitrários cujo nome comece com `~$`, embora após o patch da vulnerabilidade anterior não fosse mais possível escrever em `/Library/Application Scripts` ou em `/Library/LaunchAgents`.

Foi descoberto que, a partir de dentro do sandbox, é possível criar um **Login Item** (aplicativos que serão executados quando o usuário fizer login). No entanto, esses aplicativos **não serão executados a menos que** sejam **notarizados** e **não é possível adicionar argumentos** (então você não pode simplesmente executar um shell reverso usando **`bash`**).

A partir do bypass anterior do Sandbox, a Microsoft desativou a opção de escrever arquivos em `~/Library/LaunchAgents`. No entanto, foi descoberto que, se você colocar um **arquivo zip como um Login Item**, o `Archive Utility` simplesmente **descompactará** no local atual. Então, porque por padrão a pasta `LaunchAgents` de `~/Library` não é criada, foi possível **zipar um plist em `LaunchAgents/~$escape.plist`** e **colocar** o arquivo zip em **`~/Library`** para que, ao descompactar, ele alcance o destino de persistência.

Confira o [**relatório original aqui**](https://objective-see.org/blog/blog\_0x4B.html).

### Bypass do Sandbox do Word via Login Items e .zshenv

(Lembre-se que, a partir da primeira fuga, o Word pode escrever arquivos arbitrários cujo nome comece com `~$`).

No entanto, a técnica anterior tinha uma limitação, se a pasta **`~/Library/LaunchAgents`** existisse porque algum outro software a criou, ela falharia. Então, foi descoberta uma cadeia diferente de Login Items para isso.

Um atacante poderia criar os arquivos **`.bash_profile`** e **`.zshenv`** com o payload para executar e, em seguida, zipá-los e **escrever o zip na pasta do usuário vítima**: **`~/~$escape.zip`**.

Em seguida, adicionar o arquivo zip aos **Login Items** e depois o aplicativo **`Terminal`**. Quando o usuário fizer login novamente, o arquivo zip será descompactado na pasta do usuário, sobrescrevendo **`.bash_profile`** e **`.zshenv`** e, portanto, o terminal executará um desses arquivos (dependendo se bash ou zsh é usado).

Confira o [**relatório original aqui**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Bypass do Sandbox do Word com Open e variáveis de ambiente

De processos em sandbox ainda é possível invocar outros processos usando a utilidade **`open`**. Além disso, esses processos serão executados **dentro de seu próprio sandbox**.

Foi descoberto que a utilidade open tem a opção **`--env`** para executar um aplicativo com variáveis de ambiente **específicas**. Portanto, foi possível criar o arquivo **`.zshenv`** dentro de uma pasta **dentro** do **sandbox** e usar `open` com `--env` definindo a variável **`HOME`** para essa pasta abrindo o aplicativo `Terminal`, que executará o arquivo `.zshenv` (por algum motivo também foi necessário definir a variável `__OSINSTALL_ENVIROMENT`).

Confira o [**relatório original aqui**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Bypass do Sandbox do Word com Open e stdin

A utilidade **`open`** também suportava o parâmetro **`--stdin`** (e após o bypass anterior não era mais possível usar `--env`).

O fato é que mesmo que **`python`** fosse assinado pela Apple, ele **não executaria** um script com o atributo **`quarantine`**. No entanto, era possível passar um script via stdin para que ele não verificasse se estava em quarentena ou não:

1. Solte um arquivo **`~$exploit.py`** com comandos Python arbitrários.
2. Execute _open_ **`–stdin='~$exploit.py' -a Python`**, que executa o aplicativo Python com nosso arquivo solto servindo como sua entrada padrão. Python executa nosso código com satisfação, e como é um processo filho do _launchd_, ele não está vinculado às regras do sandbox do Word.

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

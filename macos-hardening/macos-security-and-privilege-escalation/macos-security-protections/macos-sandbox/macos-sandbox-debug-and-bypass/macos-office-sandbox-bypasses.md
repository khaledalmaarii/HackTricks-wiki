# Bypasses de Sandbox do Office no macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

### Bypass de Sandbox do Word via Agentes de Inicialização

A aplicação utiliza um **Sandbox personalizado** usando a permissão **`com.apple.security.temporary-exception.sbpl`** e este sandbox personalizado permite escrever arquivos em qualquer lugar desde que o nome do arquivo comece com `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Portanto, escapar foi tão fácil quanto **escrever um arquivo `plist`** LaunchAgent em `~/Library/LaunchAgents/~$escape.plist`.

Confira o [**relatório original aqui**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Bypass de Sandbox do Word via Itens de Login e zip

Lembre-se de que a partir da primeira fuga, o Word pode escrever arquivos arbitrários cujo nome começa com `~$`, embora após o patch da vulnerabilidade anterior não fosse possível escrever em `/Library/Application Scripts` ou em `/Library/LaunchAgents`.

Foi descoberto que de dentro do sandbox é possível criar um **Item de Login** (aplicativos que serão executados quando o usuário fizer login). No entanto, esses aplicativos **não serão executados a menos que** sejam **notarizados** e não é **possível adicionar argumentos** (então você não pode simplesmente executar um shell reverso usando **`bash`**).

A partir da fuga anterior do Sandbox, a Microsoft desabilitou a opção de escrever arquivos em `~/Library/LaunchAgents`. No entanto, foi descoberto que se você colocar um **arquivo zip como um Item de Login** o `Archive Utility` simplesmente irá descompactá-lo em sua localização atual. Assim, porque por padrão a pasta `LaunchAgents` de `~/Library` não é criada, foi possível **compactar um plist em `LaunchAgents/~$escape.plist`** e **colocar** o arquivo zip em **`~/Library`** para que ao descompactá-lo alcance o destino de persistência.

Confira o [**relatório original aqui**](https://objective-see.org/blog/blog\_0x4B.html).

### Bypass de Sandbox do Word via Itens de Login e .zshenv

(Lembre-se de que a partir da primeira fuga, o Word pode escrever arquivos arbitrários cujo nome começa com `~$`).

No entanto, a técnica anterior tinha uma limitação, se a pasta **`~/Library/LaunchAgents`** existisse porque algum outro software a criou, falharia. Então foi descoberta uma cadeia de Itens de Login diferente para isso.

Um atacante poderia criar os arquivos **`.bash_profile`** e **`.zshenv`** com o payload para executar e então compactá-los e **escrever o zip na pasta do usuário** vítima: **`~/~$escape.zip`**.

Em seguida, adicione o arquivo zip aos **Itens de Login** e depois ao aplicativo **`Terminal`**. Quando o usuário fizer login novamente, o arquivo zip será descompactado nos arquivos do usuário, sobrescrevendo **`.bash_profile`** e **`.zshenv`** e, portanto, o terminal executará um desses arquivos (dependendo se bash ou zsh é usado).

Confira o [**relatório original aqui**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Bypass de Sandbox do Word com Open e variáveis de ambiente

De processos em sandbox ainda é possível invocar outros processos usando o utilitário **`open`**. Além disso, esses processos serão executados **dentro de seu próprio sandbox**.

Foi descoberto que o utilitário open tem a opção **`--env`** para executar um aplicativo com **variáveis de ambiente específicas**. Portanto, foi possível criar o arquivo **`.zshenv` dentro de uma pasta** **dentro** do **sandbox** e usar `open` com `--env` configurando a variável **`HOME`** para essa pasta abrindo o aplicativo `Terminal`, que executará o arquivo `.zshenv` (por algum motivo também foi necessário definir a variável `__OSINSTALL_ENVIROMENT`).

Confira o [**relatório original aqui**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Bypass de Sandbox do Word com Open e stdin

O utilitário **`open`** também suportava o parâmetro **`--stdin`** (e após a fuga anterior não era mais possível usar `--env`).

A questão é que mesmo que o **`python`** fosse assinado pela Apple, ele **não executará** um script com o atributo **`quarantine`**. No entanto, era possível passar a ele um script do stdin para que não verificasse se estava em quarentena ou não:&#x20;

1. Deixe um arquivo **`~$exploit.py`** com comandos Python arbitrários.
2. Execute _open_ **`–stdin='~$exploit.py' -a Python`**, que executa o aplicativo Python com nosso arquivo deixado servindo como sua entrada padrão. O Python executa nosso código tranquilamente e, como é um processo filho do _launchd_, não está vinculado às regras de sandbox do Word.

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

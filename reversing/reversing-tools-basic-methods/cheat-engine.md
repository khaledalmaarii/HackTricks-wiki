# Cheat Engine

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes são salvos na memória de um jogo em execução e alterá-los.\
Quando você o baixa e o executa, você é **apresentado** a um **tutorial** de como usar a ferramenta. Se você deseja aprender a usar a ferramenta, é altamente recomendável completá-lo.

## O que você está procurando?

![](<../../.gitbook/assets/image (762).png>)

Esta ferramenta é muito útil para encontrar **onde algum valor** (geralmente um número) **está armazenado na memória** de um programa.\
**Geralmente números** são armazenados em formato de **4 bytes**, mas você também pode encontrá-los em formatos **double** ou **float**, ou talvez queira procurar por algo **diferente de um número**. Por esse motivo, você precisa ter certeza de que selecionou o que deseja **procurar**:

![](<../../.gitbook/assets/image (324).png>)

Também é possível indicar **diferentes** tipos de **buscas**:

![](<../../.gitbook/assets/image (311).png>)

Você também pode marcar a caixa para **parar o jogo enquanto escaneia a memória**:

![](<../../.gitbook/assets/image (1052).png>)

### Atalhos

Em _**Edit --> Settings --> Hotkeys**_ você pode definir diferentes **atalhos** para diferentes propósitos, como **parar** o **jogo** (o que é bastante útil se em algum momento você quiser escanear a memória). Outras opções estão disponíveis:

![](<../../.gitbook/assets/image (864).png>)

## Modificando o valor

Uma vez que você **encontrou** onde está o **valor** que está **procurando** (mais sobre isso nos próximos passos), você pode **modificá-lo** clicando duas vezes nele e, em seguida, clicando duas vezes em seu valor:

![](<../../.gitbook/assets/image (563).png>)

E finalmente **marcando a caixa** para que a modificação seja feita na memória:

![](<../../.gitbook/assets/image (385).png>)

A **alteração** na **memória** será imediatamente **aplicada** (observe que até que o jogo não use esse valor novamente, o valor **não será atualizado no jogo**).

## Procurando o valor

Então, vamos supor que há um valor importante (como a vida do seu usuário) que você deseja melhorar, e você está procurando por esse valor na memória)

### Através de uma mudança conhecida

Supondo que você está procurando o valor 100, você **realiza uma varredura** procurando por esse valor e encontra muitas coincidências:

![](<../../.gitbook/assets/image (108).png>)

Em seguida, faça algo para que o **valor mude**, e **pare** o jogo e **realize** uma **próxima varredura**:

![](<../../.gitbook/assets/image (684).png>)

O Cheat Engine procurará pelos **valores** que **passaram de 100 para o novo valor**. Parabéns, você **encontrou** o **endereço** do valor que estava procurando, agora você pode modificá-lo.\
_Se você ainda tiver vários valores, faça algo para modificar novamente esse valor e realize outra "próxima varredura" para filtrar os endereços._

### Valor Desconhecido, mudança conhecida

No cenário em que você **não conhece o valor** mas sabe **como fazê-lo mudar** (e até o valor da mudança) você pode procurar pelo seu número.

Portanto, comece realizando uma varredura do tipo "**Valor inicial desconhecido**":

![](<../../.gitbook/assets/image (890).png>)

Em seguida, faça a mudança do valor, indique **como** o **valor mudou** (no meu caso foi diminuído em 1) e realize uma **próxima varredura**:

![](<../../.gitbook/assets/image (371).png>)

Você verá **todos os valores que foram modificados da maneira selecionada**:

![](<../../.gitbook/assets/image (569).png>)

Depois de encontrar seu valor, você pode modificá-lo.

Observe que há **muitas mudanças possíveis** e você pode fazer esses **passos quantas vezes quiser** para filtrar os resultados:

![](<../../.gitbook/assets/image (574).png>)

### Endereço de Memória Aleatório - Encontrando o código

Até agora aprendemos como encontrar um endereço que armazena um valor, mas é altamente provável que em **diferentes execuções do jogo esse endereço esteja em lugares diferentes da memória**. Então vamos descobrir como sempre encontrar esse endereço.

Usando alguns dos truques mencionados, encontre o endereço onde seu jogo atual está armazenando o valor importante. Em seguida (parando o jogo se desejar) faça um **clique direito** no **endereço** encontrado e selecione "**Descobrir o que acessa este endereço**" ou "**Descobrir o que escreve neste endereço**":

![](<../../.gitbook/assets/image (1067).png>)

A **primeira opção** é útil para saber quais **partes** do **código** estão **usando** este **endereço** (o que é útil para mais coisas como **saber onde você pode modificar o código** do jogo).\
A **segunda opção** é mais **específica**, e será mais útil neste caso, pois estamos interessados em saber **de onde este valor está sendo escrito**.

Depois de selecionar uma dessas opções, o **depurador** será **anexado** ao programa e uma nova **janela vazia** aparecerá. Agora, **jogue** o **jogo** e **modifique** esse **valor** (sem reiniciar o jogo). A **janela** deve ser **preenchida** com os **endereços** que estão **modificando** o **valor**:

![](<../../.gitbook/assets/image (91).png>)

Agora que você encontrou o endereço que está modificando o valor, você pode **modificar o código ao seu gosto** (o Cheat Engine permite que você o modifique para NOPs rapidamente):

![](<../../.gitbook/assets/image (1057).png>)

Portanto, agora você pode modificá-lo para que o código não afete seu número, ou sempre afete de forma positiva.
### Endereço de Memória Aleatório - Encontrando o ponteiro

Seguindo os passos anteriores, encontre onde está o valor de seu interesse. Em seguida, usando "**Descobrir o que escreve neste endereço**" descubra qual endereço escreve esse valor e clique duas vezes nele para obter a visualização da desmontagem:

![](<../../.gitbook/assets/image (1039).png>)

Depois, realize uma nova pesquisa **procurando pelo valor hexadecimal entre "\[]"** (o valor de $edx neste caso):

![](<../../.gitbook/assets/image (994).png>)

(_Se vários aparecerem, geralmente você precisa escolher o menor endereço_)\
Agora, encontramos o **ponteiro que estará modificando o valor de nosso interesse**.

Clique em "**Adicionar Endereço Manualmente**":

![](<../../.gitbook/assets/image (990).png>)

Agora, marque a caixa de seleção "Ponteiro" e adicione o endereço encontrado na caixa de texto (neste cenário, o endereço encontrado na imagem anterior foi "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (392).png>)

(Observe como o primeiro "Endereço" é preenchido automaticamente com o endereço do ponteiro que você inseriu)

Clique em OK e um novo ponteiro será criado:

![](<../../.gitbook/assets/image (308).png>)

Agora, toda vez que você modificar esse valor, estará **modificando o valor importante mesmo que o endereço de memória onde o valor está seja diferente**.

### Injeção de Código

A injeção de código é uma técnica onde você injeta um trecho de código no processo alvo e, em seguida, redireciona a execução do código para passar pelo seu próprio código escrito (como dar pontos em vez de subtrair).

Então, imagine que você encontrou o endereço que está subtraindo 1 da vida do seu jogador:

![](<../../.gitbook/assets/image (203).png>)

Clique em Mostrar desmontador para obter o **código desmontado**.\
Em seguida, clique em **CTRL+a** para invocar a janela de Auto montagem e selecione _**Modelo --> Injeção de Código**_

![](<../../.gitbook/assets/image (902).png>)

Preencha o **endereço da instrução que deseja modificar** (isso geralmente é preenchido automaticamente):

![](<../../.gitbook/assets/image (744).png>)

Um modelo será gerado:

![](<../../.gitbook/assets/image (944).png>)

Então, insira seu novo código de montagem na seção "**newmem**" e remova o código original de "**originalcode**" se não quiser que ele seja executado\*\*.\*\* Neste exemplo, o código injetado adicionará 2 pontos em vez de subtrair 1:

![](<../../.gitbook/assets/image (521).png>)

**Clique em executar e assim por diante, e seu código deve ser injetado no programa alterando o comportamento da funcionalidade!**

## **Referências**

* **Tutorial do Cheat Engine, complete-o para aprender como começar com o Cheat Engine**

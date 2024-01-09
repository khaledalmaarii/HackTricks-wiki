<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) é um programa útil para encontrar onde valores importantes estão salvos na memória de um jogo em execução e alterá-los.\
Quando você baixa e executa, é **apresentado** um **tutorial** de como usar a ferramenta. Se você quer aprender a usar a ferramenta, é altamente recomendado completá-lo.

# O que você está procurando?

![](<../../.gitbook/assets/image (580).png>)

Esta ferramenta é muito útil para encontrar **onde algum valor** (geralmente um número) **está armazenado na memória** de um programa.\
**Geralmente números** são armazenados em forma de **4bytes**, mas você também pode encontrá-los em formatos **double** ou **float**, ou pode querer procurar por algo **diferente de um número**. Por isso, você precisa ter certeza de **selecionar** o que deseja **procurar**:

![](<../../.gitbook/assets/image (581).png>)

Também é possível indicar **diferentes** tipos de **buscas**:

![](<../../.gitbook/assets/image (582).png>)

Você também pode marcar a caixa para **parar o jogo enquanto escaneia a memória**:

![](<../../.gitbook/assets/image (584).png>)

## Atalhos

Em _**Editar --> Configurações --> Atalhos**_ você pode definir diferentes **atalhos** para diferentes propósitos, como **parar** o **jogo** (o que é bastante útil se em algum momento você quiser escanear a memória). Outras opções estão disponíveis:

![](<../../.gitbook/assets/image (583).png>)

# Modificando o valor

Uma vez que você **encontrou** onde está o **valor** que está **procurando** (mais sobre isso nos próximos passos), você pode **modificá-lo** clicando duas vezes nele, e depois clicando duas vezes no seu valor:

![](<../../.gitbook/assets/image (585).png>)

E finalmente **marcando a caixa** para realizar a modificação na memória:

![](<../../.gitbook/assets/image (586).png>)

A **mudança** na **memória** será imediatamente **aplicada** (note que até o jogo não usar esse valor novamente, o valor **não será atualizado no jogo**).

# Procurando o valor

Então, vamos supor que há um valor importante (como a vida do seu usuário) que você quer melhorar, e você está procurando por esse valor na memória)

## Através de uma mudança conhecida

Supondo que você está procurando pelo valor 100, você **realiza uma varredura** procurando por esse valor e encontra muitas coincidências:

![](<../../.gitbook/assets/image (587).png>)

Então, você faz algo para que **o valor mude**, e você **para** o jogo e **realiza** uma **nova varredura**:

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine procurará pelos **valores** que **mudaram de 100 para o novo valor**. Parabéns, você **encontrou** o **endereço** do valor que estava procurando, agora você pode modificá-lo.\
_Se você ainda tem vários valores, faça algo para modificar novamente esse valor, e realize outra "nova varredura" para filtrar os endereços._

## Valor Desconhecido, mudança conhecida

No cenário em que você **não conhece o valor** mas sabe **como fazê-lo mudar** (e até o valor da mudança), você pode procurar pelo seu número.

Então, comece realizando uma varredura do tipo "**Valor inicial desconhecido**":

![](<../../.gitbook/assets/image (589).png>)

Depois, faça o valor mudar, indique **como** o **valor** **mudou** (no meu caso, diminuiu em 1) e realize uma **nova varredura**:

![](<../../.gitbook/assets/image (590).png>)

Você será apresentado **todos os valores que foram modificados da maneira selecionada**:

![](<../../.gitbook/assets/image (591).png>)

Uma vez que você encontrou seu valor, você pode modificá-lo.

Note que há **muitas possíveis mudanças** e você pode fazer esses **passos quantas vezes quiser** para filtrar os resultados:

![](<../../.gitbook/assets/image (592).png>)

## Endereço de Memória Aleatório - Encontrando o código

Até agora aprendemos como encontrar um endereço que armazena um valor, mas é muito provável que em **diferentes execuções do jogo esse endereço esteja em diferentes lugares da memória**. Então vamos descobrir como sempre encontrar esse endereço.

Usando algumas das técnicas mencionadas, encontre o endereço onde seu jogo atual está armazenando o valor importante. Então (parando o jogo se desejar) faça um **clique com o botão direito** no **endereço** encontrado e selecione "**Descobrir o que acessa este endereço**" ou "**Descobrir o que escreve neste endereço**":

![](<../../.gitbook/assets/image (593).png>)

A **primeira opção** é útil para saber quais **partes** do **código** estão **usando** este **endereço** (o que é útil para mais coisas como **saber onde você pode modificar o código** do jogo).\
A **segunda opção** é mais **específica**, e será mais útil neste caso, pois estamos interessados em saber **de onde esse valor está sendo escrito**.

Uma vez que você selecionou uma dessas opções, o **debugger** será **anexado** ao programa e uma nova **janela vazia** aparecerá. Agora, **jogue** o **jogo** e **modifique** esse **valor** (sem reiniciar o jogo). A **janela** deve ser **preenchida** com os **endereços** que estão **modificando** o **valor**:

![](<../../.gitbook/assets/image (594).png>)

Agora que você encontrou o endereço que está modificando o valor, você pode **modificar o código ao seu prazer** (Cheat Engine permite que você modifique rapidamente para NOPs):

![](<../../.gitbook/assets/image (595).png>)

Assim, você pode agora modificá-lo para que o código não afete seu número, ou sempre afete de maneira positiva.

## Endereço de Memória Aleatório - Encontrando o ponteiro

Seguindo os passos anteriores, encontre onde o valor que lhe interessa está. Então, usando "**Descobrir o que escreve neste endereço**", descubra qual endereço escreve este valor e clique duas vezes nele para obter a visão de desmontagem:

![](<../../.gitbook/assets/image (596).png>)

Então, realize uma nova varredura **procurando pelo valor hex entre "\[]"** (o valor de $edx neste caso):

![](<../../.gitbook/assets/image (597).png>)

(_Se vários aparecerem, geralmente você precisa do endereço menor_)\
Agora, nós t**emos encontrado o ponteiro que modificará o valor que nos interessa**.

Clique em "**Adicionar Endereço Manualmente**":

![](<../../.gitbook/assets/image (598).png>)

Agora, clique na caixa "Ponteiro" e adicione o endereço encontrado na caixa de texto (neste cenário, o endereço encontrado na imagem anterior foi "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (599).png>)

(Note como o primeiro "Endereço" é automaticamente preenchido a partir do endereço do ponteiro que você introduz)

Clique em OK e um novo ponteiro será criado:

![](<../../.gitbook/assets/image (600).png>)

Agora, toda vez que você modifica esse valor, você está **modificando o valor importante mesmo que o endereço de memória onde o valor está seja diferente.**

## Injeção de Código

Injeção de código é uma técnica onde você injeta um pedaço de código no processo alvo, e então redireciona a execução do código para passar pelo seu próprio código escrito (como dar pontos em vez de subtrair).

Então, imagine que você encontrou o endereço que está subtraindo 1 da vida do seu jogador:

![](<../../.gitbook/assets/image (601).png>)

Clique em Mostrar desmontagem para obter o **código desmontado**.\
Depois, clique **CTRL+a** para invocar a janela de montagem automática e selecione _**Template --> Injeção de Código**_

![](<../../.gitbook/assets/image (602).png>)

Preencha o **endereço da instrução que você quer modificar** (isso geralmente é preenchido automaticamente):

![](<../../.gitbook/assets/image (603).png>)

Um template será gerado:

![](<../../.gitbook/assets/image (604).png>)

Então, insira seu novo código assembly na seção "**newmem**" e remova o código original da seção "**originalcode**" se você não quiser que ele seja executado**.** Neste exemplo, o código injetado adicionará 2 pontos em vez de subtrair 1:

![](<../../.gitbook/assets/image (605).png>)

**Clique em executar e assim por diante e seu código será injetado no programa, mudando o comportamento da funcionalidade!**

# **Referências**

* **Tutorial do Cheat Engine, complete-o para aprender como começar com o Cheat Engine**



<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

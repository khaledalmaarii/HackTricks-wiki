# Rádio

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)é um analisador de sinal digital gratuito para GNU/Linux e macOS, projetado para extrair informações de sinais de rádio desconhecidos. Ele suporta uma variedade de dispositivos SDR através do SoapySDR e permite a demodulação ajustável de sinais FSK, PSK e ASK, decodificação de vídeo analógico, análise de sinais intermitentes e escuta de canais de voz analógicos (tudo em tempo real).

### Configuração Básica

Após a instalação, há algumas coisas que você pode considerar configurar.\
Nas configurações (o segundo botão da guia) você pode selecionar o **dispositivo SDR** ou **selecionar um arquivo** para ler e qual frequência sintonizar e a taxa de amostragem (recomendado até 2,56Msps se o seu PC suportar)\\

![](<../../.gitbook/assets/image (655) (1).png>)

No comportamento da GUI, é recomendável habilitar algumas coisas se o seu PC suportar:

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
Se perceber que seu PC não está capturando coisas, tente desativar o OpenGL e diminuir a taxa de amostragem.
{% endhint %}

### Usos

* Apenas para **capturar algum tempo de um sinal e analisá-lo**, mantenha pressionado o botão "Push to capture" pelo tempo que precisar.

![](<../../.gitbook/assets/image (631).png>)

* O **Sintonizador** do SigDigger ajuda a **capturar melhores sinais** (mas também pode degradá-los). Idealmente comece com 0 e continue **aumentando até** encontrar o **ruído** introduzido ser **maior** do que a **melhoria do sinal** que você precisa).

![](<../../.gitbook/assets/image (658).png>)

### Sincronizar com o canal de rádio

Com [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sincronize com o canal que deseja ouvir, configure a opção "Baseband audio preview", configure a largura de banda para obter todas as informações sendo enviadas e em seguida ajuste o Sintonizador para o nível antes do ruído realmente começar a aumentar:

![](<../../.gitbook/assets/image (389).png>)

## Truques Interessantes

* Quando um dispositivo está enviando rajadas de informações, geralmente a **primeira parte será um preâmbulo** para que você **não precise se preocupar** se **não encontrar informações** lá **ou se houver alguns erros**.
* Em quadros de informações, geralmente você deve **encontrar diferentes quadros bem alinhados entre si**:

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **Depois de recuperar os bits, você pode precisar processá-los de alguma forma**. Por exemplo, na codificação Manchester, um para cima+para baixo será um 1 ou 0 e um para baixo+para cima será o outro. Portanto, pares de 1s e 0s (para cima e para baixo) serão um 1 real ou um 0 real.
* Mesmo se um sinal estiver usando a codificação Manchester (é impossível encontrar mais de dois 0s ou 1s seguidos), você pode **encontrar vários 1s ou 0s juntos no preâmbulo**!

### Descobrindo o tipo de modulação com IQ

Existem 3 maneiras de armazenar informações em sinais: Modulando a **amplitude**, **frequência** ou **fase**.\
Se você está verificando um sinal, existem diferentes maneiras de tentar descobrir o que está sendo usado para armazenar informações (encontre mais maneiras abaixo), mas uma boa é verificar o gráfico IQ.

![](<../../.gitbook/assets/image (630).png>)

* **Detectando AM**: Se no gráfico IQ aparecer, por exemplo, **2 círculos** (provavelmente um em 0 e outro em uma amplitude diferente), pode significar que este é um sinal AM. Isso ocorre porque no gráfico IQ a distância entre o 0 e o círculo é a amplitude do sinal, então é fácil visualizar diferentes amplitudes sendo usadas.
* **Detectando PM**: Como na imagem anterior, se você encontrar pequenos círculos não relacionados entre si, provavelmente significa que uma modulação de fase está sendo usada. Isso ocorre porque no gráfico IQ, o ângulo entre o ponto e o 0,0 é a fase do sinal, o que significa que 4 fases diferentes estão sendo usadas.
* Note que se a informação estiver oculta no fato de que uma fase é alterada e não na fase em si, você não verá diferentes fases claramente diferenciadas.
* **Detectando FM**: IQ não tem um campo para identificar frequências (a distância para o centro é amplitude e o ângulo é fase).\
Portanto, para identificar FM, você deve **ver basicamente um círculo** neste gráfico.\
Além disso, uma frequência diferente é "representada" pelo gráfico IQ por uma **aceleração de velocidade em torno do círculo** (então no SysDigger selecionando o sinal o gráfico IQ é preenchido, se você encontrar uma aceleração ou mudança de direção no círculo criado, pode significar que é FM):

## Exemplo de AM

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Descobrindo AM

#### Verificando o envelope

Verificando informações AM com [**SigDigger** ](https://github.com/BatchDrake/SigDigger)e apenas olhando o **envelope**, você pode ver diferentes níveis claros de amplitude. O sinal usado está enviando pulsos com informações em AM, assim é como um pulso se parece:

![](<../../.gitbook/assets/image (636).png>)

E assim é como parte do símbolo se parece com a forma de onda:

![](<../../.gitbook/assets/image (650) (1).png>)

#### Verificando o Histograma

Você pode **selecionar todo o sinal** onde as informações estão localizadas, selecionar o modo **Amplitude** e **Seleção** e clicar em **Histograma**. Você pode observar que são encontrados apenas 2 níveis claros

![](<../../.gitbook/assets/image (647) (1) (1).png>)

Por exemplo, se você selecionar Frequência em vez de Amplitude neste sinal AM, você encontrará apenas 1 frequência (não há como a informação modulada em frequência estar usando apenas 1 freq).

![](<../../.gitbook/assets/image (637) (1) (1).png>)

Se você encontrar muitas frequências, potencialmente isso não será FM, provavelmente a frequência do sinal foi apenas modificada por causa do canal.

#### Com IQ

Neste exemplo, você pode ver como há um **grande círculo** mas também **muitos pontos no centro**.

![](<../../.gitbook/assets/image (640).png>)

### Obter Taxa de Símbolos

#### Com um símbolo

Selecione o menor símbolo que você pode encontrar (para ter certeza de que é apenas 1) e verifique a "Frequência de seleção". Neste caso, seria 1.013kHz (então 1kHz).

![](<../../.gitbook/assets/image (638) (1).png>)

#### Com um grupo de símbolos

Você também pode indicar o número de símbolos que vai selecionar e o SigDigger calculará a frequência de 1 símbolo (quanto mais símbolos selecionados, melhor provavelmente). Neste cenário, selecionei 10 símbolos e a "Frequência de seleção" é 1.004 Khz:

![](<../../.gitbook/assets/image (635).png>)

### Obter Bits

Tendo descoberto que é um sinal **modulado em AM** e a **taxa de símbolos** (e sabendo que neste caso algo para cima significa 1 e algo para baixo significa 0), é muito fácil **obter os bits** codificados no sinal. Portanto, selecione o sinal com informações e configure a amostragem e decisão e pressione amostrar (verifique se a **Amplitude** está selecionada, a **Taxa de símbolos** descoberta está configurada e o **Recuperador de clock Gadner** está selecionado):

![](<../../.gitbook/assets/image (642) (1).png>)

* **Sincronizar com intervalos de seleção** significa que se você selecionou intervalos anteriormente para encontrar a taxa de símbolos, essa taxa de símbolos será usada.
* **Manual** significa que a taxa de símbolos indicada será usada
* Em **Seleção de intervalo fixo** você indica o número de intervalos que devem ser selecionados e ele calcula a taxa de símbolos a partir disso
* **Recuperação de clock Gadner** é geralmente a melhor opção, mas você ainda precisa indicar uma taxa de símbolos aproximada.

Ao pressionar amostrar, isso aparece:

![](<../../.gitbook/assets/image (659).png>)

Agora, para fazer o SigDigger entender **onde está o intervalo** do nível que carrega informações, você precisa clicar no **nível mais baixo** e manter clicado até o maior nível:

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

Se houvesse, por exemplo, **4 níveis diferentes de amplitude**, você teria que configurar os **Bits por símbolo para 2** e selecionar do menor para o maior.

Finalmente, **aumentando** o **Zoom** e **alterando o tamanho da linha** você pode ver os bits (e pode selecionar tudo e copiar para obter todos os bits):

![](<../../.gitbook/assets/image (649) (1).png>)

Se o sinal tiver mais de 1 bit por símbolo (por exemplo, 2), o SigDigger **não terá como saber qual símbolo é** 00, 01, 10, 11, então ele usará diferentes **escalas de cinza** para representar cada um (e se você copiar os bits, ele usará **números de 0 a 3**, você precisará tratá-los).

Além disso, use **codificações** como **Manchester**, e **para cima+para baixo** pode ser **1 ou 0** e um para baixo+para cima pode ser um 1 ou 0. Nestes casos, você precisa **tratar os para cima (1) e para baixo (0)** obtidos para substituir os pares de 01 ou 10 como 0s ou 1s.

## Exemplo de FM

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Descobrindo FM

#### Verificando as frequências e a forma de onda

Exemplo de sinal enviando informações moduladas em FM:

![](<../../.gitbook/assets/image (661) (1).png>)

Na imagem anterior, você pode observar claramente que **2 frequências são usadas** mas se você **observar** a **forma de onda** você pode **não ser capaz de identificar corretamente as 2 frequências diferentes**:

![](<../../.gitbook/assets/image (653).png>)

Isso ocorre porque capturei o sinal em ambas as frequências, portanto uma é aproximadamente a outra em negativo:

![](<../../.gitbook/assets/image (656).png>)

Se a frequência sincronizada estiver **mais próxima de uma frequência do que da outra** você pode facilmente ver as 2 frequências diferentes:

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### Verificando o histograma

Verificando o histograma de frequência do sinal com informações, você pode ver facilmente 2 sinais diferentes:

![](<../../.gitbook/assets/image (657).png>)

Neste caso, se você verificar o **histograma de amplitude** você encontrará **apenas uma amplitude**, então **não pode ser AM** (se você encontrar muitas amplitudes pode ser porque o sinal perdeu potência ao longo do canal):

![](<../../.gitbook/assets/image (646).png>)

E este seria o histograma de fase (o que torna muito claro que o sinal não está modulado em fase):

![](<../../.gitbook/assets/image (201) (2).png>)

#### Com IQ

IQ não tem um campo para identificar frequências (a distância para o centro é amplitude e o ângulo é fase).\
Portanto, para identificar FM, você deve **ver basicamente um círculo** neste gráfico.\
Além disso, uma frequência diferente é "representada" pelo gráfico IQ por uma **aceleração de velocidade em torno do círculo** (então no SysDigger selecionando o sinal o gráfico IQ é preenchido, se você encontrar uma aceleração ou mudança de direção no círculo criado, pode significar que é FM):

![](<../../.gitbook/assets/image (643) (1).png>)

### Obter Taxa de Símbolos

Você pode usar a **mesma técnica usada no exemplo de AM** para obter a taxa de símbolos uma vez que você encontrou as frequências que carregam os símbolos.

### Obter Bits

Você pode usar a **mesma técnica usada no exemplo de AM** para obter os bits uma vez que você **descobriu que o sinal está modulado em frequência** e a **taxa de símbolos**.

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) re

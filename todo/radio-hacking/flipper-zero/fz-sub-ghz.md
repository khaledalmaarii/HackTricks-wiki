# FZ - Sub-GHz

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Introdução <a href="#kfpn7" id="kfpn7"></a>

O Flipper Zero pode **receber e transmitir frequências de rádio na faixa de 300-928 MHz** com seu módulo integrado, que pode ler, salvar e emular controles remotos. Esses controles são usados para interagir com portões, barreiras, fechaduras de rádio, interruptores de controle remoto, campainhas sem fio, luzes inteligentes e muito mais. O Flipper Zero pode ajudá-lo a descobrir se sua segurança está comprometida.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

O Flipper Zero possui um módulo sub-1 GHz integrado baseado em um [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿chip CC1101 e uma antena de rádio (o alcance máximo é de 50 metros). Tanto o chip CC1101 quanto a antena são projetados para operar em frequências nas faixas de 300-348 MHz, 387-464 MHz e 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Ações

### Analisador de Frequência

{% hint style="info" %}
Como encontrar qual frequência o controle remoto está usando
{% endhint %}

Ao analisar, o Flipper Zero está escaneando a força dos sinais (RSSI) em todas as frequências disponíveis na configuração de frequência. O Flipper Zero exibe a frequência com o maior valor de RSSI, com intensidade de sinal superior a -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Para determinar a frequência do controle remoto, faça o seguinte:

1. Coloque o controle remoto muito perto do lado esquerdo do Flipper Zero.
2. Vá para **Menu Principal** **→ Sub-GHz**.
3. Selecione **Analizador de Frequência**, em seguida, pressione e segure o botão no controle remoto que deseja analisar.
4. Reveja o valor da frequência na tela.

### Ler

{% hint style="info" %}
Encontre informações sobre a frequência usada (também outra maneira de encontrar qual frequência é usada)
{% endhint %}

A opção **Ler** **escuta na frequência configurada** na modulação indicada: 433,92 AM por padrão. Se **algo for encontrado** ao ler, **as informações são exibidas** na tela. Essas informações podem ser usadas para replicar o sinal no futuro.

Enquanto o Ler está em uso, é possível pressionar o **botão esquerdo** e **configurá-lo**.\
Neste momento, existem **4 modulações** (AM270, AM650, FM328 e FM476), e **várias frequências relevantes** armazenadas:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Você pode definir **qualquer uma que lhe interesse**, no entanto, se você **não tem certeza de qual frequência** pode ser a usada pelo controle remoto que você tem, **defina o Hopping como ON** (Desligado por padrão) e pressione o botão várias vezes até o Flipper capturar e fornecer as informações necessárias para definir a frequência.

{% hint style="danger" %}
Alternar entre frequências leva algum tempo, portanto, os sinais transmitidos no momento da troca podem ser perdidos. Para uma melhor recepção do sinal, defina uma frequência fixa determinada pelo Analisador de Frequência.
{% endhint %}

### **Ler Bruto**

{% hint style="info" %}
Roube (e reproduza) um sinal na frequência configurada
{% endhint %}

A opção **Ler Bruto** **registra sinais** enviados na frequência de escuta. Isso pode ser usado para **roubar** um sinal e **repeti-lo**.

Por padrão, o **Ler Bruto também está em 433,92 em AM650**, mas se com a opção Ler você descobrir que o sinal que lhe interessa está em uma **frequência/modulação diferente, você também pode modificá-lo** pressionando esquerda (enquanto estiver dentro da opção Ler Bruto).

### Brute-Force

Se você conhece o protocolo usado, por exemplo, pela porta da garagem, é possível **gerar todos os códigos e enviá-los com o Flipper Zero**. Este é um exemplo que suporta tipos comuns de garagens em geral: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Adicionar Manualmente

{% hint style="info" %}
Adicione sinais de uma lista configurada de protocolos
{% endhint %}

#### Lista de [protocolos suportados](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (funciona com a maioria dos sistemas de código estático) | 433,92 | Estático |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433,92 | Estático |
| Nice Flo 24bit\_433                                             | 433,92 | Estático |
| CAME 12bit\_433                                                 | 433,92 | Estático |
| CAME 24bit\_433                                                 | 433,92 | Estático |
| Linear\_300                                                     | 300,00 | Estático |
| CAME TWEE                                                       | 433,92 | Estático |
| Gate TX\_433                                                    | 433,92 | Estático |
| DoorHan\_315                                                    | 315,00 | Dinâmico |
| DoorHan\_433                                                    | 433,92 | Dinâmico |
| LiftMaster\_315                                                 | 315,00 | Dinâmico |
| LiftMaster\_390                                                 | 390,00 | Dinâmico |
| Security+2.0\_310                                               | 310,00 | Dinâmico |
| Security+2.0\_315                                               | 315,00 | Dinâmico |
| Security+2.0\_390                                               | 390,00 | Dinâmico |
### Fornecedores Sub-GHz Suportados

Verifique a lista em [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Frequências Suportadas por Região

Verifique a lista em [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Teste

{% hint style="info" %}
Obtenha dBms das frequências salvas
{% endhint %}

## Referência

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

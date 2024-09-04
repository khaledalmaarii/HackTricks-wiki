# FZ - Sub-GHz

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}


## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero pode **receber e transmitir frequências de rádio na faixa de 300-928 MHz** com seu módulo embutido, que pode ler, salvar e emular controles remotos. Esses controles são usados para interação com portões, barreiras, fechaduras de rádio, interruptores de controle remoto, campainhas sem fio, luzes inteligentes e mais. Flipper Zero pode ajudá-lo a aprender se sua segurança está comprometida.

<figure><img src="../../../.gitbook/assets/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero possui um módulo sub-1 GHz embutido baseado em um [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[chip CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) e uma antena de rádio (o alcance máximo é de 50 metros). Tanto o chip CC1101 quanto a antena são projetados para operar em frequências nas faixas de 300-348 MHz, 387-464 MHz e 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (923).png" alt=""><figcaption></figcaption></figure>

## Ações

### Analisador de Frequência

{% hint style="info" %}
Como encontrar qual frequência o controle remoto está usando
{% endhint %}

Ao analisar, o Flipper Zero está escaneando a intensidade dos sinais (RSSI) em todas as frequências disponíveis na configuração de frequência. O Flipper Zero exibe a frequência com o maior valor de RSSI, com intensidade de sinal superior a -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Para determinar a frequência do controle remoto, faça o seguinte:

1. Coloque o controle remoto muito perto à esquerda do Flipper Zero.
2. Vá para **Menu Principal** **→ Sub-GHz**.
3. Selecione **Analisador de Frequência**, em seguida, pressione e segure o botão no controle remoto que você deseja analisar.
4. Revise o valor da frequência na tela.

### Ler

{% hint style="info" %}
Encontre informações sobre a frequência utilizada (também outra maneira de descobrir qual frequência está sendo usada)
{% endhint %}

A opção **Ler** **ouve na frequência configurada** na modulação indicada: 433.92 AM por padrão. Se **algo for encontrado** ao ler, **as informações são fornecidas** na tela. Essas informações podem ser usadas para replicar o sinal no futuro.

Enquanto a opção Ler está em uso, é possível pressionar o **botão esquerdo** e **configurá-la**.\
Neste momento, possui **4 modulações** (AM270, AM650, FM328 e FM476), e **várias frequências relevantes** armazenadas:

<figure><img src="../../../.gitbook/assets/image (947).png" alt=""><figcaption></figcaption></figure>

Você pode definir **qualquer uma que lhe interesse**, no entanto, se você **não tiver certeza de qual frequência** pode ser a usada pelo controle remoto que você possui, **defina Hopping como ATIVADO** (Desativado por padrão), e pressione o botão várias vezes até que o Flipper a capture e forneça as informações que você precisa para definir a frequência.

{% hint style="danger" %}
Alternar entre frequências leva algum tempo, portanto, sinais transmitidos no momento da troca podem ser perdidos. Para melhor recepção de sinal, defina uma frequência fixa determinada pelo Analisador de Frequência.
{% endhint %}

### **Ler Raw**

{% hint style="info" %}
Roubar (e repetir) um sinal na frequência configurada
{% endhint %}

A opção **Ler Raw** **grava sinais** enviados na frequência de escuta. Isso pode ser usado para **roubar** um sinal e **repeti-lo**.

Por padrão, **Ler Raw também está em 433.92 em AM650**, mas se com a opção Ler você descobriu que o sinal que lhe interessa está em uma **frequência/modulação diferente, você também pode modificar isso** pressionando à esquerda (enquanto estiver na opção Ler Raw).

### Força Bruta

Se você conhece o protocolo usado, por exemplo, pelo portão da garagem, é possível **gerar todos os códigos e enviá-los com o Flipper Zero.** Este é um exemplo que suporta tipos comuns gerais de garagens: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Adicionar Manualmente

{% hint style="info" %}
Adicionar sinais de uma lista configurada de protocolos
{% endhint %}

#### Lista de [protocolos suportados](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (funciona com a maioria dos sistemas de código estático) | 433.92 | Estático  |
| ------------------------------------------------------------------------ | ------ | -------- |
| Nice Flo 12bit\_433                                                    | 433.92 | Estático  |
| Nice Flo 24bit\_433                                                    | 433.92 | Estático  |
| CAME 12bit\_433                                                        | 433.92 | Estático  |
| CAME 24bit\_433                                                        | 433.92 | Estático  |
| Linear\_300                                                            | 300.00 | Estático  |
| CAME TWEE                                                              | 433.92 | Estático  |
| Gate TX\_433                                                           | 433.92 | Estático  |
| DoorHan\_315                                                           | 315.00 | Dinâmico |
| DoorHan\_433                                                           | 433.92 | Dinâmico |
| LiftMaster\_315                                                        | 315.00 | Dinâmico |
| LiftMaster\_390                                                        | 390.00 | Dinâmico |
| Security+2.0\_310                                                      | 310.00 | Dinâmico |
| Security+2.0\_315                                                      | 315.00 | Dinâmico |
| Security+2.0\_390                                                      | 390.00 | Dinâmico |

### Fornecedores Sub-GHz suportados

Confira a lista em [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Frequências suportadas por região

Confira a lista em [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Teste

{% hint style="info" %}
Obtenha dBms das frequências salvas
{% endhint %}

## Referência

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

# FZ - Infravermelho

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

## Introdução <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para mais informações sobre como o Infravermelho funciona, confira:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Receptor de Sinal IR no Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

O Flipper usa um receptor de sinal IR digital TSOP, que **permite interceptar sinais de controles remotos IR**. Existem alguns **smartphones** como Xiaomi, que também têm uma porta IR, mas tenha em mente que **a maioria deles só pode transmitir** sinais e **não consegue recebê-los**.

O receptor infravermelho do Flipper **é bastante sensível**. Você pode até **captar o sinal** enquanto permanece **em algum lugar entre** o controle remoto e a TV. Apontar o controle remoto diretamente para a porta IR do Flipper é desnecessário. Isso é útil quando alguém está trocando de canal enquanto está perto da TV, e tanto você quanto o Flipper estão a uma certa distância.

Como a **decodificação do sinal infravermelho** acontece do lado do **software**, o Flipper Zero potencialmente suporta a **recepção e transmissão de quaisquer códigos de controle remoto IR**. No caso de **protocolos desconhecidos** que não puderam ser reconhecidos - ele **grava e reproduz** o sinal bruto exatamente como recebido.

## Ações

### Controles Remotos Universais

O Flipper Zero pode ser usado como um **controle remoto universal para controlar qualquer TV, ar-condicionado ou centro de mídia**. Neste modo, o Flipper **realiza força bruta** em todos os **códigos conhecidos** de todos os fabricantes suportados **de acordo com o dicionário do cartão SD**. Você não precisa escolher um controle remoto específico para desligar a TV de um restaurante.

Basta pressionar o botão de energia no modo Controle Remoto Universal, e o Flipper **enviará sequencialmente os comandos "Desligar"** de todas as TVs que conhece: Sony, Samsung, Panasonic... e assim por diante. Quando a TV recebe seu sinal, ela reagirá e desligará.

Esse ataque de força bruta leva tempo. Quanto maior o dicionário, mais tempo levará para terminar. É impossível descobrir qual sinal exatamente a TV reconheceu, uma vez que não há feedback da TV.

### Aprender Novo Controle Remoto

É possível **capturar um sinal infravermelho** com o Flipper Zero. Se ele **encontrar o sinal no banco de dados**, o Flipper automaticamente **saberá qual dispositivo é** e permitirá que você interaja com ele.\
Se não encontrar, o Flipper pode **armazenar** o **sinal** e permitirá que você **o reproduza**.

## Referências

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

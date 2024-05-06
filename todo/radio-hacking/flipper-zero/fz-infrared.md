# FZ - Infravermelho

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introdução <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para mais informações sobre como o Infravermelho funciona, confira:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Receptor de Sinal IR no Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

O Flipper usa um receptor de sinal IR digital TSOP, que **permite interceptar sinais de controles remotos IR**. Alguns **smartphones** como Xiaomi, também possuem uma porta IR, mas tenha em mente que **a maioria deles só pode transmitir** sinais e são **incapazes de recebê-los**.

O receptor infravermelho do Flipper é **bastante sensível**. Você pode até **captar o sinal** estando **em algum lugar entre** o controle remoto e a TV. Apontar o controle remoto diretamente para a porta IR do Flipper é desnecessário. Isso é útil quando alguém está trocando de canal perto da TV, e tanto você quanto o Flipper estão a certa distância.

Como a **decodificação do sinal infravermelho** acontece no **lado do software**, o Flipper Zero potencialmente suporta a **receção e transmissão de quaisquer códigos de controle remoto IR**. No caso de **protocolos desconhecidos** que não puderam ser reconhecidos - ele **registra e reproduz** o sinal bruto exatamente como recebido.

## Ações

### Controles Remotos Universais

O Flipper Zero pode ser usado como um **controle remoto universal para controlar qualquer TV, ar condicionado ou centro de mídia**. Neste modo, o Flipper **força bruta** todos os **códigos conhecidos** de todos os fabricantes suportados **de acordo com o dicionário do cartão SD**. Você não precisa escolher um controle remoto específico para desligar uma TV de restaurante.

Basta pressionar o botão de energia no modo Controle Remoto Universal, e o Flipper **enviará sequencialmente comandos de "Desligar"** de todas as TVs que conhece: Sony, Samsung, Panasonic... e assim por diante. Quando a TV receber seu sinal, ela reagirá e desligará.

Essa força bruta leva tempo. Quanto maior o dicionário, mais tempo levará para terminar. É impossível descobrir qual sinal exatamente a TV reconheceu, já que não há feedback da TV.

### Aprender Novo Controle Remoto

É possível **capturar um sinal infravermelho** com o Flipper Zero. Se ele **encontrar o sinal no banco de dados**, o Flipper automaticamente **saberá qual dispositivo é** e permitirá que você interaja com ele.\
Se não encontrar, o Flipper pode **armazenar** o **sinal** e permitirá que você o **reproduza**.

## Referências

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

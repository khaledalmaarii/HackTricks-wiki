# iButton

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks Especialista em Equipe Vermelha AWS)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** repositórios [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introdução

iButton é um nome genérico para uma chave de identificação eletrônica embalada em um **recipiente metálico em forma de moeda**. Também é chamado de **Dallas Touch** Memory ou memória de contato. Embora muitas vezes seja erroneamente referido como uma chave "magnética", não há **nada magnético** nele. Na verdade, um **microchip completo** operando em um protocolo digital está escondido dentro.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### O que é iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Normalmente, iButton implica a forma física da chave e do leitor - uma moeda redonda com dois contatos. Para a moldura que o rodeia, existem muitas variações, desde o suporte de plástico mais comum com um furo até anéis, pingentes, etc.

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

Quando a chave atinge o leitor, os **contatos se tocam** e a chave é alimentada para **transmitir** seu ID. Às vezes, a chave **não é lida** imediatamente porque o **PSD de contato de um interfone é maior** do que deveria ser. Assim, os contornos externos da chave e do leitor não conseguem se tocar. Se esse for o caso, você terá que pressionar a chave sobre uma das paredes do leitor.

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **Protocolo 1-Wire** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

As chaves Dallas trocam dados usando o protocolo 1-Wire. Com apenas um contato para transferência de dados (!!) em ambas as direções, do mestre para o escravo e vice-versa. O protocolo 1-Wire funciona de acordo com o modelo Mestre-Escravo. Nesta topologia, o Mestre sempre inicia a comunicação e o Escravo segue suas instruções.

Quando a chave (Escravo) entra em contato com o interfone (Mestre), o chip dentro da chave é ativado, alimentado pelo interfone, e a chave é inicializada. Em seguida, o interfone solicita o ID da chave. A seguir, veremos esse processo com mais detalhes.

O Flipper pode funcionar tanto no modo Mestre quanto no modo Escravo. No modo de leitura da chave, o Flipper atua como um leitor, ou seja, funciona como um Mestre. E no modo de emulação de chave, o Flipper finge ser uma chave, estando no modo Escravo.

### Chaves Dallas, Cyfral & Metakom

Para informações sobre como essas chaves funcionam, confira a página [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Ataques

Os iButtons podem ser atacados com o Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Referências

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

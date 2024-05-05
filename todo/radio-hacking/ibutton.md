# iButton

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Introdução

iButton é um nome genérico para uma chave de identificação eletrônica embalada em um **recipiente metálico em forma de moeda**. Também é chamado de **Dallas Touch** Memory ou memória de contato. Embora muitas vezes seja erroneamente referido como uma chave "magnética", não há **nada magnético** nele. Na verdade, um **microchip completo** operando em um protocolo digital está escondido dentro.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### O que é iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Normalmente, iButton implica a forma física da chave e do leitor - uma moeda redonda com dois contatos. Para a estrutura que o envolve, existem muitas variações, desde o suporte de plástico mais comum com um furo até anéis, pingentes, etc.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Quando a chave atinge o leitor, os **contatos se tocam** e a chave é alimentada para **transmitir** seu ID. Às vezes, a chave **não é lida** imediatamente porque o **PSD de contato de um interfone é maior** do que deveria ser. Nesse caso, você terá que pressionar a chave em uma das paredes do leitor.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocolo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

As chaves Dallas trocam dados usando o protocolo 1-wire. Com apenas um contato para transferência de dados (!!) em ambas as direções, do mestre para o escravo e vice-versa. O protocolo 1-wire funciona de acordo com o modelo Mestre-Escravo. Nesta topologia, o Mestre sempre inicia a comunicação e o Escravo segue suas instruções.

Quando a chave (Escravo) entra em contato com o interfone (Mestre), o chip dentro da chave é ativado, alimentado pelo interfone, e a chave é inicializada. Em seguida, o interfone solicita o ID da chave. Em seguida, veremos esse processo com mais detalhes.

O Flipper pode funcionar tanto no modo Mestre quanto no modo Escravo. No modo de leitura de chave, o Flipper atua como um leitor, ou seja, funciona como um Mestre. E no modo de emulação de chave, o Flipper finge ser uma chave, está no modo Escravo.

### Chaves Dallas, Cyfral & Metakom

Para informações sobre como essas chaves funcionam, verifique a página [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Ataques

Os iButtons podem ser atacados com o Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Referências

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

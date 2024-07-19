# iButton

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

## Intro

iButton é um nome genérico para uma chave de identificação eletrônica embalada em um **recipiente metálico em forma de moeda**. Também é chamada de **Dallas Touch** Memory ou memória de contato. Embora muitas vezes seja erroneamente chamada de chave “magnética”, não há **nada magnético** nela. Na verdade, um **microchip** completo operando em um protocolo digital está escondido dentro.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### O que é iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Normalmente, iButton implica a forma física da chave e do leitor - uma moeda redonda com dois contatos. Para a moldura que a envolve, existem muitas variações, desde o suporte plástico mais comum com um buraco até anéis, pingentes, etc.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Quando a chave chega ao leitor, os **contatos se tocam** e a chave é alimentada para **transmitir** sua ID. Às vezes, a chave **não é lida** imediatamente porque o **PSD de contato de um intercomunicador é maior** do que deveria ser. Assim, os contornos externos da chave e do leitor não conseguem se tocar. Se esse for o caso, você terá que pressionar a chave contra uma das paredes do leitor.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocolo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

As chaves Dallas trocam dados usando o protocolo 1-wire. Com apenas um contato para transferência de dados (!!) em ambas as direções, do mestre para o escravo e vice-versa. O protocolo 1-wire funciona de acordo com o modelo Mestre-Escravo. Nesta topologia, o Mestre sempre inicia a comunicação e o Escravo segue suas instruções.

Quando a chave (Escravo) entra em contato com o intercomunicador (Mestre), o chip dentro da chave é ativado, alimentado pelo intercomunicador, e a chave é inicializada. Em seguida, o intercomunicador solicita a ID da chave. A seguir, examinaremos esse processo em mais detalhes.

Flipper pode funcionar tanto em modos Mestre quanto Escravo. No modo de leitura da chave, o Flipper atua como um leitor, ou seja, funciona como um Mestre. E no modo de emulação da chave, o flipper finge ser uma chave, estando no modo Escravo.

### Chaves Dallas, Cyfral e Metakom

Para informações sobre como essas chaves funcionam, confira a página [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Ataques

iButtons podem ser atacados com Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Referências

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

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

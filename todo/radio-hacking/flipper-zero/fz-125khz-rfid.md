# FZ - RFID 125kHz

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

## Introdução

Para mais informações sobre como as tags de 125kHz funcionam, confira:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Ações

Para mais informações sobre esses tipos de tags [**leia esta introdução**](../../../radio-hacking/pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Ler

Tenta **ler** as informações do cartão. Depois, pode **emular** elas.

{% hint style="warning" %}
Note que alguns intercomunicadores tentam se proteger da duplicação de chaves enviando um comando de escrita antes de ler. Se a escrita for bem-sucedida, essa tag é considerada falsa. Quando o Flipper emula RFID, não há como o leitor distinguir do original, então não ocorrem tais problemas.
{% endhint %}

### Adicionar Manualmente

Você pode criar **cartões falsos no Flipper Zero indicando os dados** que você inseriu manualmente e depois emulá-lo.

#### IDs nos cartões

Às vezes, quando você recebe um cartão, você encontrará o ID (ou parte dele) escrito visivelmente no cartão.

* **EM Marin**

Por exemplo, neste cartão EM-Marin é possível **ler os últimos 3 de 5 bytes claramente**.\
Os outros 2 podem ser forçados bruscamente se você não puder lê-los do cartão.

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

* **HID**

O mesmo acontece neste cartão HID onde apenas 2 de 3 bytes podem ser encontrados impressos no cartão

<figure><img src="../../../.gitbook/assets/image (15) (3).png" alt=""><figcaption></figcaption></figure>

### Emular/Escrever

Após **copiar** um cartão ou **inserir** o ID **manualmente**, é possível **emular** com o Flipper Zero ou **escrever** em um cartão real.

## Referências

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

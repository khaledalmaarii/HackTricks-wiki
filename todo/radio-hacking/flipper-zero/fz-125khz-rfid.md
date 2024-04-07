# FZ - 125kHz RFID

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Introdução

Para mais informações sobre como funcionam as tags de 125kHz, consulte:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Ações

Para mais informações sobre esses tipos de tags, [**leia esta introdução**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Ler

Tenta **ler** as informações do cartão. Em seguida, pode **emulá-las**.

{% hint style="warning" %}
Observe que alguns interfones tentam se proteger contra a duplicação de chaves enviando um comando de gravação antes da leitura. Se a gravação for bem-sucedida, essa tag é considerada falsa. Quando o Flipper emula RFID, não há como o leitor distingui-lo do original, portanto, tais problemas não ocorrem.
{% endhint %}

### Adicionar Manualmente

Você pode criar **cartões falsos no Flipper Zero indicando os dados** manualmente e depois emulá-los.

#### IDs nos cartões

Às vezes, ao obter um cartão, você encontrará o ID (ou parte) dele escrito no cartão visível.

* **EM Marin**

Por exemplo, neste cartão EM-Marin, no cartão físico é possível **ler os últimos 3 de 5 bytes claramente**.\
Os outros 2 podem ser forçados se você não puder lê-los no cartão.

<figure><img src="../../../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

* **HID**

O mesmo acontece neste cartão HID, onde apenas 2 de 3 bytes podem ser encontrados impressos no cartão

<figure><img src="../../../.gitbook/assets/image (1011).png" alt=""><figcaption></figcaption></figure>

### Emular/Gravar

Depois de **copiar** um cartão ou **inserir** o ID **manualmente**, é possível **emulá-lo** com o Flipper Zero ou **gravá-lo** em um cartão real.

## Referências

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# FZ - NFC

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introdução <a href="#id-9wrzi" id="id-9wrzi"></a>

Para informações sobre RFID e NFC, consulte a seguinte página:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Cartões NFC Suportados <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Além dos cartões NFC, o Flipper Zero suporta **outros tipos de cartões de alta frequência** como vários **Mifare** Classic e Ultralight e **NTAG**.
{% endhint %}

Novos tipos de cartões NFC serão adicionados à lista de cartões suportados. O Flipper Zero suporta os seguintes **tipos de cartões NFC tipo A** (ISO 14443A):

* ﻿**Cartões bancários (EMV)** — apenas lê UID, SAK e ATQA sem salvar.
* ﻿**Cartões desconhecidos** — lê (UID, SAK, ATQA) e emula um UID.

Para os **tipos de cartões NFC B, F e V**, o Flipper Zero é capaz de ler um UID sem salvá-lo.

### Tipos de Cartões NFC tipo A <a href="#uvusf" id="uvusf"></a>

#### Cartão bancário (EMV) <a href="#kzmrp" id="kzmrp"></a>

O Flipper Zero só pode ler um UID, SAK, ATQA e dados armazenados em cartões bancários **sem salvar**.

Tela de leitura de cartão bancárioPara cartões bancários, o Flipper Zero só pode ler dados **sem salvar e emulá-los**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Cartões desconhecidos <a href="#id-37eo8" id="id-37eo8"></a>

Quando o Flipper Zero é **incapaz de determinar o tipo de cartão NFC**, então apenas um **UID, SAK e ATQA** podem ser **lidos e salvos**.

Tela de leitura de cartão desconhecidoPara cartões NFC desconhecidos, o Flipper Zero só pode emular um UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Tipos de Cartões NFC B, F e V <a href="#wyg51" id="wyg51"></a>

Para os **tipos de cartões NFC B, F e V**, o Flipper Zero só pode **ler e exibir um UID** sem salvá-lo.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Ações

Para uma introdução sobre NFC [**leia esta página**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Ler

O Flipper Zero pode **ler cartões NFC**, no entanto, ele **não entende todos os protocolos** baseados em ISO 14443. No entanto, como o **UID é um atributo de baixo nível**, você pode se encontrar em uma situação em que o **UID já foi lido, mas o protocolo de transferência de dados de alto nível ainda é desconhecido**. Você pode ler, emular e inserir manualmente o UID usando o Flipper para leitores primitivos que usam o UID para autorização.

#### Ler o UID VS Ler os Dados Internos <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

No Flipper, a leitura de tags de 13,56 MHz pode ser dividida em duas partes:

* **Leitura de baixo nível** — lê apenas o UID, SAK e ATQA. O Flipper tenta adivinhar o protocolo de alto nível com base nos dados lidos do cartão. Você não pode ter certeza de 100% disso, pois é apenas uma suposição com base em certos fatores.
* **Leitura de alto nível** — lê os dados da memória do cartão usando um protocolo de alto nível específico. Isso seria ler os dados em um Mifare Ultralight, ler os setores de um Mifare Classic ou ler os atributos do cartão de PayPass/Apple Pay.

### Ler Específico

Caso o Flipper Zero não seja capaz de encontrar o tipo de cartão a partir dos dados de baixo nível, em `Ações Extras` você pode selecionar `Ler Tipo de Cartão Específico` e **indicar manualmente** **o tipo de cartão que deseja ler**.

#### Cartões Bancários EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Além de simplesmente ler o UID, você pode extrair muitos mais dados de um cartão bancário. É possível **obter o número completo do cartão** (os 16 dígitos na frente do cartão), **data de validade** e, em alguns casos, até o **nome do proprietário** juntamente com uma lista das **transações mais recentes**.\
No entanto, você **não pode ler o CVV dessa forma** (os 3 dígitos no verso do cartão). Além disso, **os cartões bancários estão protegidos contra ataques de replay**, então copiá-los com o Flipper e depois tentar emulá-los para pagar algo não funcionará.
## Referências

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

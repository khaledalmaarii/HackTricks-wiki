# FZ - NFC

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

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Para informações sobre RFID e NFC, confira a página a seguir:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Cartões NFC suportados <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Além dos cartões NFC, o Flipper Zero suporta **outro tipo de cartões de alta frequência** como vários **Mifare** Classic e Ultralight e **NTAG**.
{% endhint %}

Novos tipos de cartões NFC serão adicionados à lista de cartões suportados. O Flipper Zero suporta os seguintes **tipos de cartões NFC A** (ISO 14443A):

* ﻿**Cartões bancários (EMV)** — apenas lê UID, SAK e ATQA sem salvar.
* ﻿**Cartões desconhecidos** — lê (UID, SAK, ATQA) e emula um UID.

Para **cartões NFC tipo B, tipo F e tipo V**, o Flipper Zero é capaz de ler um UID sem salvá-lo.

### Cartões NFC tipo A <a href="#uvusf" id="uvusf"></a>

#### Cartão bancário (EMV) <a href="#kzmrp" id="kzmrp"></a>

O Flipper Zero pode apenas ler um UID, SAK, ATQA e dados armazenados em cartões bancários **sem salvar**.

Tela de leitura de cartão bancárioPara cartões bancários, o Flipper Zero pode apenas ler dados **sem salvar e emular**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Cartões desconhecidos <a href="#id-37eo8" id="id-37eo8"></a>

Quando o Flipper Zero é **incapaz de determinar o tipo do cartão NFC**, então apenas um **UID, SAK e ATQA** podem ser **lidos e salvos**.

Tela de leitura de cartão desconhecidoPara cartões NFC desconhecidos, o Flipper Zero pode emular apenas um UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Tipos de cartões NFC B, F e V <a href="#wyg51" id="wyg51"></a>

Para **tipos de cartões NFC B, F e V**, o Flipper Zero pode apenas **ler e exibir um UID** sem salvá-lo.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Ações

Para uma introdução sobre NFC [**leia esta página**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Ler

O Flipper Zero pode **ler cartões NFC**, no entanto, ele **não entende todos os protocolos** que são baseados em ISO 14443. No entanto, como **UID é um atributo de baixo nível**, você pode se encontrar em uma situação em que **UID já foi lido, mas o protocolo de transferência de dados de alto nível ainda é desconhecido**. Você pode ler, emular e inserir manualmente o UID usando o Flipper para os leitores primitivos que usam UID para autorização.

#### Lendo o UID VS Lendo os Dados Internos <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

No Flipper, a leitura de tags de 13,56 MHz pode ser dividida em duas partes:

* **Leitura de baixo nível** — lê apenas o UID, SAK e ATQA. O Flipper tenta adivinhar o protocolo de alto nível com base nesses dados lidos do cartão. Você não pode ter 100% de certeza com isso, pois é apenas uma suposição baseada em certos fatores.
* **Leitura de alto nível** — lê os dados da memória do cartão usando um protocolo de alto nível específico. Isso seria ler os dados em um Mifare Ultralight, ler os setores de um Mifare Classic ou ler os atributos do cartão de PayPass/Apple Pay.

### Ler Específico

Caso o Flipper Zero não consiga encontrar o tipo de cartão a partir dos dados de baixo nível, em `Ações Extras` você pode selecionar `Ler Tipo de Cartão Específico` e **indicar manualmente** **o tipo de cartão que você gostaria de ler**.

#### Cartões Bancários EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Além de simplesmente ler o UID, você pode extrair muito mais dados de um cartão bancário. É possível **obter o número completo do cartão** (os 16 dígitos na frente do cartão), **data de validade**, e em alguns casos até mesmo o **nome do proprietário** junto com uma lista das **transações mais recentes**.\
No entanto, você **não pode ler o CVV dessa forma** (os 3 dígitos na parte de trás do cartão). Além disso, **cartões bancários estão protegidos contra ataques de repetição**, então copiá-lo com o Flipper e depois tentar emulá-lo para pagar por algo não funcionará.

## Referências

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

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

# FZ - NFC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que são mais importantes para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha de tecnologia, desde APIs até aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Introdução <a href="#9wrzi" id="9wrzi"></a>

Para informações sobre RFID e NFC, consulte a seguinte página:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Cartões NFC suportados <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
Além dos cartões NFC, o Flipper Zero suporta **outros tipos de cartões de alta frequência**, como vários **Mifare** Classic e Ultralight e **NTAG**.
{% endhint %}

Novos tipos de cartões NFC serão adicionados à lista de cartões suportados. O Flipper Zero suporta os seguintes **tipos de cartões NFC tipo A** (ISO 14443A):

* ﻿**Cartões bancários (EMV)** - apenas lê UID, SAK e ATQA sem salvar.
* ﻿**Cartões desconhecidos** - lê (UID, SAK, ATQA) e emula um UID.

Para **cartões NFC tipo B, tipo F e tipo V**, o Flipper Zero é capaz de ler um UID sem salvá-lo.

### Tipos de cartões NFC tipo A <a href="#uvusf" id="uvusf"></a>

#### Cartão bancário (EMV) <a href="#kzmrp" id="kzmrp"></a>

O Flipper Zero só pode ler um UID, SAK, ATQA e dados armazenados em cartões bancários **sem salvar**.

Tela de leitura de cartão bancárioPara cartões bancários, o Flipper Zero só pode ler dados **sem salvar e emulá-los**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Cartões desconhecidos <a href="#37eo8" id="37eo8"></a>

Quando o Flipper Zero é **incapaz de determinar o tipo de cartão NFC**, então apenas um **UID, SAK e ATQA** podem ser **lidos e salvos**.

Tela de leitura de cartão desconhecidoPara cartões NFC desconhecidos, o Flipper Zero só pode emular um UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Tipos de cartões NFC B, F e V <a href="#wyg51" id="wyg51"></a>

Para **cartões NFC dos tipos B, F e V**, o Flipper Zero só pode **ler e exibir um UID** sem salvá-lo.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Ações

Para uma introdução sobre NFC [**leia esta página**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Leitura

O Flipper Zero pode **ler cartões NFC**, no entanto, ele **não entende todos os protocolos** baseados em ISO 14443. No entanto, como o **UID é um atributo de baixo nível**, você pode se encontrar em uma situação em que o **UID já foi lido, mas o protocolo de transferência de dados de alto nível ainda é desconhecido**. Você pode ler, emular e inserir manualmente o UID usando o Flipper para leitores primitivos que usam o UID para autorização.
#### Leitura do UID vs Leitura dos Dados Internos <a href="#leitura-do-uid-vs-leitura-dos-dados-internos" id="leitura-do-uid-vs-leitura-dos-dados-internos"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

No Flipper, a leitura de tags de 13,56 MHz pode ser dividida em duas partes:

* **Leitura de baixo nível** - lê apenas o UID, SAK e ATQA. O Flipper tenta adivinhar o protocolo de alto nível com base nesses dados lidos do cartão. Não é possível ter certeza de 100% disso, pois é apenas uma suposição com base em certos fatores.
* **Leitura de alto nível** - lê os dados da memória do cartão usando um protocolo de alto nível específico. Isso seria a leitura dos dados em um Mifare Ultralight, a leitura dos setores de um Mifare Classic ou a leitura dos atributos do cartão PayPass/Apple Pay.

### Leitura Específica

Caso o Flipper Zero não seja capaz de identificar o tipo de cartão a partir dos dados de baixo nível, em `Ações Extras` você pode selecionar `Ler Tipo de Cartão Específico` e **indicar manualmente o tipo de cartão que deseja ler**.

#### Cartões Bancários EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#cartões-bancários-emv-paypass-paywave-apple-pay-google-pay" id="cartões-bancários-emv-paypass-paywave-apple-pay-google-pay"></a>

Além de simplesmente ler o UID, é possível extrair muitos outros dados de um cartão bancário. É possível **obter o número completo do cartão** (os 16 dígitos na frente do cartão), a **data de validade** e, em alguns casos, até mesmo o **nome do proprietário** juntamente com uma lista das **transações mais recentes**.\
No entanto, **não é possível ler o CVV dessa forma** (os 3 dígitos na parte de trás do cartão). Além disso, **os cartões bancários estão protegidos contra ataques de replay**, portanto, copiá-los com o Flipper e depois tentar emulá-los para pagar algo não funcionará.

## Referências

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre as vulnerabilidades que mais importam para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha de tecnologia, desde APIs até aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

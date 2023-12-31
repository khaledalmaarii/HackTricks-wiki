# Número de Série do macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Dispositivos Apple fabricados após 2010 geralmente possuem números de série **alfanuméricos de 12 caracteres**, com os **três primeiros dígitos representando o local de fabricação**, os dois seguintes indicando o **ano** e a **semana** de fabricação, os próximos três dígitos fornecendo um **identificador único**, e os **quatro últimos dígitos representando o número do modelo**.

Exemplo de número de série: **C02L13ECF8J2**

### **3 - Locais de Fabricação**

| Código         | Fábrica                                      |
| -------------- | -------------------------------------------- |
| FC             | Fountain Colorado, EUA                       |
| F              | Fremont, Califórnia, EUA                     |
| XA, XB, QP, G8 | EUA                                          |
| RN             | México                                       |
| CK             | Cork, Irlanda                                |
| VM             | Foxconn, Pardubice, República Tcheca         |
| SG, E          | Singapura                                    |
| MB             | Malásia                                      |
| PT, CY         | Coreia                                       |
| EE, QT, UV     | Taiwan                                       |
| FK, F1, F2     | Foxconn – Zhengzhou, China                   |
| W8             | Shanghai China                               |
| DL, DM         | Foxconn – China                              |
| DN             | Foxconn, Chengdu, China                      |
| YM, 7J         | Hon Hai/Foxconn, China                       |
| 1C, 4H, WQ, F7 | China                                        |
| C0             | Tech Com – Subsidiária da Quanta Computer, China |
| C3             | Foxxcon, Shenzhen, China                     |
| C7             | Pentragon, Changhai, China                   |
| RM             | Recondicionado/remodelado                    |

### 1 - Ano de Fabricação

| Código | Lançamento            |
| ------ | --------------------- |
| C      | 2010/2020 (1º semestre) |
| D      | 2010/2020 (2º semestre) |
| F      | 2011/2021 (1º semestre) |
| G      | 2011/2021 (2º semestre) |
| H      | 2012/... (1º semestre)  |
| J      | 2012 (2º semestre)      |
| K      | 2013 (1º semestre)      |
| L      | 2013 (2º semestre)      |
| M      | 2014 (1º semestre)      |
| N      | 2014 (2º semestre)      |
| P      | 2015 (1º semestre)      |
| Q      | 2015 (2º semestre)      |
| R      | 2016 (1º semestre)      |
| S      | 2016 (2º semestre)      |
| T      | 2017 (1º semestre)      |
| V      | 2017 (2º semestre)      |
| W      | 2018 (1º semestre)      |
| X      | 2018 (2º semestre)      |
| Y      | 2019 (1º semestre)      |
| Z      | 2019 (2º semestre)      |

### 1 - Semana de Fabricação

O quinto caractere representa a semana na qual o dispositivo foi fabricado. Existem 28 caracteres possíveis nesta posição: **os dígitos de 1 a 9 são usados para representar a primeira até a nona semana**, e os **caracteres de C a Y**, **excluindo** as vogais A, E, I, O e U, e a letra S, representam a **décima até a vigésima sétima semana**. Para dispositivos fabricados no **segundo semestre do ano, adicione 26** ao número representado pelo quinto caractere do número de série. Por exemplo, um produto com um número de série cujos quarto e quinto dígitos são “JH” foi fabricado na 40ª semana de 2012.

### 3 - Código Único

Os próximos três dígitos são um código identificador que **serve para diferenciar cada dispositivo Apple do mesmo modelo** que é fabricado no mesmo local e durante a mesma semana do mesmo ano, garantindo que cada dispositivo tenha um número de série diferente.

### 4 - Número de Série

Os últimos quatro dígitos do número de série representam o **modelo do produto**.

### Referência

{% embed url="https://beetstech.com/blog/decode-meaning-behind-apple-serial-number" %}

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

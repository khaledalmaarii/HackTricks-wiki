# Hacking de Hardware

<details>

<summary><strong>Aprenda hacking da AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## JTAG

JTAG permite realizar uma varredura de limite. A varredura de limite analisa certos circuitos, incluindo células de varredura de limite incorporadas e registros para cada pino.

O padrão JTAG define **comandos específicos para realizar varreduras de limite**, incluindo os seguintes:

* **BYPASS** permite testar um chip específico sem a sobrecarga de passar por outros chips.
* **SAMPLE/PRELOAD** faz uma amostra dos dados que entram e saem do dispositivo quando está em seu modo de funcionamento normal.
* **EXTEST** define e lê estados de pinos.

Também pode suportar outros comandos como:

* **IDCODE** para identificar um dispositivo
* **INTEST** para o teste interno do dispositivo

Você pode encontrar essas instruções ao usar uma ferramenta como o JTAGulator.

### A Porta de Acesso ao Teste

As varreduras de limite incluem testes da **Porta de Acesso ao Teste (TAP)** de quatro fios, uma porta de propósito geral que fornece **acesso ao suporte de teste JTAG** incorporado em um componente. O TAP usa os seguintes cinco sinais:

* Entrada de clock de teste (**TCK**) O TCK é o **clock** que define com que frequência o controlador TAP tomará uma única ação (ou seja, saltar para o próximo estado na máquina de estados).
* Seleção de modo de teste (**TMS**) de entrada TMS controla a **máquina de estados finitos**. Em cada batida do clock, o controlador TAP JTAG do dispositivo verifica a voltagem no pino TMS. Se a voltagem estiver abaixo de um certo limite, o sinal é considerado baixo e interpretado como 0, enquanto se a voltagem estiver acima de um certo limite, o sinal é considerado alto e interpretado como 1.
* Entrada de dados de teste (**TDI**) TDI é o pino que envia **dados para o chip através das células de varredura**. Cada fornecedor é responsável por definir o protocolo de comunicação sobre este pino, porque o JTAG não define isso.
* Saída de dados de teste (**TDO**) TDO é o pino que envia **dados para fora do chip**.
* Reset de teste (**TRST**) de entrada O TRST opcional redefine a máquina de estados finitos **para um estado conhecido bom**. Alternativamente, se o TMS for mantido em 1 por cinco ciclos consecutivos do clock, ele invoca um reset, da mesma forma que o pino TRST faria, razão pela qual o TRST é opcional.

Às vezes, você poderá encontrar esses pinos marcados na PCB. Em outras ocasiões, você pode precisar **encontrá-los**.

### Identificando os pinos JTAG

A maneira mais rápida, mas mais cara, de detectar portas JTAG é usando o **JTAGulator**, um dispositivo criado especificamente para esse fim (embora ele também possa **detectar pinouts UART**).

Ele possui **24 canais** aos quais você pode conectar aos pinos das placas. Em seguida, ele realiza um **ataque BF** de todas as combinações possíveis enviando comandos de varredura de limite **IDCODE** e **BYPASS**. Se receber uma resposta, ele exibe o canal correspondente a cada sinal JTAG.

Uma maneira mais barata, mas muito mais lenta, de identificar pinouts JTAG é usando o [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) carregado em um microcontrolador compatível com Arduino.

Usando o **JTAGenum**, você primeiro **define os pinos do dispositivo de sondagem** que você usará para a enumeração. Você terá que fazer referência ao diagrama de pinos do dispositivo e, em seguida, conectar esses pinos aos pontos de teste em seu dispositivo alvo.

Uma **terceira maneira** de identificar os pinos JTAG é **inspecionando a PCB** em busca de um dos pinouts. Em alguns casos, as PCBs podem fornecer convenientemente a **interface Tag-Connect**, que é uma indicação clara de que a placa possui um conector JTAG também. Você pode ver como essa interface se parece em [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Além disso, inspecionar os **datasheets dos chipsets na PCB** pode revelar diagramas de pinout que apontam para interfaces JTAG.

## SDW

SWD é um protocolo específico da ARM projetado para depuração.

A interface SWD requer **dois pinos**: um sinal bidirecional **SWDIO**, que é equivalente aos pinos **TDI e TDO do JTAG e um clock**, e **SWCLK**, que é equivalente ao **TCK** no JTAG. Muitos dispositivos suportam a **Porta de Depuração Serial ou JTAG (SWJ-DP)**, uma interface combinada JTAG e SWD que permite conectar uma sonda SWD ou JTAG ao alvo.

<details>

<summary><strong>Aprenda hacking da AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

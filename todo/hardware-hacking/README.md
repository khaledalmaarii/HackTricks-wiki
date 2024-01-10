<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo do** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


#

# JTAG

JTAG permite realizar um boundary scan. O boundary scan analisa certos circuitos, incluindo células de boundary-scan embutidas e registros para cada pino.

O padrão JTAG define **comandos específicos para a realização de boundary scans**, incluindo os seguintes:

* **BYPASS** permite testar um chip específico sem a sobrecarga de passar por outros chips.
* **SAMPLE/PRELOAD** captura uma amostra dos dados que entram e saem do dispositivo quando está em seu modo de funcionamento normal.
* **EXTEST** configura e lê estados de pinos.

Ele também pode suportar outros comandos, como:

* **IDCODE** para identificar um dispositivo
* **INTEST** para o teste interno do dispositivo

Você pode se deparar com essas instruções ao usar uma ferramenta como o JTAGulator.

## The Test Access Port

Boundary scans incluem testes do **Test Access Port (TAP)** de quatro fios, um porto de propósito geral que fornece **acesso às funções de suporte de teste JTAG** incorporadas em um componente. O TAP usa os seguintes cinco sinais:

* Entrada de relógio de teste (**TCK**) O TCK é o **relógio** que define a frequência com que o controlador TAP realizará uma única ação (ou seja, avançar para o próximo estado na máquina de estados).
* Entrada de seleção de modo de teste (**TMS**) O TMS controla a **máquina de estados finitos**. A cada batida do relógio, o controlador TAP JTAG do dispositivo verifica a tensão no pino TMS. Se a tensão estiver abaixo de um certo limiar, o sinal é considerado baixo e interpretado como 0, enquanto se a tensão estiver acima de um certo limiar, o sinal é considerado alto e interpretado como 1.
* Entrada de dados de teste (**TDI**) O TDI é o pino que envia **dados para dentro do chip através das células de varredura**. Cada fornecedor é responsável por definir o protocolo de comunicação sobre este pino, porque o JTAG não define isso.
* Saída de dados de teste (**TDO**) O TDO é o pino que envia **dados para fora do chip**.
* Entrada de reset de teste (**TRST**) O TRST opcional reseta a máquina de estados finitos **para um estado conhecido como bom**. Alternativamente, se o TMS for mantido em 1 por cinco ciclos de relógio consecutivos, ele invoca um reset, da mesma forma que o pino TRST faria, razão pela qual o TRST é opcional.

Às vezes você poderá encontrar esses pinos marcados na PCB. Em outras ocasiões, você pode precisar **encontrá-los**.

## Identificando pinos JTAG

A maneira mais rápida, mas também mais cara, de detectar portas JTAG é usando o **JTAGulator**, um dispositivo criado especificamente para esse propósito (embora ele também possa **detectar pinouts UART**).

Ele possui **24 canais** que você pode conectar aos pinos da placa. Em seguida, ele realiza um **ataque BF** de todas as combinações possíveis enviando comandos de boundary scan **IDCODE** e **BYPASS**. Se receber uma resposta, ele exibe o canal correspondente a cada sinal JTAG.

Uma maneira mais barata, mas muito mais lenta, de identificar os pinouts JTAG é usando o [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) carregado em um microcontrolador compatível com Arduino.

Usando o **JTAGenum**, você primeiro **define os pinos do dispositivo de sondagem** que usará para a enumeração. Você teria que referenciar o diagrama de pinout do dispositivo e, em seguida, conectar esses pinos aos pontos de teste no seu dispositivo alvo.

Uma **terceira maneira** de identificar pinos JTAG é **inspecionando a PCB** em busca de um dos pinouts. Em alguns casos, as PCBs podem fornecer convenientemente a **interface Tag-Connect**, o que é uma indicação clara de que a placa também possui um conector JTAG. Você pode ver como essa interface se parece em [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Além disso, inspecionar os **datasheets dos chipsets na PCB** pode revelar diagramas de pinout que apontam para interfaces JTAG.

# SDW

SWD é um protocolo específico da ARM projetado para depuração.

A interface SWD requer **dois pinos**: um sinal bidirecional **SWDIO**, que é o equivalente aos pinos **TDI e TDO do JTAG e um relógio**, e **SWCLK**, que é o equivalente de **TCK** no JTAG. Muitos dispositivos suportam o **Serial Wire or JTAG Debug Port (SWJ-DP)**, uma interface JTAG e SWD combinada que permite conectar uma sonda SWD ou JTAG ao alvo.


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo do** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

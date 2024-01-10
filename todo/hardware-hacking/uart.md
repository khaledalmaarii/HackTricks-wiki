<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Informações Básicas

UART é um protocolo serial, o que significa que transfere dados entre componentes um bit por vez. Em contraste, protocolos de comunicação paralela transmitem dados simultaneamente através de múltiplos canais. Protocolos seriais comuns incluem RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express e USB.

Geralmente, a linha é mantida alta (em um valor lógico 1) enquanto o UART está no estado ocioso. Então, para sinalizar o início de uma transferência de dados, o transmissor envia um bit de início para o receptor, durante o qual o sinal é mantido baixo (em um valor lógico 0). Em seguida, o transmissor envia de cinco a oito bits de dados contendo a mensagem real, seguidos por um bit de paridade opcional e um ou dois bits de parada (com um valor lógico 1), dependendo da configuração. O bit de paridade, usado para verificação de erros, é raramente visto na prática. O bit de parada (ou bits) sinaliza o fim da transmissão.

Chamamos a configuração mais comum de 8N1: oito bits de dados, sem paridade e um bit de parada. Por exemplo, se quiséssemos enviar o caractere C, ou 0x43 em ASCII, em uma configuração UART 8N1, enviaríamos os seguintes bits: 0 (o bit de início); 0, 1, 0, 0, 0, 0, 1, 1 (o valor de 0x43 em binário), e 1 (o bit de parada).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

Ferramentas de hardware para se comunicar com UART:

* Adaptador USB-para-serial
* Adaptadores com os chips CP2102 ou PL2303
* Ferramenta multipropósito como: Bus Pirate, o Adafruit FT232H, o Shikra ou o Attify Badge

## Identificando Portas UART

UART tem 4 portas: **TX**(Transmitir), **RX**(Receber), **Vcc**(Voltagem) e **GND**(Terra). Você pode ser capaz de encontrar 4 portas com as letras **`TX`** e **`RX`** **escritas** na PCB. Mas se não houver indicação, talvez seja necessário tentar encontrá-las por conta própria usando um **multímetro** ou um **analisador lógico**.

Com um **multímetro** e o dispositivo desligado:

* Para identificar o pino **GND**, use o modo **Teste de Continuidade**, coloque o cabo preto no terra e teste com o vermelho até ouvir um som do multímetro. Vários pinos GND podem ser encontrados na PCB, então você pode ter encontrado ou não o pertencente ao UART.
* Para identificar o **porta VCC**, ajuste o modo de **tensão DC** e configure para 20 V de tensão. Sonda preta no terra e sonda vermelha no pino. Ligue o dispositivo. Se o multímetro medir uma tensão constante de 3,3 V ou 5 V, você encontrou o pino Vcc. Se você obter outras tensões, tente novamente com outros portos.
* Para identificar o **porta TX**, modo de **tensão DC** até 20 V de tensão, sonda preta no terra e sonda vermelha no pino, e ligue o dispositivo. Se você encontrar a tensão flutuando por alguns segundos e depois estabilizando no valor Vcc, é provável que tenha encontrado o porta TX. Isso ocorre porque, ao ligar, ele envia alguns dados de depuração.
* O **porta RX** seria o mais próximo dos outros 3, tem a menor flutuação de tensão e o menor valor geral de todos os pinos UART.

Você pode confundir os portos TX e RX e nada aconteceria, mas se confundir os portos GND e VCC, você pode queimar o circuito.

Com um analisador lógico:

## Identificando a Taxa de Baud do UART

A maneira mais fácil de identificar a taxa de baud correta é olhar para a **saída do pino TX e tentar ler os dados**. Se os dados recebidos não forem legíveis, mude para a próxima taxa de baud possível até que os dados se tornem legíveis. Você pode usar um adaptador USB-para-serial ou um dispositivo multipropósito como o Bus Pirate para fazer isso, emparelhado com um script auxiliar, como [baudrate.py](https://github.com/devttys0/baudrate/). As taxas de baud mais comuns são 9600, 38400, 19200, 57600 e 115200.

{% hint style="danger" %}
É importante notar que neste protocolo você precisa conectar o TX de um dispositivo ao RX do outro!
{% endhint %}

# Bus Pirate

Neste cenário, vamos monitorar a comunicação UART do Arduino que está enviando todas as impressões do programa para o Monitor Serial.
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


# Informações Básicas

SPI (Serial Peripheral Interface) é um Protocolo de Comunicação Serial Síncrona usado em sistemas embarcados para comunicação de curta distância entre CIs (Circuitos Integrados). O Protocolo de Comunicação SPI faz uso da arquitetura mestre-escravo que é orquestrada pelo Sinal de Clock e Chip Select. Uma arquitetura mestre-escravo consiste em um mestre (geralmente um microprocessador) que gerencia periféricos externos como EEPROM, sensores, dispositivos de controle, etc., que são considerados como escravos.

Vários escravos podem ser conectados a um mestre, mas os escravos não podem se comunicar entre si. Os escravos são administrados por dois pinos, clock e chip select. Como o SPI é um protocolo de comunicação síncrona, os pinos de entrada e saída seguem os sinais de clock. O chip select é usado pelo mestre para selecionar um escravo e interagir com ele. Quando o chip select está alto, o dispositivo escravo não está selecionado, enquanto quando está baixo, o chip foi selecionado e o mestre estaria interagindo com o escravo.

O MOSI (Master Out, Slave In) e MISO (Master In, Slave Out) são responsáveis pelo envio e recebimento de dados. Os dados são enviados para o dispositivo escravo através do pino MOSI enquanto o chip select é mantido baixo. Os dados de entrada contêm instruções, endereços de memória ou dados conforme a folha de dados do fornecedor do dispositivo escravo. Após uma entrada válida, o pino MISO é responsável por transmitir dados para o mestre. Os dados de saída são enviados exatamente no próximo ciclo de clock após o término da entrada. Os pinos MISO transmitem dados até que os dados sejam totalmente transmitidos ou o mestre defina o pino de chip select como alto (nesse caso, o escravo pararia de transmitir e o mestre não ouviria após esse ciclo de clock).

# Dump Flash

## Bus Pirate + flashrom

![](<../../.gitbook/assets/image (201).png>)

Observe que mesmo que o PINOUT do Pirate Bus indique pinos para **MOSI** e **MISO** para se conectar ao SPI, no entanto, alguns SPIs podem indicar pinos como DI e DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (648) (1) (1).png>)

No Windows ou Linux, você pode usar o programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para despejar o conteúdo da memória flash executando algo como:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

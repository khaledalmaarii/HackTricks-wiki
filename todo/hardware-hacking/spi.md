# SPI

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Informações Básicas

SPI (Serial Peripheral Interface) é um Protocolo de Comunicação Serial Síncrono usado em sistemas embarcados para comunicação de curta distância entre CIs (Circuitos Integrados). O Protocolo de Comunicação SPI faz uso da arquitetura mestre-escravo que é orquestrada pelo Sinal de Clock e Chip Select. Uma arquitetura mestre-escravo consiste em um mestre (geralmente um microprocessador) que gerencia periféricos externos como EEPROM, sensores, dispositivos de controle, etc., que são considerados escravos.

Vários escravos podem ser conectados a um mestre, mas os escravos não podem se comunicar entre si. Os escravos são administrados por dois pinos, clock e chip select. Como o SPI é um protocolo de comunicação síncrono, os pinos de entrada e saída seguem os sinais de clock. O chip select é usado pelo mestre para selecionar um escravo e interagir com ele. Quando o chip select está alto, o dispositivo escravo não está selecionado, enquanto quando está baixo, o chip foi selecionado e o mestre estaria interagindo com o escravo.

O MOSI (Master Out, Slave In) e MISO (Master In, Slave Out) são responsáveis pelo envio e recebimento de dados. Os dados são enviados para o dispositivo escravo através do pino MOSI enquanto o chip select é mantido baixo. Os dados de entrada contêm instruções, endereços de memória ou dados conforme a folha de dados do fornecedor do dispositivo escravo. Após uma entrada válida, o pino MISO é responsável por transmitir dados para o mestre. Os dados de saída são enviados exatamente no próximo ciclo de clock após o término da entrada. Os pinos MISO transmitem dados até que os dados sejam totalmente transmitidos ou o mestre defina o pino de chip select como alto (nesse caso, o escravo pararia de transmitir e o mestre não ouviria após esse ciclo de clock).

## Despejando Firmware de EEPROMs

Despejar firmware pode ser útil para analisar o firmware e encontrar vulnerabilidades neles. Muitas vezes, o firmware não está disponível na internet ou é irrelevante devido a variações de fatores como número do modelo, versão, etc. Portanto, extrair o firmware diretamente do dispositivo físico pode ser útil para ser específico ao procurar ameaças.

Obter um Console Serial pode ser útil, mas muitas vezes acontece que os arquivos são somente leitura. Isso limita a análise devido a vários motivos. Por exemplo, ferramentas necessárias para enviar e receber pacotes não estariam presentes no firmware. Portanto, extrair os binários para engenharia reversa não é viável. Portanto, ter todo o firmware despejado no sistema e extrair os binários para análise pode ser muito útil.

Além disso, durante a análise e obtenção de acesso físico aos dispositivos, despejar o firmware pode ajudar a modificar os arquivos ou injetar arquivos maliciosos e depois regravá-los na memória, o que poderia ser útil para implantar uma porta dos fundos no dispositivo. Portanto, existem inúmeras possibilidades que podem ser desbloqueadas com o despejo de firmware.

### Programador e Leitor de EEPROM CH341A

Este dispositivo é uma ferramenta barata para despejar firmwares de EEPROMs e também regravá-los com arquivos de firmware. Esta tem sido uma escolha popular para trabalhar com chips de BIOS de computador (que são apenas EEPROMs). Este dispositivo se conecta via USB e precisa de ferramentas mínimas para começar. Além disso, geralmente conclui a tarefa rapidamente, então pode ser útil também no acesso físico ao dispositivo.

<img src="../../.gitbook/assets/board_image_ch341a.jpg" alt="drawing" width="400" align="center"/>

Conecte a memória EEPROM ao Programador CH341a e conecte o dispositivo ao computador. Caso o dispositivo não seja detectado, tente instalar os drivers no computador. Além disso, certifique-se de que a EEPROM está conectada na orientação correta (geralmente, coloque o Pino VCC na orientação reversa ao conector USB) caso contrário, o software não conseguirá detectar o chip. Consulte o diagrama se necessário:

<img src="../../.gitbook/assets/connect_wires_ch341a.jpg" alt="drawing" width="350"/>

<img src="../../.gitbook/assets/eeprom_plugged_ch341a.jpg" alt="drawing" width="350"/>

Por fim, use softwares como flashrom, G-Flash (GUI), etc. para despejar o firmware. O G-Flash é uma ferramenta GUI mínima, rápida e detecta automaticamente a EEPROM. Isso pode ser útil se o firmware precisar ser extraído rapidamente, sem muita manipulação da documentação.

<img src="../../.gitbook/assets/connected_status_ch341a.jpg" alt="drawing" width="350"/>

Após despejar o firmware, a análise pode ser feita nos arquivos binários. Ferramentas como strings, hexdump, xxd, binwalk, etc. podem ser usadas para extrair muitas informações sobre o firmware, bem como todo o sistema de arquivos também.

Para extrair o conteúdo do firmware, o binwalk pode ser usado. O Binwalk analisa assinaturas hexadecimais e identifica os arquivos no arquivo binário e é capaz de extraí-los.
```
binwalk -e <filename>
```
O <filename> pode ser .bin ou .rom de acordo com as ferramentas e configurações utilizadas.

{% hint style="danger" %} Note que a extração de firmware é um processo delicado e requer muita paciência. Qualquer manuseio incorreto pode potencialmente corromper o firmware ou até mesmo apagá-lo completamente, tornando o dispositivo inutilizável. É recomendado estudar o dispositivo específico antes de tentar extrair o firmware. {% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (907).png>)

Note que mesmo que o PINOUT do Bus Pirate indique pinos para **MOSI** e **MISO** para se conectar ao SPI, no entanto, alguns SPIs podem indicar os pinos como DI e DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (357).png>)

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
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

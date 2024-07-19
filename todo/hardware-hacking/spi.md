# SPI

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

## Informações Básicas

SPI (Serial Peripheral Interface) é um Protocolo de Comunicação Serial Síncrono usado em sistemas embarcados para comunicação de curta distância entre ICs (Circuitos Integrados). O Protocolo de Comunicação SPI utiliza a arquitetura mestre-escravo, que é orquestrada pelo Clock e pelo Sinal de Seleção de Chip. Uma arquitetura mestre-escravo consiste em um mestre (geralmente um microprocessador) que gerencia periféricos externos como EEPROM, sensores, dispositivos de controle, etc., que são considerados escravos.

Múltiplos escravos podem ser conectados a um mestre, mas os escravos não podem se comunicar entre si. Os escravos são administrados por dois pinos, clock e seleção de chip. Como o SPI é um protocolo de comunicação síncrono, os pinos de entrada e saída seguem os sinais de clock. A seleção de chip é usada pelo mestre para selecionar um escravo e interagir com ele. Quando a seleção de chip está alta, o dispositivo escravo não é selecionado, enquanto quando está baixa, o chip foi selecionado e o mestre estaria interagindo com o escravo.

O MOSI (Master Out, Slave In) e o MISO (Master In, Slave Out) são responsáveis pelo envio e recebimento de dados. Os dados são enviados para o dispositivo escravo através do pino MOSI enquanto a seleção de chip é mantida baixa. Os dados de entrada contêm instruções, endereços de memória ou dados conforme a folha de dados do fornecedor do dispositivo escravo. Após uma entrada válida, o pino MISO é responsável por transmitir dados para o mestre. Os dados de saída são enviados exatamente no próximo ciclo de clock após o término da entrada. O pino MISO transmite dados até que os dados sejam totalmente transmitidos ou o mestre defina o pino de seleção de chip como alto (nesse caso, o escravo pararia de transmitir e o mestre não ouviria após esse ciclo de clock).

## Dumping de Firmware de EEPROMs

Fazer o dump de firmware pode ser útil para analisar o firmware e encontrar vulnerabilidades nele. Muitas vezes, o firmware não está disponível na internet ou é irrelevante devido a variações de fatores como número do modelo, versão, etc. Portanto, extrair o firmware diretamente do dispositivo físico pode ser útil para ser específico ao caçar ameaças.

Obter o Console Serial pode ser útil, mas muitas vezes acontece que os arquivos são somente leitura. Isso limita a análise por várias razões. Por exemplo, ferramentas que são necessárias para enviar e receber pacotes podem não estar presentes no firmware. Portanto, extrair os binários para engenharia reversa não é viável. Assim, ter o firmware completo despejado no sistema e extrair os binários para análise pode ser muito útil.

Além disso, durante o red teaming e ao obter acesso físico a dispositivos, fazer o dump do firmware pode ajudar a modificar os arquivos ou injetar arquivos maliciosos e, em seguida, regravar esses arquivos na memória, o que pode ser útil para implantar um backdoor no dispositivo. Portanto, existem inúmeras possibilidades que podem ser desbloqueadas com o dumping de firmware.

### Programador e Leitor de EEPROM CH341A

Este dispositivo é uma ferramenta econômica para fazer o dump de firmwares de EEPROMs e também regravar com arquivos de firmware. Este tem sido uma escolha popular para trabalhar com chips BIOS de computador (que são apenas EEPROMs). Este dispositivo se conecta via USB e precisa de ferramentas mínimas para começar. Além disso, geralmente realiza a tarefa rapidamente, o que pode ser útil no acesso físico ao dispositivo também.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

Conecte a memória EEPROM ao Programador CH341a e conecte o dispositivo ao computador. Caso o dispositivo não seja detectado, tente instalar drivers no computador. Além disso, certifique-se de que a EEPROM está conectada na orientação correta (geralmente, coloque o pino VCC na orientação reversa em relação ao conector USB) ou, caso contrário, o software não conseguirá detectar o chip. Consulte o diagrama se necessário:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Finalmente, use softwares como flashrom, G-Flash (GUI), etc. para fazer o dump do firmware. G-Flash é uma ferramenta GUI mínima, rápida e detecta a EEPROM automaticamente. Isso pode ser útil quando o firmware precisa ser extraído rapidamente, sem muitas alterações na documentação.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Após fazer o dump do firmware, a análise pode ser realizada nos arquivos binários. Ferramentas como strings, hexdump, xxd, binwalk, etc. podem ser usadas para extrair muitas informações sobre o firmware, bem como sobre todo o sistema de arquivos.

Para extrair os conteúdos do firmware, o binwalk pode ser usado. O binwalk analisa assinaturas hexadecimais e identifica os arquivos no arquivo binário e é capaz de extraí-los.
```
binwalk -e <filename>
```
O arquivo pode ser .bin ou .rom de acordo com as ferramentas e configurações utilizadas.

{% hint style="danger" %}
Observe que a extração de firmware é um processo delicado e requer muita paciência. Qualquer manuseio inadequado pode potencialmente corromper o firmware ou até mesmo apagá-lo completamente, tornando o dispositivo inutilizável. É recomendável estudar o dispositivo específico antes de tentar extrair o firmware.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Observe que, mesmo que o PINOUT do Pirate Bus indique pinos para **MOSI** e **MISO** para conectar ao SPI, alguns SPIs podem indicar pinos como DI e DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

No Windows ou Linux, você pode usar o programa [**`flashrom`**](https://www.flashrom.org/Flashrom) para despejar o conteúdo da memória flash executando algo como:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

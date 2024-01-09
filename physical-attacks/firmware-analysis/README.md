# Análise de Firmware

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introdução

Firmware é um tipo de software que fornece comunicação e controle sobre os componentes de hardware de um dispositivo. É o primeiro código executado por um dispositivo. Geralmente, **inicializa o sistema operacional** e fornece serviços de execução específicos para programas ao **comunicar-se com vários componentes de hardware**. A maioria, se não todos, os dispositivos eletrônicos possuem firmware.

Dispositivos armazenam firmware em **memória não volátil**, como ROM, EPROM ou memória flash.

É importante **examinar** o **firmware** e depois tentar **modificá-lo**, pois podemos descobrir muitos problemas de segurança durante esse processo.

## **Coleta de informações e reconhecimento**

Durante esta etapa, colete o máximo de informações possíveis sobre o alvo para entender sua composição geral e tecnologia subjacente. Tente reunir o seguinte:

* Arquiteturas de CPU suportadas
* Plataforma do sistema operacional
* Configurações do bootloader
* Esquemas de hardware
* Fichas técnicas
* Estimativas de linhas de código (LoC)
* Localização do repositório de código-fonte
* Componentes de terceiros
* Licenças de código aberto (por exemplo, GPL)
* Registros de alterações
* IDs da FCC
* Diagramas de design e fluxo de dados
* Modelos de ameaças
* Relatórios de testes de penetração anteriores
* Tickets de rastreamento de bugs (por exemplo, Jira e plataformas de bug bounty como BugCrowd ou HackerOne)

Quando possível, adquira dados usando ferramentas e técnicas de inteligência de fontes abertas (OSINT). Se software de código aberto for usado, baixe o repositório e realize análises estáticas manuais e automatizadas contra a base de código. Às vezes, projetos de software de código aberto já utilizam ferramentas de análise estática gratuitas fornecidas por fornecedores que disponibilizam resultados de varredura como [Coverity Scan](https://scan.coverity.com) e [LGTM da Semmle](https://lgtm.com/#explore).

## Obtendo o Firmware

Existem diferentes maneiras com diferentes níveis de dificuldade para baixar o firmware

* **Diretamente** da equipe de desenvolvimento, fabricante/fornecedor ou cliente
* **Construir do zero** usando tutoriais fornecidos pelo fabricante
* Do **site de suporte do fornecedor**
* Consultas **Google dork** direcionadas a extensões de arquivos binários e plataformas de compartilhamento de arquivos como Dropbox, Box e Google Drive
* É comum encontrar imagens de firmware através de clientes que fazem upload de conteúdos para fóruns, blogs ou comentam em sites onde entraram em contato com o fabricante para solucionar um problema e receberam firmware via zip ou pen drive.
* Exemplo: `intitle:"Netgear" intext:"Firmware Download"`
* Baixar builds de locais de armazenamento expostos de provedores de nuvem como Amazon Web Services (AWS) S3 buckets (com ferramentas como [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner))
* **Interceptar** comunicação do dispositivo durante **atualizações**
* Extrair diretamente **do hardware** via **UART**, **JTAG**, **PICit**, etc.
* Capturar **comunicação serial** dentro dos componentes de hardware para **solicitações de servidor de atualização**
* Via um **endpoint codificado** dentro dos aplicativos móveis ou robustos
* **Despejar** firmware do **bootloader** (por exemplo, U-boot) para armazenamento flash ou pela **rede** via **tftp**
* Remover o **chip de flash** (por exemplo, SPI) ou MCU da placa para análise offline e extração de dados (ÚLTIMO RECURSO).
* Você precisará de um programador de chip compatível para armazenamento flash e/ou o MCU.

## Analisando o firmware

Agora que você **tem o firmware**, precisa extrair informações sobre ele para saber como tratá-lo. Diferentes ferramentas que você pode usar para isso:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se você não encontrar muito com essas ferramentas, verifique a **entropia** da imagem com `binwalk -E <bin>`, se a entropia for baixa, então é improvável que esteja criptografada. Se a entropia for alta, é provável que esteja criptografada (ou comprimida de alguma forma).

Além disso, você pode usar essas ferramentas para extrair **arquivos embutidos no firmware**:

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Ou [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o Sistema de Arquivos

Com as ferramentas mencionadas anteriormente, como `binwalk -ev <bin>`, você deve ter conseguido **extrair o sistema de arquivos**.\
O Binwalk geralmente extrai dentro de uma **pasta com o nome do tipo de sistema de arquivos**, que geralmente é um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extração Manual do Sistema de Arquivos

Às vezes, o binwalk **não terá o byte mágico do sistema de arquivos em suas assinaturas**. Nestes casos, use o binwalk para **encontrar o deslocamento do sistema de arquivos e recortar o sistema de arquivos comprimido** do binário e **extrair manualmente** o sistema de arquivos de acordo com seu tipo, usando os passos abaixo.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Execute o seguinte **comando dd** para extrair o sistema de arquivos Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativamente, o seguinte comando também pode ser executado.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Para squashfs (usado no exemplo acima)

`$ unsquashfs dir.squashfs`

Os arquivos estarão no diretório "`squashfs-root`" depois.

* Arquivos de arquivo CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Para sistemas de arquivos jffs2

`$ jefferson rootfsfile.jffs2`

* Para sistemas de arquivos ubifs com flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Analisando o Sistema de Arquivos

Agora que você tem o sistema de arquivos, é hora de começar a procurar por más práticas, como:

* **Daemons de rede inseguros** legados, como telnetd (às vezes os fabricantes renomeiam binários para disfarçar)
* **Credenciais codificadas** (nomes de usuário, senhas, chaves de API, chaves SSH e variantes de backdoor)
* **APIs codificadas** e detalhes do servidor backend
* **Funcionalidade do servidor de atualização** que pode ser usada como ponto de entrada
* **Revisar código não compilado e scripts de inicialização** para execução remota de código
* **Extrair binários compilados** para serem usados para análise offline com um desmontador para etapas futuras

Algumas **coisas interessantes para procurar** dentro do firmware:

* etc/shadow e etc/passwd
* listar o diretório etc/ssl
* procurar por arquivos relacionados a SSL, como .pem, .crt, etc.
* procurar por arquivos de configuração
* procurar por arquivos de script
* procurar por outros arquivos .bin
* procurar por palavras-chave como admin, password, remote, chaves AWS, etc.
* procurar por servidores web comuns em dispositivos IoT
* procurar por binários comuns como ssh, tftp, dropbear, etc.
* procurar por funções c proibidas
* procurar por funções vulneráveis a injeção de comandos
* procurar por URLs, endereços de e-mail e endereços IP
* e mais…

Ferramentas que procuram por esse tipo de informação (mesmo que você sempre deva dar uma olhada manual e se familiarizar com a estrutura do sistema de arquivos, as ferramentas podem ajudá-lo a encontrar **coisas ocultas**):

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng)**:** Script bash incrível que, neste caso, é útil para procurar **informações sensíveis** dentro do sistema de arquivos. Basta **entrar no chroot no sistema de arquivos do firmware e executá-lo**.
* [**Firmwalker**](https://github.com/craigz28/firmwalker)**:** Script bash para procurar informações sensíveis em potencial
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core):
* Identificação de componentes de software, como sistema operacional, arquitetura de CPU e componentes de terceiros, juntamente com suas informações de versão associadas
* Extração do sistema de arquivos do firmware (s) de imagens
* Detecção de certificados e chaves privadas
* Detecção de implementações fracas mapeadas para a Enumeração de Fraquezas Comuns (CWE)
* Detecção baseada em feed e assinatura de vulnerabilidades
* Análise comportamental estática básica
* Comparação (diff) de versões e arquivos de firmware
* Emulação em modo usuário de binários do sistema de arquivos usando QEMU
* Detecção de mitigações binárias, como NX, DEP, ASLR, canários de pilha, RELRO e FORTIFY_SOURCE
* API REST
* e mais...
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer): FwAnalyzer é uma ferramenta para analisar imagens de sistemas de arquivos (ext2/3/4), FAT/VFat, SquashFS, UBIFS, arquivos de arquivo cpio e conteúdo de diretórios usando um conjunto de regras configuráveis.
* [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep): Uma Ferramenta de Análise de Segurança de Firmware IoT de Software Livre
* [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go): Esta é uma reescrita completa do projeto original ByteSweep em Go.
* [**EMBA**](https://github.com/e-m-b-a/emba): _EMBA_ é projetado como a ferramenta central de análise de firmware para pentesters. Ele suporta todo o processo de análise de segurança, começando com o processo de _extração de firmware_, fazendo _análise estática_ e _análise dinâmica_ por meio de emulação e, finalmente, gerando um relatório. _EMBA_ descobre automaticamente possíveis pontos fracos e vulnerabilidades no firmware. Exemplos são binários inseguros, componentes de software antigos e desatualizados, scripts potencialmente vulneráveis ou senhas codificadas.

{% hint style="warning" %}
Dentro do sistema de arquivos, você também pode encontrar **código-fonte** de programas (que você sempre deve **verificar**), mas também **binários compilados**. Esses programas podem estar de alguma forma expostos e você deve **decompilar** e **verificar** eles para potenciais vulnerabilidades.

Ferramentas como [**checksec.sh**](https://github.com/slimm609/checksec.sh) podem ser úteis para encontrar binários desprotegidos. Para binários do Windows, você pode usar [**PESecurity**](https://github.com/NetSPI/PESecurity).
{% endhint %}

## Emulando Firmware

A ideia de emular o Firmware é poder realizar uma **análise dinâmica** do dispositivo **em execução** ou de um **programa individual**.

{% hint style="info" %}
Às vezes, a emulação parcial ou completa **pode não funcionar devido a dependências de hardware ou arquitetura**. Se a arquitetura e a endianness corresponderem a um dispositivo que você possui, como um raspberry pie, o sistema de arquivos raiz ou binário específico pode ser transferido para o dispositivo para testes adicionais. Este método também se aplica a máquinas virtuais pré-construídas usando a mesma arquitetura e endianness do alvo.
{% endhint %}

### Emulação Binária

Se você deseja emular apenas um programa para procurar vulnerabilidades, primeiro precisa identificar sua endianness e a arquitetura da CPU para a qual foi compilado.

#### Exemplo MIPS
```bash
file ./squashfs-root/bin/busybox
./squashfs-root/bin/busybox: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```
Agora você pode **emular** o executável busybox usando **QEMU**.
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Como o executável **é** compilado para **MIPS** e segue a ordenação de bytes **big-endian**, usaremos o emulador **`qemu-mips`** do QEMU. Para emular executáveis **little-endian**, teríamos que selecionar o emulador com o sufixo `el` (`qemu-mipsel`):
```bash
qemu-mips -L ./squashfs-root/ ./squashfs-root/bin/ls
100              100.7z           15A6D2.squashfs  squashfs-root    squashfs-root-0
```
#### Exemplo ARM
```bash
file bin/busybox
bin/busybox: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-armhf.so.1, no section header
```
Emulação:
```bash
qemu-arm -L ./squashfs-root/ ./squashfs-root/bin/ls
1C00000.squashfs  B80B6C            C41DD6.xz         squashfs-root     squashfs-root-0
```
### Emulação Completa do Sistema

Existem várias ferramentas, baseadas em **qemu** em geral, que permitem emular o firmware completo:

* [**https://github.com/firmadyne/firmadyne**](https://github.com/firmadyne/firmadyne)**:**
* É necessário instalar várias coisas, configurar o postgres, depois executar o script extractor.py para extrair o firmware, usar o script getArch.sh para obter a arquitetura. Em seguida, usar os scripts tar2db.py e makeImage.sh para armazenar informações da imagem extraída no banco de dados e gerar uma imagem QEMU que podemos emular. Depois, usar o script inferNetwork.sh para obter as interfaces de rede, e finalmente usar o script run.sh, que é automaticamente criado na pasta ./scratch/1/.
* [**https://github.com/attify/firmware-analysis-toolkit**](https://github.com/attify/firmware-analysis-toolkit)**:**
* Esta ferramenta depende do firmadyne e automatiza o processo de emulação do firmware usando firmadynee. é necessário configurar `fat.config` antes de usá-lo: `sudo python3 ./fat.py IoTGoat-rpi-2.img --qemu 2.5.0`
* [**https://github.com/therealsaumil/emux**](https://github.com/therealsaumil/emux)
* [**https://github.com/getCUJO/MIPS-X**](https://github.com/getCUJO/MIPS-X)
* [**https://github.com/qilingframework/qiling#qltool**](https://github.com/qilingframework/qiling#qltool)

## **Análise Dinâmica**

Nesta etapa, você deve ter um dispositivo executando o firmware para atacar ou o firmware sendo emulado para atacar. Em qualquer caso, é altamente recomendável que você também tenha **um shell no OS e no sistema de arquivos que está em execução**.

Observe que, às vezes, se você estiver emulando o firmware, **algumas atividades dentro da emulação podem falhar** e você pode precisar reiniciar a emulação. Por exemplo, uma aplicação web pode precisar obter informações de um dispositivo com o qual o dispositivo original está integrado, mas a emulação não está emulando.

Você deve **reverificar o sistema de arquivos**, como já fizemos em um **passo anterior, pois no ambiente em execução novas informações podem estar acessíveis.**

Se **páginas web** estiverem expostas, lendo o código e tendo acesso a elas, você deve **testá-las**. No hacktricks, você pode encontrar muitas informações sobre diferentes técnicas de hacking web.

Se **serviços de rede** estiverem expostos, você deve tentar atacá-los. No hacktricks, você pode encontrar muitas informações sobre diferentes técnicas de hacking de serviços de rede. Você também pode tentar fuzzá-los com **fuzzers** de rede e protocolo, como [Mutiny](https://github.com/Cisco-Talos/mutiny-fuzzer), [boofuzz](https://github.com/jtpereyda/boofuzz) e [kitty](https://github.com/cisco-sas/kitty).

Você deve verificar se pode **atacar o bootloader** para obter um shell root:

{% content-ref url="bootloader-testing.md" %}
[bootloader-testing.md](bootloader-testing.md)
{% endcontent-ref %}

Você deve testar se o dispositivo está realizando algum tipo de **testes de integridade do firmware**; se não, isso permitiria que atacantes oferecessem firmwares com backdoor, instalassem-nos em dispositivos de outras pessoas ou até os implantassem remotamente se houver alguma vulnerabilidade de atualização de firmware:

{% content-ref url="firmware-integrity.md" %}
[firmware-integrity.md](firmware-integrity.md)
{% endcontent-ref %}

Vulnerabilidades de atualização de firmware geralmente ocorrem porque a **integridade** do **firmware** pode **não** ser **validada**, uso de protocolos de **rede** **não criptografados**, uso de **credenciais** **hardcoded**, uma **autenticação insegura** ao componente na nuvem que hospeda o firmware e até mesmo **logging** excessivo e inseguro (dados sensíveis), permitir **atualizações físicas** sem verificações.

## **Análise em Tempo de Execução**

A análise em tempo de execução envolve se conectar a um processo ou binário em execução enquanto um dispositivo está funcionando em seu ambiente normal ou emulado. Abaixo estão os passos básicos para análise em tempo de execução:

1. `sudo chroot . ./qemu-arch -L <optionalLibPath> -g <gdb_port> <binary>`
2. Anexar gdb-multiarch ou usar IDA para emular o binário
3. Definir pontos de interrupção para funções identificadas durante a etapa 4, como memcpy, strncpy, strcmp, etc.
4. Executar strings de carga útil grandes para identificar estouros ou falhas no processo usando um fuzzer
5. Avançar para a etapa 8 se uma vulnerabilidade for identificada

Ferramentas que podem ser úteis são (não exaustivas):

* gdb-multiarch
* [Peda](https://github.com/longld/peda)
* Frida
* ptrace
* strace
* IDA Pro
* Ghidra
* Binary Ninja
* Hopper

## **Exploração Binária**

Após identificar uma vulnerabilidade dentro de um binário nas etapas anteriores, é necessário um proof-of-concept (PoC) adequado para demonstrar o impacto e o risco no mundo real. Desenvolver código de exploração requer experiência em programação em linguagens de baixo nível (por exemplo, ASM, C/C++, shellcode, etc.) bem como conhecimento na arquitetura alvo específica (por exemplo, MIPS, ARM, x86 etc.). O código PoC envolve obter execução arbitrária em um dispositivo ou aplicativo controlando uma instrução na memória.

Não é comum que proteções de tempo de execução binário (por exemplo, NX, DEP, ASLR, etc.) estejam em vigor em sistemas embarcados; no entanto, quando isso acontece, técnicas adicionais podem ser necessárias, como programação orientada a retorno (ROP). ROP permite que um atacante implemente funcionalidade maliciosa arbitrária encadeando código existente no processo/binário alvo conhecido como gadgets. Serão necessárias etapas para explorar uma vulnerabilidade identificada, como um estouro de buffer, formando uma cadeia ROP. Uma ferramenta que pode ser útil para situações como essas é o localizador de gadgets da Capstone ou ROPGadget - [https://github.com/JonathanSalwan/ROPgadget](https://github.com/JonathanSalwan/ROPgadget).

Utilize as seguintes referências para orientação adicional:

* [https://azeria-labs.com/writing-arm-shellcode/](https://azeria-labs.com/writing-arm-shellcode/)
* [https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/](https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/)

## OSs Preparados para Analisar Firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distribuição destinada a ajudá-lo a realizar avaliação de segurança e pentesting de dispositivos Internet of Things (IoT). Poupa muito tempo ao fornecer um ambiente pré-configurado com todas as ferramentas necessárias carregadas.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operacional de teste de segurança embarcado baseado no Ubuntu 18.04 pré-carregado com ferramentas de teste de segurança de firmware.

## Firmware Vulnerável para Prática

Para praticar a descoberta de vulnerabilidades em firmware, use os seguintes projetos de firmware vulneráveis como ponto de partida.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Referências

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Treinamento e Certificação

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

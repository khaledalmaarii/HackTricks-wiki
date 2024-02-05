# Partições/Sistemas de Arquivos/Carving

## Partições/Sistemas de Arquivos/Carving

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Partições

Um disco rígido ou um **disco SSD pode conter diferentes partições** com o objetivo de separar fisicamente os dados.\
A **unidade mínima** de um disco é o **setor** (normalmente composto por 512B). Portanto, o tamanho de cada partição precisa ser um múltiplo desse tamanho.

### MBR (Master Boot Record)

É alocado no **primeiro setor do disco após os 446B do código de inicialização**. Este setor é essencial para indicar ao PC o que e de onde uma partição deve ser montada.\
Ele permite até **4 partições** (no máximo **apenas 1** pode ser ativa/**inicializável**). No entanto, se você precisar de mais partições, pode usar **partições estendidas**. O **último byte** deste primeiro setor é a assinatura do registro de inicialização **0x55AA**. Apenas uma partição pode ser marcada como ativa.\
MBR permite **máximo de 2,2TB**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

Dos **bytes 440 a 443** do MBR, você pode encontrar a **Assinatura do Disco do Windows** (se o Windows for usado). A letra da unidade lógica do disco rígido depende da Assinatura do Disco do Windows. Alterar esta assinatura pode impedir o Windows de inicializar (ferramenta: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Formato**

| Offset      | Comprimento | Item                |
| ----------- | ----------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Código de inicialização |
| 446 (0x1BE) | 16 (0x10)  | Primeira Partição     |
| 462 (0x1CE) | 16 (0x10)  | Segunda Partição    |
| 478 (0x1DE) | 16 (0x10)  | Terceira Partição     |
| 494 (0x1EE) | 16 (0x10)  | Quarta Partição    |
| 510 (0x1FE) | 2 (0x2)    | Assinatura 0x55 0xAA |

**Formato do Registro de Partição**

| Offset    | Comprimento | Item                                                   |
| --------- | ----------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01)    | Sinalizador ativo (0x80 = inicializável)                          |
| 1 (0x01)  | 1 (0x01)    | Cabeça de início                                             |
| 2 (0x02)  | 1 (0x01)    | Setor de início (bits 0-5); bits superiores do cilindro (6- 7) |
| 3 (0x03)  | 1 (0x01)    | Bits mais baixos do cilindro de início                           |
| 4 (0x04)  | 1 (0x01)    | Código do tipo de partição (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01)    | Cabeça final                                               |
| 6 (0x06)  | 1 (0x01)    | Setor final (bits 0-5); bits superiores do cilindro (6- 7)   |
| 7 (0x07)  | 1 (0x01)    | Bits mais baixos do cilindro final                             |
| 8 (0x08)  | 4 (0x04)    | Setores anteriores à partição (pouco endian)            |
| 12 (0x0C) | 4 (0x04)    | Setores na partição                                   |

Para montar um MBR no Linux, primeiro você precisa obter o deslocamento de início (você pode usar `fdisk` e o comando `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

E então use o seguinte código
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Endereçamento de bloco lógico)**

**Endereçamento de bloco lógico** (**LBA**) é um esquema comum usado para **especificar a localização de blocos** de dados armazenados em dispositivos de armazenamento de computador, geralmente sistemas de armazenamento secundário como discos rígidos. O LBA é um esquema de endereçamento linear particularmente simples; **os blocos são localizados por um índice inteiro**, sendo o primeiro bloco o LBA 0, o segundo LBA 1, e assim por diante.

### GPT (Tabela de Partição GUID)

É chamada de Tabela de Partição GUID porque cada partição no seu disco tem um **identificador globalmente único**.

Assim como o MBR, ela começa no **setor 0**. O MBR ocupa 32 bits enquanto o **GPT** usa **64 bits**.\
O GPT **permite até 128 partições** no Windows e até **9,4ZB**.\
Além disso, as partições podem ter um nome Unicode de 36 caracteres.

Em um disco MBR, a partição e os dados de inicialização são armazenados em um único local. Se esses dados forem sobrescritos ou corrompidos, você terá problemas. Em contraste, o **GPT armazena várias cópias desses dados em todo o disco**, sendo muito mais robusto e capaz de recuperar os dados danificados.

O GPT também armazena valores de **verificação de redundância cíclica (CRC)** para verificar se seus dados estão íntegros. Se os dados estiverem corrompidos, o GPT pode detectar o problema e **tentar recuperar os dados danificados** de outra localização no disco.

**MBR Protetor (LBA0)**

Para compatibilidade limitada com versões anteriores, o espaço do MBR legado ainda é reservado na especificação do GPT, mas agora é usado de uma **maneira que impede que utilitários de disco baseados em MBR reconheçam erroneamente e possivelmente sobrescrevam discos GPT**. Isso é chamado de MBR protetor.

![](<../../../.gitbook/assets/image (491).png>)

**MBR Híbrido (LBA 0 + GPT)**

Em sistemas operacionais que suportam **inicialização baseada em GPT por meio de serviços BIOS** em vez de EFI, o primeiro setor também pode ser usado para armazenar o primeiro estágio do código do **carregador de inicialização**, mas **modificado** para reconhecer **partições GPT**. O carregador de inicialização no MBR não deve assumir um tamanho de setor de 512 bytes.

**Cabeçalho da tabela de partição (LBA 1)**

O cabeçalho da tabela de partição define os blocos utilizáveis no disco. Também define o número e o tamanho das entradas de partição que compõem a tabela de partição (deslocamentos 80 e 84 na tabela).

| Deslocamento | Comprimento | Conteúdo                                                                                                                                                                        |
| ------------ | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)     | 8 bytes     | Assinatura ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h ou 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)em máquinas little-endian) |
| 8 (0x08)     | 4 bytes     | Revisão 1.0 (00h 00h 01h 00h) para UEFI 2.8                                                                                                                                     |
| 12 (0x0C)    | 4 bytes     | Tamanho do cabeçalho em little-endian (em bytes, geralmente 5Ch 00h 00h 00h ou 92 bytes)                                                                                                    |
| 16 (0x10)    | 4 bytes     | [CRC32](https://en.wikipedia.org/wiki/CRC32) do cabeçalho (deslocamento +0 até o tamanho do cabeçalho) em little-endian, com este campo zerado durante o cálculo                                |
| 20 (0x14)    | 4 bytes     | Reservado; deve ser zero                                                                                                                                                          |
| 24 (0x18)    | 8 bytes     | LBA atual (localização desta cópia do cabeçalho)                                                                                                                                      |
| 32 (0x20)    | 8 bytes     | LBA de backup (localização da outra cópia do cabeçalho)                                                                                                                                  |
| 40 (0x28)    | 8 bytes     | Primeiro LBA utilizável para partições (último LBA da tabela de partição primária + 1)                                                                                                          |
| 48 (0x30)    | 8 bytes     | Último LBA utilizável (primeiro LBA da tabela de partição secundária − 1)                                                                                                                       |
| 56 (0x38)    | 16 bytes    | GUID do disco em endian misto                                                                                                                                                       |
| 72 (0x48)    | 8 bytes     | LBA inicial de uma matriz de entradas de partição (sempre 2 na cópia primária)                                                                                                        |
| 80 (0x50)    | 4 bytes     | Número de entradas de partição na matriz                                                                                                                                            |
| 84 (0x54)    | 4 bytes     | Tamanho de uma única entrada de partição (geralmente 80h ou 128)                                                                                                                           |
| 88 (0x58)    | 4 bytes     | CRC32 da matriz de entradas de partição em little-endian                                                                                                                               |
| 92 (0x5C)    | \*          | Reservado; deve ser zeros para o restante do bloco (420 bytes para um tamanho de setor de 512 bytes; mas pode ser mais com tamanhos de setor maiores)                                         |

**Entradas de partição (LBA 2–33)**

| Formato de entrada de partição GUID |          |                                                                                                                   |
| ----------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Deslocamento                        | Comprimento   | Conteúdo                                                                                                          |
| 0 (0x00)                            | 16 bytes | [GUID do tipo de partição](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (endian misto) |
| 16 (0x10)                           | 16 bytes | GUID de partição único (endian misto)                                                                              |
| 32 (0x20)                           | 8 bytes  | Primeiro LBA ([little endian](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                           | 8 bytes  | Último LBA (inclusive, geralmente ímpar)                                                                                 |
| 48 (0x30)                           | 8 bytes  | Flags de atributo (por exemplo, o bit 60 denota somente leitura)                                                                   |
| 56 (0x38)                           | 72 bytes | Nome da partição (36 unidades de código [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                                   |

**Tipos de Partições**

![](<../../../.gitbook/assets/image (492).png>)

Mais tipos de partições em [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Inspeção

Após montar a imagem forense com [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), você pode inspecionar o primeiro setor usando a ferramenta do Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na imagem a seguir, um **MBR** foi detectado no **setor 0** e interpretado:

![](<../../../.gitbook/assets/image (494).png>)

Se fosse uma **tabela GPT em vez de um MBR**, deveria aparecer a assinatura _EFI PART_ no **setor 1** (que na imagem anterior está vazio).

## Sistemas de Arquivos

### Lista de sistemas de arquivos do Windows

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

O sistema de arquivos **FAT (File Allocation Table)** é nomeado por seu método de organização, a tabela de alocação de arquivos, que reside no início do volume. Para proteger o volume, **duas cópias** da tabela são mantidas, caso uma seja danificada. Além disso, as tabelas de alocação de arquivos e a pasta raiz devem ser armazenadas em uma **localização fixa** para que os arquivos necessários para iniciar o sistema possam ser localizados corretamente.

![](<../../../.gitbook/assets/image (495).png>)

A unidade de espaço mínima usada por este sistema de arquivos é um **cluster, tipicamente 512B** (que é composto por um número de setores).

O antigo **FAT12** tinha endereços de cluster de valores de **12 bits** com até **4078 clusters**; permitia até 4084 clusters com UNIX. O mais eficiente **FAT16** aumentou para endereço de cluster de **16 bits** permitindo até **65.517 clusters** por volume. O FAT32 usa endereço de cluster de 32 bits permitindo até **268.435.456 clusters** por volume.

O **tamanho máximo de arquivo permitido pelo FAT é de 4GB** (menos um byte) porque o sistema de arquivos usa um campo de 32 bits para armazenar o tamanho do arquivo em bytes, e 2^32 bytes = 4 GiB. Isso ocorre para FAT12, FAT16 e FAT32.

O **diretório raiz** ocupa uma **posição específica** tanto para FAT12 quanto para FAT16 (no FAT32, ele ocupa uma posição como qualquer outra pasta). Cada entrada de arquivo/pasta contém estas informações:

* Nome do arquivo/pasta (máximo de 8 caracteres)
* Atributos
* Data de criação
* Data de modificação
* Data do último acesso
* Endereço da tabela FAT onde o primeiro cluster do arquivo começa
* Tamanho

Quando um arquivo é "excluído" usando um sistema de arquivos FAT, a entrada do diretório permanece quase **inalterada**, exceto pelo **primeiro caractere do nome do arquivo** (modificado para 0xE5), preservando a maior parte do nome do arquivo "excluído", juntamente com seu carimbo de tempo, comprimento do arquivo e — mais importante — sua localização física no disco. A lista de clusters de disco ocupados pelo arquivo será, no entanto, apagada da Tabela de Alocação de Arquivos, marcando esses setores como disponíveis para uso por outros arquivos criados ou modificados posteriormente. No caso do FAT32, há também um campo apagado adicional responsável pelos 16 bits superiores do valor do cluster de início do arquivo.

### **NTFS**

{% content-ref url="ntfs.md" %}
[ntfs.md](ntfs.md)
{% endcontent-ref %}

### EXT

**Ext2** é o sistema de arquivos mais comum para **partições sem journaling** (**partições que não mudam muito**) como a partição de inicialização. **Ext3/4** são **com journaling** e são usados geralmente para as **outras partições**.

{% content-ref url="ext.md" %}
[ext.md](ext.md)
{% endcontent-ref %}

## **Metadados**

Alguns arquivos contêm metadados. Essas informações são sobre o conteúdo do arquivo, que às vezes pode ser interessante para um analista, pois dependendo do tipo de arquivo, pode conter informações como:

* Título
* Versão do MS Office usada
* Autor
* Datas de criação e última modificação
* Modelo da câmera
* Coordenadas GPS
* Informações da imagem

Você pode usar ferramentas como [**exiftool**](https://exiftool.org) e [**Metadiver**](https://www.easymetadata.com/metadiver-2/) para obter os metadados de um arquivo.

## **Recuperação de Arquivos Deletados**

### Arquivos Deletados Registrados

Como visto anteriormente, existem vários locais onde o arquivo ainda é salvo após ser "excluído". Isso ocorre porque geralmente a exclusão de um arquivo de um sistema de arquivos apenas o marca como excluído, mas os dados não são tocados. Portanto, é possível inspecionar os registros dos arquivos (como o MFT) e encontrar os arquivos excluídos.

Além disso, o sistema operacional geralmente salva muitas informações sobre alterações no sistema de arquivos e backups, então é possível tentar usá-los para recuperar o arquivo ou o máximo de informações possível.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Escultura de Arquivos**

**Escultura de arquivos** é uma técnica que tenta **encontrar arquivos no volume de dados**. Existem 3 principais maneiras como ferramentas desse tipo funcionam: **Com base nos cabeçalhos e rodapés dos tipos de arquivo**, com base nas **estruturas dos tipos de arquivo** e com base no **próprio conteúdo**.

Observe que essa técnica **não funciona para recuperar arquivos fragmentados**. Se um arquivo **não estiver armazenado em setores contíguos**, então essa técnica não será capaz de encontrá-lo ou pelo menos parte dele.

Existem várias ferramentas que você pode usar para Escultura de Arquivos indicando os tipos de arquivo que deseja procurar

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Escultura de Fluxo de Dados**

A Escultura de Fluxo de Dados é semelhante à Escultura de Arquivos, mas **em vez de procurar arquivos completos, ela procura fragmentos interessantes** de informações.\
Por exemplo, em vez de procurar um arquivo completo contendo URLs registrados, essa técnica procurará URLs.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Exclusão Segura

Obviamente, existem maneiras de **excluir arquivos "de forma segura" e parte dos logs sobre eles**. Por exemplo, é possível **sobrescrever o conteúdo** de um arquivo com dados inúteis várias vezes e, em seguida, **remover** os **logs** do **$MFT** e **$LOGFILE** sobre o arquivo, e **remover as Cópias de Sombra do Volume**.\
Você pode notar que mesmo realizando essa ação, pode haver **outras partes onde a existência do arquivo ainda está registrada**, e isso é verdade e faz parte do trabalho do profissional forense encontrar essas informações.

## Referências

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

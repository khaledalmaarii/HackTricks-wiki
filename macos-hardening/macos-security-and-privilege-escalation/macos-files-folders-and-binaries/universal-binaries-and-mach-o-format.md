# Binários universais do macOS e Formato Mach-O

{% hint style="success" %}
Aprenda e pratique Hacking AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Informações Básicas

Os binários do Mac OS geralmente são compilados como **binários universais**. Um **binário universal** pode **suportar várias arquiteturas no mesmo arquivo**.

Esses binários seguem a **estrutura Mach-O** que é basicamente composta por:

* Cabeçalho
* Comandos de Carregamento
* Dados

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (470).png>)

## Cabeçalho Fat

Procure pelo arquivo com: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* número de estruturas que seguem */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* especificador de CPU (int) */
cpu_subtype_t	cpusubtype;	/* especificador de máquina (int) */
uint32_t	offset;		/* deslocamento do arquivo para este arquivo de objeto */
uint32_t	size;		/* tamanho deste arquivo de objeto */
uint32_t	align;		/* alinhamento como uma potência de 2 */
};
</code></pre>

O cabeçalho tem os bytes de **magic** seguidos pelo **número** de **arquiteturas** que o arquivo **contém** (`nfat_arch`) e cada arquitetura terá uma estrutura `fat_arch`.

Verifique com:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (for architecture x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (for architecture arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Cabeçalhos Fat
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>arquitetura x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>arquitetura arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

ou usando a ferramenta [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

Como você pode estar pensando, geralmente um binário universal compilado para 2 arquiteturas **dobra o tamanho** de um compilado para apenas 1 arquitetura.

## **Cabeçalho Mach-O**

O cabeçalho contém informações básicas sobre o arquivo, como bytes mágicos para identificá-lo como um arquivo Mach-O e informações sobre a arquitetura de destino. Você pode encontrá-lo em: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
```c
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe	/* NXSwapInt(MH_MAGIC) */
struct mach_header {
uint32_t	magic;		/* mach magic number identifier */
cpu_type_t	cputype;	/* cpu specifier (e.g. I386) */
cpu_subtype_t	cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file (usage and alignment for the file) */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
};

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */
struct mach_header_64 {
uint32_t	magic;		/* mach magic number identifier */
int32_t		cputype;	/* cpu specifier */
int32_t		cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
uint32_t	reserved;	/* reserved */
};
```
### Tipos de Arquivos Mach-O

Existem diferentes tipos de arquivos, você pode encontrá-los definidos no [**código-fonte, por exemplo, aqui**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Os mais importantes são:

- `MH_OBJECT`: Arquivo de objeto relocável (produtos intermediários da compilação, ainda não executáveis).
- `MH_EXECUTE`: Arquivos executáveis.
- `MH_FVMLIB`: Arquivo de biblioteca VM fixa.
- `MH_CORE`: Despejos de código.
- `MH_PRELOAD`: Arquivo executável pré-carregado (não mais suportado no XNU).
- `MH_DYLIB`: Bibliotecas Dinâmicas.
- `MH_DYLINKER`: Linker Dinâmico.
- `MH_BUNDLE`: Arquivos de "plugin". Gerados usando -bundle no gcc e carregados explicitamente por `NSBundle` ou `dlopen`.
- `MH_DYSM`: Arquivo `.dSym` companheiro (arquivo com símbolos para depuração).
- `MH_KEXT_BUNDLE`: Extensões de Kernel.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ou usando [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Flags Mach-O**

O código fonte também define várias flags úteis para carregar bibliotecas:

* `MH_NOUNDEFS`: Sem referências indefinidas (totalmente vinculado)
* `MH_DYLDLINK`: Vinculação Dyld
* `MH_PREBOUND`: Referências dinâmicas predefinidas.
* `MH_SPLIT_SEGS`: Arquivo divide segmentos r/o e r/w.
* `MH_WEAK_DEFINES`: Binário possui símbolos definidos fracos
* `MH_BINDS_TO_WEAK`: Binário usa símbolos fracos
* `MH_ALLOW_STACK_EXECUTION`: Torna a pilha executável
* `MH_NO_REEXPORTED_DYLIBS`: Biblioteca sem comandos LC\_REEXPORT
* `MH_PIE`: Executável Independente de Posição
* `MH_HAS_TLV_DESCRIPTORS`: Há uma seção com variáveis locais de thread
* `MH_NO_HEAP_EXECUTION`: Sem execução para páginas de heap/dados
* `MH_HAS_OBJC`: Binário possui seções oBject-C
* `MH_SIM_SUPPORT`: Suporte ao simulador
* `MH_DYLIB_IN_CACHE`: Usado em dylibs/frameworks na cache de biblioteca compartilhada.

## **Comandos de Carregamento Mach-O**

A **disposição do arquivo na memória** é especificada aqui, detalhando a **localização da tabela de símbolos**, o contexto da thread principal no início da execução e as **bibliotecas compartilhadas** necessárias. Instruções são fornecidas ao carregador dinâmico **(dyld)** sobre o processo de carregamento do binário na memória.

O uso da estrutura **load\_command**, definida no mencionado **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Existem cerca de **50 tipos diferentes de comandos de carga** que o sistema trata de forma diferente. Os mais comuns são: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` e `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Basicamente, este tipo de Comando de Carga define **como carregar o \_\_TEXT** (código executável) **e \_\_DATA** (dados para o processo) **segmentos** de acordo com os **deslocamentos indicados na seção de Dados** quando o binário é executado.
{% endhint %}

Esses comandos **definem segmentos** que são **mapeados** no **espaço de memória virtual** de um processo quando ele é executado.

Existem **diferentes tipos** de segmentos, como o segmento **\_\_TEXT**, que contém o código executável de um programa, e o segmento **\_\_DATA**, que contém dados usados pelo processo. Esses **segmentos estão localizados na seção de dados** do arquivo Mach-O.

**Cada segmento** pode ser **dividido** em várias **seções**. A estrutura do **comando de carga** contém **informações** sobre **essas seções** dentro do respectivo segmento.

No cabeçalho, primeiro você encontra o **cabeçalho do segmento**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* para arquiteturas de 64 bits */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* inclui o tamanho das structs section_64 */
char		segname[16];	/* nome do segmento */
uint64_t	vmaddr;		/* endereço de memória deste segmento */
uint64_t	vmsize;		/* tamanho de memória deste segmento */
uint64_t	fileoff;	/* deslocamento do arquivo deste segmento */
uint64_t	filesize;	/* quantidade a ser mapeada do arquivo */
int32_t		maxprot;	/* proteção VM máxima */
int32_t		initprot;	/* proteção VM inicial */
<strong>	uint32_t	nsects;		/* número de seções no segmento */
</strong>	uint32_t	flags;		/* flags */
};
</code></pre>

Exemplo de cabeçalho de segmento:

<figure><img src="../../../.gitbook/assets/image (1126).png" alt=""><figcaption></figcaption></figure>

Este cabeçalho define o **número de seções cujos cabeçalhos aparecem após** ele:
```c
struct section_64 { /* for 64-bit architectures */
char		sectname[16];	/* name of this section */
char		segname[16];	/* segment this section goes in */
uint64_t	addr;		/* memory address of this section */
uint64_t	size;		/* size in bytes of this section */
uint32_t	offset;		/* file offset of this section */
uint32_t	align;		/* section alignment (power of 2) */
uint32_t	reloff;		/* file offset of relocation entries */
uint32_t	nreloc;		/* number of relocation entries */
uint32_t	flags;		/* flags (section type and attributes)*/
uint32_t	reserved1;	/* reserved (for offset or index) */
uint32_t	reserved2;	/* reserved (for count or sizeof) */
uint32_t	reserved3;	/* reserved */
};
```
Exemplo de **cabeçalho de seção**:

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

Se você **adicionar** o **deslocamento da seção** (0x37DC) + o **deslocamento** onde o **arquivo começa**, neste caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

Também é possível obter **informações de cabeçalho** a partir da **linha de comando** com:
```bash
otool -lv /bin/ls
```
Segmentos comuns carregados por este comando:

- **`__PAGEZERO`:** Instrui o kernel a **mapear** o **endereço zero** para que ele **não possa ser lido, escrito ou executado**. As variáveis maxprot e minprot na estrutura são definidas como zero para indicar que não há **direitos de leitura-escrita-execução nesta página**.
- Essa alocação é importante para **mitigar vulnerabilidades de referência de ponteiro nulo**. Isso ocorre porque o XNU impõe uma página zero rígida que garante que a primeira página (apenas a primeira) da memória seja inacessível (exceto no i386). Um binário poderia atender a esses requisitos criando um pequeno \_\_PAGEZERO (usando o `-pagezero_size`) para cobrir os primeiros 4k e tendo o restante da memória de 32 bits acessível tanto no modo usuário quanto no modo kernel.
- **`__TEXT`**: Contém **código executável** com permissões de **leitura** e **execução** (não gravável)**.** Seções comuns deste segmento:
  - `__text`: Código binário compilado
  - `__const`: Dados constantes (somente leitura)
  - `__[c/u/os_log]string`: Constantes de string C, Unicode ou os logs
  - `__stubs` e `__stubs_helper`: Envolvidos durante o processo de carregamento de biblioteca dinâmica
  - `__unwind_info`: Dados de desenrolamento de pilha.
- Note que todo esse conteúdo é assinado, mas também marcado como executável (criando mais opções para exploração de seções que não necessariamente precisam desse privilégio, como seções dedicadas a strings).
- **`__DATA`**: Contém dados que são **legíveis** e **graváveis** (não executáveis)**.**
  - `__got:` Tabela de Deslocamento Global
  - `__nl_symbol_ptr`: Ponteiro de símbolo não preguiçoso (vinculado no carregamento)
  - `__la_symbol_ptr`: Ponteiro de símbolo preguiçoso (vinculado no uso)
  - `__const`: Deveria ser dados somente leitura (não realmente)
  - `__cfstring`: Strings CoreFoundation
  - `__data`: Variáveis globais (que foram inicializadas)
  - `__bss`: Variáveis estáticas (que não foram inicializadas)
  - `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, etc): Informações usadas pelo tempo de execução Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const não é garantido ser constante (permissões de escrita), assim como outros ponteiros e a GOT. Esta seção torna `__const`, alguns inicializadores e a tabela GOT (uma vez resolvida) **somente leitura** usando `mprotect`.
- **`__LINKEDIT`**: Contém informações para o linker (dyld) como, símbolos, strings e entradas de tabela de realocação. É um contêiner genérico para conteúdos que não estão nem em `__TEXT` nem em `__DATA` e seu conteúdo é descrito em outros comandos de carregamento.
  - Informações do dyld: Rebase, opcodes de ligação não preguiçosa/preguiçosa/fraca e informações de exportação
  - Início de funções: Tabela de endereços de início de funções
  - Dados no Código: Ilhas de dados em \_\_text
  - Tabela de Símbolos: Símbolos no binário
  - Tabela de Símbolos Indiretos: Símbolos de ponteiro/stub
  - Tabela de Strings
  - Assinatura de Código
- **`__OBJC`**: Contém informações usadas pelo tempo de execução Objective-C. Embora essas informações também possam ser encontradas no segmento \_\_DATA, dentro de várias seções em \_\_objc\_\*.
- **`__RESTRICT`**: Um segmento sem conteúdo com uma única seção chamada **`__restrict`** (também vazia) que garante que ao executar o binário, ele irá ignorar variáveis ambientais DYLD.

Como foi possível ver no código, **os segmentos também suportam flags** (embora não sejam muito utilizadas):

- `SG_HIGHVM`: Apenas núcleo (não utilizado)
- `SG_FVMLIB`: Não utilizado
- `SG_NORELOC`: Segmento sem realocação
- `SG_PROTECTED_VERSION_1`: Criptografia. Usado, por exemplo, pelo Finder para criptografar o segmento de texto `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contém o ponto de entrada no atributo **entryoff**. No momento do carregamento, o **dyld** simplesmente **adiciona** esse valor à (em memória) **base do binário**, e então **salta** para esta instrução para iniciar a execução do código binário.

**`LC_UNIXTHREAD`** contém os valores que os registradores devem ter ao iniciar a thread principal. Isso já foi descontinuado, mas o **`dyld`** ainda o utiliza. É possível ver os valores dos registradores definidos por isso com:
```bash
otool -l /usr/lib/dyld
[...]
Load command 13
cmd LC_UNIXTHREAD
cmdsize 288
flavor ARM_THREAD_STATE64
count ARM_THREAD_STATE64_COUNT
x0  0x0000000000000000 x1  0x0000000000000000 x2  0x0000000000000000
x3  0x0000000000000000 x4  0x0000000000000000 x5  0x0000000000000000
x6  0x0000000000000000 x7  0x0000000000000000 x8  0x0000000000000000
x9  0x0000000000000000 x10 0x0000000000000000 x11 0x0000000000000000
x12 0x0000000000000000 x13 0x0000000000000000 x14 0x0000000000000000
x15 0x0000000000000000 x16 0x0000000000000000 x17 0x0000000000000000
x18 0x0000000000000000 x19 0x0000000000000000 x20 0x0000000000000000
x21 0x0000000000000000 x22 0x0000000000000000 x23 0x0000000000000000
x24 0x0000000000000000 x25 0x0000000000000000 x26 0x0000000000000000
x27 0x0000000000000000 x28 0x0000000000000000  fp 0x0000000000000000
lr 0x0000000000000000 sp  0x0000000000000000  pc 0x0000000000004b70
cpsr 0x00000000

[...]
```
### **`LC_CODE_SIGNATURE`**

Contém informações sobre a **assinatura de código do arquivo Mach-O**. Ele contém apenas um **deslocamento** que **aponta** para o **bloco de assinatura**. Geralmente, isso está no final do arquivo.\
No entanto, você pode encontrar algumas informações sobre esta seção neste [**post de blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) e neste [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Suporte para criptografia binária. No entanto, é claro, se um atacante conseguir comprometer o processo, ele poderá despejar a memória sem criptografia.

### **`LC_LOAD_DYLINKER`**

Contém o **caminho para o executável do link dinâmico** que mapeia bibliotecas compartilhadas no espaço de endereço do processo. O **valor é sempre definido como `/usr/lib/dyld`**. É importante observar que no macOS, o mapeamento de dylib acontece no **modo de usuário**, não no modo kernel.

### **`LC_IDENT`**

Obsoleto, mas quando configurado para gerar despejos em caso de pânico, um despejo principal Mach-O é criado e a versão do kernel é definida no comando `LC_IDENT`.

### **`LC_UUID`**

UUID aleatório. Não é útil diretamente, mas o XNU o armazena com o restante das informações do processo. Pode ser usado em relatórios de falhas.

### **`LC_DYLD_ENVIRONMENT`**

Permite indicar variáveis de ambiente ao dyld antes que o processo seja executado. Isso pode ser muito perigoso, pois pode permitir a execução de código arbitrário dentro do processo, portanto, este comando de carregamento é usado apenas no dyld construído com `#define SUPPORT_LC_DYLD_ENVIRONMENT` e restringe ainda mais o processamento apenas a variáveis no formato `DYLD_..._PATH` especificando caminhos de carregamento.

### **`LC_LOAD_DYLIB`**

Este comando de carregamento descreve uma **dependência de biblioteca dinâmica** que **instrui** o **carregador** (dyld) a **carregar e vincular a biblioteca**. Há um comando de carregamento `LC_LOAD_DYLIB` **para cada biblioteca** que o binário Mach-O requer.

* Este comando de carregamento é uma estrutura do tipo **`dylib_command`** (que contém uma struct dylib, descrevendo a biblioteca dinâmica dependente real):
```objectivec
struct dylib_command {
uint32_t        cmd;            /* LC_LOAD_{,WEAK_}DYLIB */
uint32_t        cmdsize;        /* includes pathname string */
struct dylib    dylib;          /* the library identification */
};

struct dylib {
union lc_str  name;                 /* library's path name */
uint32_t timestamp;                 /* library's build time stamp */
uint32_t current_version;           /* library's current version number */
uint32_t compatibility_version;     /* library's compatibility vers number*/
};
```
![](<../../../.gitbook/assets/image (486).png>)

Você também pode obter essas informações a partir da linha de comando com:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Algumas bibliotecas potencialmente relacionadas a malware são:

* **DiskArbitration**: Monitorando unidades USB
* **AVFoundation:** Captura de áudio e vídeo
* **CoreWLAN**: Escaneamento de Wifi.

{% hint style="info" %}
Um binário Mach-O pode conter um ou **mais** **construtores**, que serão **executados** **antes** do endereço especificado em **LC\_MAIN**.\
Os deslocamentos de quaisquer construtores são mantidos na seção **\_\_mod\_init\_func** do segmento **\_\_DATA\_CONST**.
{% endhint %}

## **Dados Mach-O**

No cerne do arquivo está a região de dados, composta por vários segmentos conforme definido na região de comandos de carga. **Uma variedade de seções de dados pode ser alojada dentro de cada segmento**, com cada seção **mantendo código ou dados** específicos para um tipo.

{% hint style="success" %}
Os dados são basicamente a parte que contém todas as **informações** carregadas pelos comandos de carga **LC\_SEGMENTS\_64**
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Isso inclui:

* **Tabela de funções:** Que contém informações sobre as funções do programa.
* **Tabela de símbolos**: Que contém informações sobre a função externa usada pelo binário
* Também pode conter funções internas, nomes de variáveis e mais.

Para verificar, você pode usar a ferramenta [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

Ou a partir da linha de comando:
```bash
size -m /bin/ls
```
## Seções Comuns do Objetive-C

No segmento `__TEXT` (r-x):

- `__objc_classname`: Nomes das classes (strings)
- `__objc_methname`: Nomes dos métodos (strings)
- `__objc_methtype`: Tipos dos métodos (strings)

No segmento `__DATA` (rw-):

- `__objc_classlist`: Ponteiros para todas as classes do Objetive-C
- `__objc_nlclslist`: Ponteiros para classes do Objetive-C não preguiçosas
- `__objc_catlist`: Ponteiro para Categorias
- `__objc_nlcatlist`: Ponteiro para Categorias não preguiçosas
- `__objc_protolist`: Lista de protocolos
- `__objc_const`: Dados constantes
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

# Volatility - CheatSheet

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

Se você deseja algo **rápido e louco** que lançará vários plugins do Volatility em paralelo, você pode usar: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Instalação

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{% tabs %}
{% tab title="Método1" %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% endtab %}

{% tab title="Método 2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Comandos do Volatility

Acesse a documentação oficial em [Referência de comandos do Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)

### Uma nota sobre plugins "list" vs "scan"

O Volatility tem duas abordagens principais para plugins, que às vezes são refletidas em seus nomes. Os plugins "list" tentarão navegar pelas estruturas do Kernel do Windows para recuperar informações como processos (localizar e percorrer a lista encadeada das estruturas `_EPROCESS` na memória), identificadores do sistema operacional (localizando e listando a tabela de identificadores, desreferenciando quaisquer ponteiros encontrados, etc). Eles se comportam mais ou menos como a API do Windows se solicitada, por exemplo, para listar processos.

Isso torna os plugins "list" bastante rápidos, mas tão vulneráveis quanto a API do Windows à manipulação por malware. Por exemplo, se o malware usar DKOM para desvincular um processo da lista encadeada `_EPROCESS`, ele não aparecerá no Gerenciador de Tarefas e nem na lista de processos.

Os plugins "scan", por outro lado, adotarão uma abordagem semelhante à escultura da memória em busca de coisas que podem fazer sentido quando desreferenciadas como estruturas específicas. `psscan`, por exemplo, lerá a memória e tentará criar objetos `_EPROCESS` a partir dela (ele usa varredura de pool-tag, que procura por strings de 4 bytes que indicam a presença de uma estrutura de interesse). A vantagem é que ele pode encontrar processos que foram encerrados e, mesmo que o malware manipule a lista encadeada `_EPROCESS`, o plugin ainda encontrará a estrutura perdida na memória (pois ela ainda precisa existir para o processo ser executado). A desvantagem é que os plugins "scan" são um pouco mais lentos que os plugins "list" e às vezes podem fornecer falsos positivos (um processo que foi encerrado há muito tempo e teve partes de sua estrutura sobrescritas por outras operações).

De: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Perfis de SO

### Volatility3

Como explicado no readme, você precisa colocar a **tabela de símbolos do SO** que deseja suportar dentro de _volatility3/volatility/symbols_.\
Os pacotes de tabelas de símbolos para os vários sistemas operacionais estão disponíveis para **download** em:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Perfil Externo

Você pode obter a lista de perfis suportados fazendo:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Se deseja usar um **novo perfil que baixou** (por exemplo, um perfil linux), precisa criar em algum lugar a seguinte estrutura de pastas: _plugins/overlays/linux_ e colocar dentro desta pasta o arquivo zip contendo o perfil. Em seguida, obtenha o número de perfis usando:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Você pode **baixar perfis do Linux e Mac** em [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)

No trecho anterior, você pode ver que o perfil é chamado `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`, e você pode usá-lo para executar algo como:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Descobrir Perfil
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Diferenças entre imageinfo e kdbgscan**

[**A partir daqui**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): Ao contrário do imageinfo, que simplesmente fornece sugestões de perfil, o **kdbgscan** é projetado para identificar positivamente o perfil correto e o endereço KDBG correto (se houver múltiplos). Este plugin escaneia as assinaturas do KDBGHeader vinculadas aos perfis do Volatility e aplica verificações de sanidade para reduzir falsos positivos. A verbosidade da saída e o número de verificações de sanidade que podem ser realizadas dependem se o Volatility pode encontrar um DTB, então, se você já conhece o perfil correto (ou se tiver uma sugestão de perfil do imageinfo), certifique-se de usá-lo a partir de .

Sempre dê uma olhada no **número de processos que o kdbgscan encontrou**. Às vezes, o imageinfo e o kdbgscan podem encontrar **mais de um** perfil adequado, mas apenas o **válido terá algum processo relacionado** (Isso ocorre porque para extrair processos é necessário o endereço KDBG correto).
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

O **bloco de depuração do kernel**, referido como **KDBG** pelo Volatility, é crucial para tarefas forenses realizadas pelo Volatility e vários depuradores. Identificado como `KdDebuggerDataBlock` e do tipo `_KDDEBUGGER_DATA64`, ele contém referências essenciais como `PsActiveProcessHead`. Esta referência específica aponta para o início da lista de processos, permitindo a listagem de todos os processos, o que é fundamental para uma análise de memória minuciosa.

## Informações do SO
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
O plugin `banners.Banners` pode ser usado no **vol3 para tentar encontrar banners linux** no dump.

## Hashes/Senhas

Extrair hashes SAM, [credenciais em cache do domínio](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) e [segredos lsa](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets).
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endtab %}

{% tab title="vol2" %}O Volatility é uma ferramenta poderosa para análise de dumps de memória. Abaixo estão alguns comandos úteis para análise de dumps de memória com o Volatility:

- **Identificar o perfil do sistema operacional:**
  ```
  volatility -f memdump.mem imageinfo
  ```

- **Listar todos os processos em execução:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema pslist
  ```

- **Analisar os sockets de rede abertos:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema sockscan
  ```

- **Analisar os handlers de arquivos abertos:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema filescan
  ```

- **Analisar os módulos carregados:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema modscan
  ```

- **Analisar as conexões de rede:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema connscan
  ```

- **Analisar os registros de eventos:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema evtlogs
  ```

- **Extrair um processo específico:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema procdump -p PID -D output_directory
  ```

- **Analisar o registro do Windows:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema printkey -K "RegistroDoWindows"
  ```
{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
## Despejo de Memória

O despejo de memória de um processo irá **extrair tudo** do estado atual do processo. O módulo **procdump** irá apenas **extrair** o **código**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Processos

### Listar processos

Tente encontrar processos **suspeitos** (por nome) ou **inesperados** processos filhos (por exemplo, um cmd.exe como filho de iexplorer.exe).\
Pode ser interessante **comparar** o resultado do pslist com o de psscan para identificar processos ocultos.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endtab %}

{% tab title="vol2" %}A seguir estão alguns comandos úteis do Volatility para análise de despejo de memória:

- **imageinfo**: exibe informações gerais sobre a imagem de memória.
- **pslist**: lista os processos em execução.
- **pstree**: exibe os processos em formato de árvore.
- **dlllist**: lista as DLLs carregadas em cada processo.
- **handles**: exibe os identificadores de objeto aberto para cada processo.
- **cmdline**: exibe os argumentos da linha de comando de cada processo.
- **filescan**: escaneia a memória em busca de estruturas de dados de arquivos.
- **dumpfiles**: extrai arquivos da memória.
- **malfind**: encontra possíveis malwares na memória.
- **apihooks**: exibe os ganchos de API em cada processo.
- **ldrmodules**: exibe os módulos carregados em cada processo.
- **svcscan**: lista os serviços do Windows.
- **connections**: exibe informações de conexão de rede.
- **connscan**: escaneia a memória em busca de objetos de conexão de rede.
- **netscan**: encontra sockets de rede e conexões.
- **autoruns**: exibe os pontos de entrada de inicialização automática.
- **printkey**: exibe as chaves do registro do Windows.
- **hivelist**: exibe os hives do registro do Windows.
- **hashdump**: extrai hashes de senha do sistema.
- **userassist**: exibe programas frequentemente usados.
- **shellbags**: exibe pastas acessadas recentemente.
- **mbrparser**: analisa o Registro Mestre de Inicialização (MBR).
- **devicetree**: exibe a árvore de dispositivos.
- **modscan**: escaneia a memória em busca de módulos do kernel.
- **moddump**: extrai módulos do kernel da memória.
- **yarascan**: escaneia a memória em busca de padrões com o Yara.
- **yarascan**: escaneia a memória em busca de padrões com o Yara.
- **yara**: executa regras Yara em um arquivo ou processo.
- **memmap**: exibe os intervalos de memória usados por um processo.
- **vadinfo**: exibe informações sobre regiões de memória virtuais.
- **vaddump**: extrai regiões de memória virtuais.
- **vadtree**: exibe as regiões de memória virtuais em formato de árvore.
- **vadwalk**: exibe as regiões de memória virtuais em um processo.
- **dlldump**: extrai uma DLL específica da memória.
- **dumpregistry**: extrai uma chave de registro específica.
- **dumpregistrykeys**: extrai chaves de registro de um processo.
- **dumpregistryvalues**: extrai valores de registro de um processo.
- **dumpcerts**: extrai certificados da memória.
- **dumpfiles**: extrai arquivos da memória.
- **dumpregistry**: extrai uma chave de registro específica.
- **dumpregistrykeys**: extrai chaves de registro de um processo.
- **dumpregistryvalues**: extrai valores de registro de um processo.
- **dumpcerts**: extrai certificados da memória.
- **hivedump**: extrai um hive do registro.
- **hivelist**: exibe os hives do registro.
- **printkey**: exibe as chaves do registro.
- **printkey -K**: exibe uma chave de registro específica.
- **printkey -o**: exibe as subchaves de uma chave de registro.
- **printkey -v**: exibe os valores de uma chave de registro.
- **printkey -y**: exibe os valores de uma chave de registro em formato RAW.
- **hashdump**: extrai hashes de senha do sistema.
- **hashdump -s**: extrai hashes de senha do sistema em formato SAM.
- **hashdump -l**: extrai hashes de senha do sistema em formato LSA.
- **hashdump -h**: extrai hashes de senha do sistema em formato hexadecimal.
- **hashdump -a**: extrai todos os hashes de senha do sistema.
- **hashdump -c**: extrai hashes de senha do sistema em formato CrackMapExec.
- **hashdump -k**: extrai hashes de senha do sistema em formato de chave de registro.
- **hashdump -d**: extrai hashes de senha do sistema em formato de despejo de memória.
- **hashdump -p**: extrai hashes de senha do sistema em formato de arquivo de texto.
- **hashdump -o**: extrai hashes de senha do sistema em formato Ophcrack.
- **hashdump -j**: extrai hashes de senha do sistema em formato John the Ripper.
- **hashdump -m**: extrai hashes de senha do sistema em formato de matriz.
- **hashdump -b**: extrai hashes de senha do sistema em formato de arquivo de backup.
- **hashdump -x**: extrai hashes de senha do sistema em formato de arquivo XML.
- **hashdump -g**: extrai hashes de senha do sistema em formato de arquivo GPG.
- **hashdump -u**: extrai hashes de senha do sistema em formato de arquivo Unix.
- **hashdump -w**: extrai hashes de senha do sistema em formato de arquivo de palavra-passe.
- **hashdump -r**: extrai hashes de senha do sistema em formato de arquivo Rainbow.
- **hashdump -f**: extrai hashes de senha do sistema em formato de arquivo de força bruta.
- **hashdump -e**: extrai hashes de senha do sistema em formato de arquivo de exportação.
- **hashdump -i**: extrai hashes de senha do sistema em formato de arquivo de importação.
- **hashdump -n**: extrai hashes de senha do sistema em formato de arquivo de rede.
- **hashdump -m**: extrai hashes de senha do sistema em formato de arquivo de matriz.
- **hashdump -t**: extrai hashes de senha do sistema em formato de arquivo de texto.
- **hashdump -z**: extrai hashes de senha do sistema em formato de arquivo ZIP.
- **hashdump -q**: extrai hashes de senha do sistema em formato de arquivo de consulta.
- **hashdump -v**: extrai hashes de senha do sistema em formato de arquivo de verificação.
- **hashdump -y**: extrai hashes de senha do sistema em formato de arquivo YARA.
- **hashdump -u**: extrai hashes de senha do sistema em formato de arquivo Unix.
- **hashdump -w**: extrai hashes de senha do sistema em formato de arquivo de palavra-passe.
- **hashdump -r**: extrai hashes de senha do sistema em formato de arquivo Rainbow.
- **hashdump -f**: extrai hashes de senha do sistema em formato de arquivo de força bruta.
- **hashdump -e**: extrai hashes de senha do sistema em formato de arquivo de exportação.
- **hashdump -i**: extrai hashes de senha do sistema em formato de arquivo de importação.
- **hashdump -n**: extrai hashes de senha do sistema em formato de arquivo de rede.
- **hashdump -m**: extrai hashes de senha do sistema em formato de arquivo de matriz.
- **hashdump -t**: extrai hashes de senha do sistema em formato de arquivo de texto.
- **hashdump -z**: extrai hashes de senha do sistema em formato de arquivo ZIP.
- **hashdump -q**: extrai hashes de senha do sistema em formato de arquivo de consulta.
- **hashdump -v**: extrai hashes de senha do sistema em formato de arquivo de verificação.
- **hashdump -y**: extrai hashes de senha do sistema em formato de arquivo YARA.
- **hashdump -u**: extrai hashes de senha do sistema em formato de arquivo Unix.
- **hashdump -w**: extrai hashes de senha do sistema em formato de arquivo de palavra-passe.
- **hashdump -r**: extrai hashes de senha do sistema em formato de arquivo Rainbow.
- **hashdump -f**: extrai hashes de senha do sistema em formato de arquivo de força bruta.
- **hashdump -e**: extrai hashes de senha do sistema em formato de arquivo de exportação.
- **hashdump -i**: extrai hashes de senha do sistema em formato de arquivo de importação.
- **hashdump -n**: extrai hashes de senha do sistema em formato de arquivo de rede.
- **hashdump -m**: extrai hashes de senha do sistema em formato de arquivo de matriz.
- **hashdump -t**: extrai hashes de senha do sistema em formato de arquivo de texto.
- **hashdump -z**: extrai hashes de senha do sistema em formato de arquivo ZIP.
- **hashdump -q**: extrai hashes de senha do sistema em formato de arquivo de consulta.
- **hashdump -v**: extrai hashes de senha do sistema em formato de arquivo de verificação.
- **hashdump -y**: extrai hashes de senha do sistema em formato de arquivo YARA.
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
### Despejar proc

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endtab %}

{% tab title="vol2" %}A seguir estão alguns comandos úteis do Volatility para análise de despejo de memória:

- **imageinfo**: exibe informações gerais sobre a imagem de memória.
- **pslist**: lista os processos em execução.
- **pstree**: exibe os processos em formato de árvore.
- **psscan**: verifica os processos ocultos.
- **dlllist**: lista as DLLs carregadas em cada processo.
- **handles**: exibe os identificadores de objeto aberto para cada processo.
- **cmdline**: exibe os argumentos da linha de comando de cada processo.
- **consoles**: lista os consoles associados a cada processo.
- **filescan**: verifica os arquivos mapeados na memória.
- **svcscan**: lista os serviços do Windows.
- **connections**: exibe as conexões de rede.
- **malfind**: procura por possíveis malwares na memória.
- **apihooks**: identifica possíveis ganchos de API.
- **ldrmodules**: lista os módulos carregados em cada processo.
- **modscan**: verifica os módulos do kernel.
- **ssdt**: exibe a Tabela de Despacho de Serviço do Sistema.
- **callbacks**: lista os callbacks do kernel.
- **driverirp**: exibe as IRPs (Pacotes de Solicitação de E/S) manipuladas por drivers.
- **devicetree**: exibe a árvore de dispositivos.
- **printkey**: exibe as chaves do Registro de impressão.
- **privs**: lista os privilégios de cada processo.
- **getsids**: exibe os SIDs (Identificadores de Segurança) associados a cada processo.
- **hivelist**: lista os hives do Registro.
- **hashdump**: extrai hashes de senha do SAM e do sistema.
- **userassist**: exibe programas frequentemente usados.
- **shellbags**: lista pastas acessadas recentemente.
- **mftparser**: analisa a Tabela de Arquivos Mestres (MFT).
- **mbrparser**: analisa o Registro Mestre de Inicialização (MBR).
- **yarascan**: executa varreduras YARA na memória.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara**: executa varreduras YARA em arquivos.
- **yarascan**: executa varreduras YARA na memória.
- **yara
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### Linha de comando

Alguma coisa suspeita foi executada?
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endtab %}

{% tab title="vol2" %}A seguir estão alguns comandos úteis do Volatility para análise de despejo de memória:

- **imageinfo**: exibe informações gerais sobre a imagem de memória.
- **pslist**: lista os processos em execução.
- **pstree**: exibe os processos em formato de árvore.
- **psscan**: verifica os processos ocultos.
- **dlllist**: lista as DLLs carregadas em cada processo.
- **handles**: exibe os identificadores de objeto aberto para cada processo.
- **cmdline**: mostra os argumentos da linha de comando de cada processo.
- **consoles**: lista os consoles associados a cada processo.
- **vadinfo**: exibe informações sobre regiões de memória alocadas.
- **vadtree**: exibe as regiões de memória em formato de árvore.
- **malfind**: procura por possíveis malwares na memória.
- **apihooks**: identifica possíveis ganchos de API.
- **ldrmodules**: lista os módulos carregados em cada processo.
- **modscan**: verifica módulos do kernel carregados.
- **ssdt**: exibe a Tabela de Despacho de Serviços do Sistema.
- **callbacks**: lista os callbacks do kernel.
- **devicetree**: exibe a árvore de dispositivos.
- **driverirp**: exibe IRPs de drivers do kernel.
- **svcscan**: lista os serviços do Windows.
- **connections**: exibe informações de conexões de rede.
- **connscan**: verifica conexões de rede.
- **sockets**: lista os sockets de rede.
- **sockscan**: verifica sockets de rede.
- **netscan**: verifica conexões de rede.
- **autoruns**: lista os programas que são executados automaticamente.
- **printkey**: exibe informações sobre uma chave de registro.
- **hivelist**: lista as chaves de registro presentes na memória.
- **hashdump**: extrai hashes de senha do SAM.
- **userassist**: exibe informações sobre programas usados pelos usuários.
- **shellbags**: lista pastas acessadas recentemente.
- **mbrparser**: analisa o Registro Mestre de Inicialização.
- **mftparser**: analisa a Tabela de Arquivos Mestra.
- **yarascan**: executa varredura com Yara.
- **dumpfiles**: extrai arquivos do espaço de endereço do kernel.
- **dumpregistry**: extrai chaves de registro.
- **dumpcerts**: extrai certificados.
- **memmap**: exibe um mapa de memória.
- **memdump**: faz o despejo da memória.
- **linux_bash**: exibe comandos Bash executados.
- **linux_psaux**: exibe informações sobre processos Linux.
- **linux_proc_maps**: exibe mapas de memória de processos Linux.
- **linux_proc_maps**: exibe mapas de memória de processos Linux.
- **linux_lsof**: exibe arquivos abertos por processos Linux.
- **linux_check_afinfo**: verifica informações de soquete AF_INET.
- **linux_check_creds**: verifica credenciais de processos Linux.
- **linux_check_fop**: verifica ponteiros de função de operações de arquivo.
- **linux_check_idt**: verifica a Tabela de Despacho de Interrupção.
- **linux_check_modules**: verifica módulos do kernel Linux.
- **linux_check_syscall**: verifica a tabela de chamadas do sistema.
- **linux_check_syscalltbl**: verifica a tabela de chamadas do sistema.
- **linux_check_sysctl**: verifica variáveis de controle do sistema.
- **linux_check_sysmap**: verifica o mapa de memória do kernel.
- **linux_check_task_struct**: verifica a estrutura de tarefas do kernel.
- **linux_check_timer_list**: verifica a lista de temporizadores do kernel.
- **linux_check_vma**: verifica áreas de memória virtuais.
- **linux_lsmod**: lista módulos do kernel Linux.
- **linux_pslist**: lista processos Linux.
- **linux_pstree**: exibe processos Linux em formato de árvore.
- **linux_check_tty**: verifica terminais de controle de texto.
- **linux_ifconfig**: exibe informações de configuração de rede.
- **linux_netstat**: exibe estatísticas de rede.
- **linux_route**: exibe tabela de roteamento.
- **linux_dump_map**: faz o despejo de um mapa de memória.
- **linux_dump_mem**: faz o despejo da memória.
- **linux_banner**: exibe informações do kernel Linux.
- **linux_cpuinfo**: exibe informações da CPU.
- **linux_dmesg**: exibe mensagens do kernel.
- **linux_idt**: exibe a Tabela de Despacho de Interrupção.
- **linux_interrupts**: exibe interrupções.
- **linux_mount**: exibe pontos de montagem.
- **linux_slabinfo**: exibe informações sobre caches de objetos.
- **linux_uname**: exibe informações do sistema.
- **linux_version**: exibe a versão do kernel.
- **linux_check_afinfo**: verifica informações de soquete AF_INET.
- **linux_check_creds**: verifica credenciais de processos Linux.
- **linux_check_fop**: verifica ponteiros de função de operações de arquivo.
- **linux_check_idt**: verifica a Tabela de Despacho de Interrupção.
- **linux_check_modules**: verifica módulos do kernel Linux.
- **linux_check_syscall**: verifica a tabela de chamadas do sistema.
- **linux_check_syscalltbl**: verifica a tabela de chamadas do sistema.
- **linux_check_sysctl**: verifica variáveis de controle do sistema.
- **linux_check_sysmap**: verifica o mapa de memória do kernel.
- **linux_check_task_struct**: verifica a estrutura de tarefas do kernel.
- **linux_check_timer_list**: verifica a lista de temporizadores do kernel.
- **linux_check_vma**: verifica áreas de memória virtuais.
- **linux_lsmod**: lista módulos do kernel Linux.
- **linux_pslist**: lista processos Linux.
- **linux_pstree**: exibe processos Linux em formato de árvore.
- **linux_check_tty**: verifica terminais de controle de texto.
- **linux_ifconfig**: exibe informações de configuração de rede.
- **linux_netstat**: exibe estatísticas de rede.
- **linux_route**: exibe tabela de roteamento.
- **linux_dump_map**: faz o despejo de um mapa de memória.
- **linux_dump_mem**: faz o despejo da memória.
- **linux_banner**: exibe informações do kernel Linux.
- **linux_cpuinfo**: exibe informações da CPU.
- **linux_dmesg**: exibe mensagens do kernel.
- **linux_idt**: exibe a Tabela de Despacho de Interrupção.
- **linux_interrupts**: exibe interrupções.
- **linux_mount**: exibe pontos de montagem.
- **linux_slabinfo**: exibe informações sobre caches de objetos.
- **linux_uname**: exibe informações do sistema.
- **linux_version**: exibe a versão do kernel.
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
Comandos executados no `cmd.exe` são gerenciados pelo **`conhost.exe`** (ou `csrss.exe` em sistemas anteriores ao Windows 7). Isso significa que se o **`cmd.exe`** for encerrado por um atacante antes que um despejo de memória seja obtido, ainda é possível recuperar o histórico de comandos da sessão da memória do **`conhost.exe`**. Para fazer isso, se atividades incomuns forem detectadas nos módulos do console, a memória do processo **`conhost.exe`** associado deve ser despejada. Em seguida, ao procurar **strings** dentro desse despejo, linhas de comando usadas na sessão podem ser potencialmente extraídas.

### Ambiente

Obtenha as variáveis de ambiente de cada processo em execução. Pode haver alguns valores interessantes.
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endtab %}

{% tab title="vol2" %}## Folha de dicas do Volatility

### Comandos básicos
- `imageinfo`: exibe informações básicas sobre a imagem de memória
- `pslist`: lista os processos em execução
- `pstree`: exibe os processos em formato de árvore
- `psscan`: escaneia todos os processos
- `dlllist`: lista as DLLs carregadas por cada processo
- `cmdline`: exibe os argumentos da linha de comando de um processo
- `filescan`: escaneia os handles de arquivo
- `handles`: exibe os handles de arquivo de um processo
- `vadinfo`: exibe informações sobre regiões de memória alocadas
- `vadtree`: exibe as regiões de memória alocadas em formato de árvore
- `malfind`: encontra possíveis malwares na memória
- `yarascan`: escaneia a memória em busca de padrões com o Yara

### Plugins úteis
- `malfind`: encontra possíveis malwares na memória
- `timeliner`: cria uma linha do tempo dos processos
- `dumpfiles`: extrai arquivos da memória
- `apihooks`: detecta possíveis ganchos de API
- `ldrmodules`: lista os módulos carregados
- `svcscan`: lista os serviços do Windows
- `connscan`: escaneia as conexões de rede
- `autoruns`: lista os programas que são executados automaticamente
- `printkey`: exibe as subchaves e valores de uma chave de registro
- `hivelist`: lista os hives de registro

### Exemplos de uso
- `vol.py -f mem.raw imageinfo`
- `vol.py -f mem.raw pslist`
- `vol.py -f mem.raw --profile=Win7SP1x64 pstree`
- `vol.py -f mem.raw --profile=Win7SP1x64 malfind`

### Dicas adicionais
- Sempre especifique o perfil do sistema operacional ao usar o Volatility
- Faça uma cópia da imagem de memória original para preservar a integridade dos dados
- Documente todas as etapas do processo de análise de memória
- Utilize plugins adicionais conforme necessário para uma análise mais aprofundada

{% endtab %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
### Privilégios de Token

Verifique os tokens de privilégio em serviços inesperados.\
Pode ser interessante listar os processos que estão usando algum token privilegiado.
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}

{% tab title="vol2" %}A seguir estão alguns comandos úteis do Volatility para análise de despejo de memória:

- **imageinfo**: exibe informações gerais sobre a imagem de memória.
- **pslist**: lista os processos em execução.
- **pstree**: exibe os processos em formato de árvore.
- **dlllist**: lista as DLLs carregadas em cada processo.
- **handles**: exibe os identificadores de objeto aberto para cada processo.
- **cmdline**: exibe os argumentos da linha de comando de cada processo.
- **filescan**: escaneia a memória em busca de estruturas de dados de arquivos.
- **dumpfiles**: extrai arquivos do espaço de endereço de um processo.
- **malfind**: encontra possíveis malwares na memória.
- **apihooks**: exibe os ganchos de API em cada processo.
- **ldrmodules**: lista os módulos carregados em cada processo.
- **svcscan**: lista os serviços do Windows.
- **connections**: exibe informações de conexão de rede.
- **connscan**: escaneia a memória em busca de objetos de conexão de rede.
- **netscan**: encontra sockets de rede e conexões.
- **autoruns**: lista os programas que são configurados para serem executados automaticamente.
- **printkey**: exibe informações sobre uma determinada chave do registro.
- **hivelist**: lista os hives do registro presentes na memória.
- **hashdump**: extrai hashes de senha do SAM ou do LSASS.
- **userassist**: exibe programas frequentemente executados.
- **shellbags**: exibe informações sobre pastas acessadas.
- **timeliner**: cria uma linha do tempo dos eventos do sistema.
- **mftparser**: analisa o Master File Table (MFT) para informações sobre arquivos.
- **memmap**: exibe um mapa de memória do processo.
- **vadinfo**: exibe informações sobre regiões de memória alocadas virtualmente.
- **vaddump**: extrai regiões de memória alocadas virtualmente.
- **yarascan**: escaneia a memória em busca de padrões usando Yara.
- **yarascan**: escaneia a memória em busca de padrões usando Yara.
- **modscan**: escaneia a memória em busca de módulos do kernel.
- **moddump**: extrai módulos do kernel.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
### SIDs

Verifique cada SSID possuído por um processo.\
Pode ser interessante listar os processos que usam um SID de privilégios (e os processos que usam algum SID de serviço).
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}O Volatility é uma ferramenta poderosa para análise de dumps de memória. Abaixo estão alguns comandos úteis para análise de dumps de memória com o Volatility:

- **Identificar o perfil do sistema operacional:**
  ```
  volatility -f <dumpfile> imageinfo
  ```

- **Listar processos em execução:**
  ```
  volatility -f <dumpfile> --profile=<profile> pslist
  ```

- **Analisar sockets de rede:**
  ```
  volatility -f <dumpfile> --profile=<profile> netscan
  ```

- **Analisar registros de eventos:**
  ```
  volatility -f <dumpfile> --profile=<profile> evnets
  ```

- **Analisar registros de registro:**
  ```
  volatility -f <dumpfile> --profile=<profile> printkey -K 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
  ```

- **Analisar arquivos abertos:**
  ```
  volatility -f <dumpfile> --profile=<profile> filescan
  ```

- **Analisar conexões de rede:**
  ```
  volatility -f <dumpfile> --profile=<profile> connscan
  ```

- **Analisar cache de DNS:**
  ```
  volatility -f <dumpfile> --profile=<profile> dnscache
  ```

- **Analisar drivers carregados:**
  ```
  volatility -f <dumpfile> --profile=<profile> ldrmodules
  ```

- **Analisar módulos do kernel:**
  ```
  volatility -f <dumpfile> --profile=<profile> modscan
  ```

- **Analisar tarefas agendadas:**
  ```
  volatility -f <dumpfile> --profile=<profile> getsids
  ```

- **Analisar tokens de segurança:**
  ```
  volatility -f <dumpfile> --profile=<profile> tokens
  ```

- **Analisar serviços:**
  ```
  volatility -f <dumpfile> --profile=<profile> svcscan
  ```

- **Analisar portas abertas:**
  ```
  volatility -f <dumpfile> --profile=<profile> portscan
  ```

- **Analisar registros de registro:**
  ```
  volatility -f <dumpfile> --profile=<profile> printkey -K 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
  ```

- **Analisar arquivos de memória física:**
  ```
  volatility -f <dumpfile> --profile=<profile> memdump -p <pid> -D <output_directory>
  ```

- **Analisar arquivos de memória virtual:**
  ```
  volatility -f <dumpfile> --profile=<profile> memmap --output=dot --output-file=memmap.dot
  ```

- **Analisar arquivos de página:**
  ```
  volatility -f <dumpfile> --profile=<profile> psscan
  ```

- **Analisar arquivos de registro:**
  ```
  volatility -f <dumpfile> --profile=<profile> hivelist
  ```

- **Analisar arquivos de registro:**
  ```
  volatility -f <dumpfile> --profile=<profile> printkey -K 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
  ```

- **Analisar arquivos de registro:**
  ```
  volatility -f <dumpfile> --profile=<profile> printkey -K 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
  ```

- **Analisar arquivos de registro:**
  ```
  volatility -f <dumpfile> --profile=<profile> printkey -K 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
  ```

- **Analisar arquivos de registro:**
  ```
  volatility -f <dumpfile> --profile=<profile> printkey -K 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
  ```

- **Analisar arquivos de registro:**
  ```
  volatility -f <dumpfile> --profile=<profile> printkey -K 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
  ```

- **Analisar arquivos de registro:**
  ```
  volatility -f <dumpfile> --profile=<profile> printkey -K 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
  ```

- **Analisar arquivos de registro:**
  ```
  volatility -f <dumpfile> --profile=<profile> printkey -K 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
  ```

- **Analisar arquivos de registro:**
  ```
  volatility -f <dumpfile> --profile=<profile> printkey -K 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
  ```
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
### Handles

Útil para saber a quais outros arquivos, chaves, threads, processos... um **processo tem um handle** (aberto)
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{% endtab %}

{% tab title="vol2" %}O Volatility é uma ferramenta poderosa para análise de dumps de memória. Abaixo estão alguns comandos úteis para análise de memória com o Volatility:

- **Identificar o perfil do sistema operacional:**
  ```bash
  volatility -f memdump.mem imageinfo
  ```

- **Listar processos em execução:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE pslist
  ```

- **Analisar conexões de rede:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE connections
  ```

- **Analisar registros de registro:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE hivelist
  ```

- **Extrair um arquivo específico da memória:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE dumpfiles -Q ADDRESS -D output_directory/
  ```

- **Analisar cache DNS:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE dnscache
  ```

- **Analisar histórico de navegação:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE iehistory
  ```

- **Analisar processos e módulos carregados:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE psxview
  ```

- **Analisar pools de etiquetas de segurança:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE privs
  ```

- **Analisar sockets de rede:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE sockets
  ```

- **Analisar tarefas e DLLs injetadas:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE malfind
  ```

- **Analisar chaves de registro recentemente modificadas:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE hivescan
  ```

- **Analisar processos e threads:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE pstree
  ```

- **Analisar manipulação de objetos:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE handles
  ```

- **Analisar drivers carregados:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE ldrmodules
  ```

- **Analisar registros de eventos:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE evtlogs
  ```

- **Analisar tokens de segurança:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE tokens
  ```

- **Analisar serviços e drivers:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE svcscan
  ```

- **Analisar arquivos abertos:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE filescan
  ```

- **Analisar cache de impressão:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE printkey
  ```

- **Analisar cache de registro:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE printkey -K "ControlSet001\Control\Print\Printers"
  ```

- **Analisar cache de registro (todos os valores):**
  ```bash
  volatility -f memdump.mem --profile=PROFILE printkey -all
  ```

- **Analisar cache de registro (filtrar por valor):**
  ```bash
  volatility -f memdump.mem --profile=PROFILE printkey -K "ControlSet001\Control\Print\Printers" -all
  ```
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
### DLLs

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endtab %}

{% tab title="vol2" %}O seguinte é um resumo das principais funções do Volatility para análise de despejo de memória:

- **imageinfo**: Exibe informações gerais sobre o despejo de memória.
- **kdbgscan**: Localiza o depurador do kernel (KDBG) no despejo de memória.
- **kpcrscan**: Localiza o Registro de Controle do Processador do Kernel (KPCR) no despejo de memória.
- **pslist**: Lista os processos em execução no despejo de memória.
- **psscan**: Examina os processos em execução no despejo de memória.
- **pstree**: Exibe os processos em execução no despejo de memória em formato de árvore.
- **dlllist**: Lista as DLLs carregadas na memória.
- **handles**: Exibe os identificadores de objeto e os processos que possuem alças abertas.
- **cmdline**: Exibe os argumentos da linha de comando dos processos.
- **netscan**: Exibe informações sobre sockets de rede.
- **connections**: Lista as conexões de rede.
- **sockets**: Lista os sockets de rede.
- **svcscan**: Lista os serviços.
- **modscan**: Lista os módulos carregados.
- **malfind**: Procura por possíveis malwares na memória.
- **apihooks**: Detecta possíveis ganchos de API.
- **ldrmodules**: Lista os módulos carregados.
- **devicetree**: Exibe a árvore de dispositivos.
- **driverirp**: Lista os IRPs de driver.
- **ssdt**: Lista as entradas da Tabela de Despacho de Serviços do Sistema (SSDT).
- **gdt**: Exibe a Tabela de Descritores Globais.
- **idt**: Exibe a Tabela de Descritores de Interrupção.
- **callbacks**: Lista os callbacks registrados.
- **mutantscan**: Lista os Mutantes.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os átomos.
- **atomscan**: Lista os
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
### Strings por processos

O Volatility nos permite verificar a qual processo uma string pertence.
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endtab %}

{% tab title="vol2" %}O seguinte é um resumo das principais funções do Volatility para análise de despejo de memória:

- **imageinfo**: Exibe informações gerais sobre o despejo de memória.
- **kdbgscan**: Localiza o valor do depurador do kernel (KDBG) para uso em outros comandos.
- **pslist**: Lista os processos em execução no despejo de memória.
- **pstree**: Exibe os processos em forma de árvore.
- **dlllist**: Lista as DLLs carregadas em cada processo.
- **handles**: Exibe os identificadores de objeto aberto para cada processo.
- **cmdline**: Exibe os argumentos da linha de comando de cada processo.
- **filescan**: Escaneia a memória em busca de estruturas de dados de arquivos.
- **dumpfiles**: Extrai arquivos do despejo de memória.
- **malfind**: Identifica possíveis malwares na memória.
- **apihooks**: Detecta possíveis ganchos de API.
- **ldrmodules**: Lista os módulos carregados em cada processo.
- **svcscan**: Lista os serviços registrados no despejo de memória.
- **connections**: Exibe informações de conexão de rede.
- **sockets**: Lista os sockets de rede.
- **devicetree**: Exibe a árvore de dispositivos.
- **modscan**: Escaneia a memória em busca de módulos do kernel.
- **ssdt**: Exibe a Tabela de Despacho de Serviço do Sistema (SSDT).
- **callbacks**: Lista os callbacks do kernel.
- **mutantscan**: Identifica objetos de mutante.
- **yarascan**: Escaneia a memória em busca de padrões com o Yara.
- **printkey**: Exibe as chaves do registro do Windows.
- **hivelist**: Lista os hives do registro do Windows.
- **hashdump**: Extrai hashes de senha do despejo de memória.
- **userassist**: Exibe informações do UserAssist.
- **getsids**: Lista os SIDs dos processos.
- **getsids**: Lista os SIDs dos processos.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de átomo.
- **atomscan**: Identifica objetos de á
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
Permite também pesquisar por strings dentro de um processo usando o módulo yarascan:
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping Registry Hives**
  - `volatility -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Dumping LSA Secrets**
  - `volatility -f <memory_dump> --profile=<profile> lsadump`

- **Dumping SAM Database**
 json
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Dumping Password Hashes**
  - `volatility -f <memory_dump> --profile=<profile> hashdump`

- **Extracting Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`

- **Analyzing Malware**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> driverscan`

- **Analyzing DLLs**
  - `voljsonatility -f <memory_dump> --profile=<profile> dlllist`

- **Analyzing Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles`

- **Analyzing PSScan**
  - `volatility -f <memory_dump> --profile=<profile> psscan`

- **Analyzing Mutants**
  - `volatility -f <memory_dump> --profile=<profile> mutantscan`

- **Analyzing Yara Rules**
  - `volatility -f <memory_dump> --profile=<profile> yarascan`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing SSDT**
  - `volatility -f <memory_dump> --profile=<profile> ssdt`

- **Analyzing GDT**
  - `volatility -f <memory_dump> --profile=<profile> gdt`

- **Analyzing IDT**
  - `volatility -f <memory_dump> --profile=<profile> idt`

- **Analyzing LDT**
  - `volatility -f <memory_dump> --profile=<profile> ldt`

- **Analyzing User Handles**
  - `volatility -f <memory_dump> --profile=<profile> userhandles`

- **Analyzing Privileges**
  - `volatility -f <memory_dump> --profile=<profile> privs`

- **Analyzing Crashes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
  - `volatility -f <memory_dump> --profile=<profile> modscan`

- **Analyzing ImpHash**
  - `volatility -f <memory_dump> --profile=<profile> impscan`

- **Analyzing API Audit**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Trace**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Monitor**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile> apihooks`

- **Analyzing API Hooks**
  - `volatility -f <memory_dump> --profile=<profile>
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
### UserAssist

O **Windows** mantém o controle dos programas que você executa usando um recurso no registro chamado **chaves UserAssist**. Essas chaves registram quantas vezes cada programa é executado e quando foi executado pela última vez.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Commands

- **Image Identification**
  - `volatility -f <memory_dump> imageinfo`

- **Listing Processes**
  - `volatility -f <memory_dump> --profile=<profile> pslist`

- **Dumping a Process**
  - `volatility -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

- **Listing Network Connections**
  - `volatility -f <memory_dump> --profile=<profile> connections`

- **Dumping Registry Hives**
  - `voljson -f <memory_dump> --profile=<profile> hivelist`
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Analyzing Registry Keys**
  - `volatility -f <memory_dump> --profile=<profile> printkey -o <offset>`

- **Extracting Files**
  - `volatility -f <memory_dump> --profile=<profile> filescan`
  - `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <physical_offset> -D <output_directory>`

### Advanced Commands

- **Detecting Hidden Processes**
  - `volatility -f <memory_dump> --profile=<profile> psxview`

- **Analyzing Kernel Modules**
     - `volatility -f <memory_dump> --profile=<profile> modscan`
     - `volatility -f <memory_dump> --profile=<profile> moddump -o <offset> -D <output_directory>`

- **Identifying Sockets**
  - `volatility -f <memory_dump> --profile=<profile> sockscan`

- **Analyzing Drivers**
  - `volatility -f <memory_dump> --profile=<profile> drvscan`

- **Detecting Rootkits**
  - `volatility -f <memory_dump> --profile=<profile> malfind`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`

- **Analyzing Process Handles**
  - `volatility -f <memory_dump> --profile=<profile> handles -p <pid>`

- **Analyzing Process DLLs**
  - `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`

- **Analyzing Process Memory**
  - `volatility -f <memory_dump> --profile=<profile> memmap -p <pid>`

- **Analyzing Process Threads**
  - `volatility -f <memory_dump> --profile=<profile> threads -p <pid>`

- **Analyzing Process Environment Variables**
  - `volatility -f <memory_dump> --profile=<profile> envars -p <pid>`
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Serviços

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endtab %}

{% tab title="vol2" %}A seguir estão alguns comandos comuns do Volatility que podem ser úteis durante a análise de um dump de memória:

- **imageinfo**: exibe informações gerais sobre o dump de memória.
- **pslist**: lista os processos em execução no dump de memória.
- **pstree**: exibe os processos em formato de árvore.
- **dlllist**: lista as DLLs carregadas em cada processo.
- **handles**: exibe os identificadores de objetos abertos por cada processo.
- **cmdline**: exibe os argumentos da linha de comando de cada processo.
- **filescan**: escaneia a memória em busca de estruturas de dados de arquivos.
- **dumpfiles**: extrai arquivos do dump de memória.
- **malfind**: encontra possíveis injeções de malware na memória.
- **apihooks**: identifica possíveis ganchos de API em processos.
- **ldrmodules**: lista os módulos carregados em cada processo.
- **svcscan**: lista os serviços do Windows.
- **connections**: exibe informações de conexão de rede.
- **sockets**: lista os sockets de rede.
- **devicetree**: exibe a árvore de dispositivos.
- **registry**: permite acessar o registro do Windows.
- **hivelist**: lista os hives do registro.
- **printkey**: exibe as subchaves e valores de uma determinada chave do registro.
- **hashdump**: extrai hashes de senhas do dump de memória.
- **kdbgscan**: encontra o valor KDBG para análise de pool.
- **gdt**: exibe a tabela de descritores globais.
- **idt**: exibe a tabela de descritores de interrupção.
- **ssdt**: exibe a tabela de descritores de serviços do sistema.
- **callbacks**: lista os callbacks do kernel.
- **driverirp**: exibe as rotinas de tratamento de solicitação de E/S de driver.
- **modscan**: encontra módulos do kernel carregados.
- **moddump**: extrai um módulo do kernel.
- **yarascan**: escaneia a memória em busca de padrões usando YARA.
- **mbrparser**: analisa o registro de inicialização principal (MBR).
- **mftparser**: analisa a tabela de arquivos mestre (MFT).
- **shellbags**: analisa informações de pastas acessadas recentemente.
- **timeliner**: cria uma linha do tempo dos eventos do sistema.
- **psxview**: detecta processos ocultos.
- **autoruns**: lista os programas configurados para serem executados durante a inicialização.
- **consoles**: exibe informações sobre consoles de usuários.
- **desktops**: lista os desktops interativos.
- **shimcache**: analisa o cache de compatibilidade de aplicativos.
- **userassist**: analisa informações sobre programas usados por usuários.
- **malfind**: encontra possíveis injeções de malware na memória.
- **apihooks**: identifica possíveis ganchos de API em processos.
- **ldrmodules**: lista os módulos carregados em cada processo.
- **svcscan**: lista os serviços do Windows.
- **connections**: exibe informações de conexão de rede.
- **sockets**: lista os sockets de rede.
- **devicetree**: exibe a árvore de dispositivos.
- **registry**: permite acessar o registro do Windows.
- **hivelist**: lista os hives do registro.
- **printkey**: exibe as subchaves e valores de uma determinada chave do registro.
- **hashdump**: extrai hashes de senhas do dump de memória.
- **kdbgscan**: encontra o valor KDBG para análise de pool.
- **gdt**: exibe a tabela de descritores globais.
- **idt**: exibe a tabela de descritores de interrupção.
- **ssdt**: exibe a tabela de descritores de serviços do sistema.
- **callbacks**: lista os callbacks do kernel.
- **driverirp**: exibe as rotinas de tratamento de solicitação de E/S de driver.
- **modscan**: encontra módulos do kernel carregados.
- **moddump**: extrai um módulo do kernel.
- **yarascan**: escaneia a memória em busca de padrões usando YARA.
- **mbrparser**: analisa o registro de inicialização principal (MBR).
- **mftparser**: analisa a tabela de arquivos mestre (MFT).
- **shellbags**: analisa informações de pastas acessadas recentemente.
- **timeliner**: cria uma linha do tempo dos eventos do sistema.
- **psxview**: detecta processos ocultos.
- **autoruns**: lista os programas configurados para serem executados durante a inicialização.
- **consoles**: exibe informações sobre consoles de usuários.
- **desktops**: lista os desktops interativos.
- **shimcache**: analisa o cache de compatibilidade de aplicativos.
- **userassist**: analisa informações sobre programas usados por usuários.
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
## Rede

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% endtab %}

{% tab title="vol2" %}O seguinte é um resumo das principais funções do Volatility para análise de despejo de memória:

- **imageinfo**: exibe informações gerais sobre o despejo de memória.
- **kdbgscan**: localiza o ponteiro KDBG no despejo de memória.
- **kpcrscan**: localiza o ponteiro KPCR no despejo de memória.
- **pslist**: lista os processos em execução.
- **pstree**: exibe os processos em execução em formato de árvore.
- **dlllist**: lista os módulos DLL carregados em cada processo.
- **handles**: exibe os identificadores de objeto abertos por cada processo.
- **filescan**: localiza estruturas de arquivos no despejo de memória.
- **cmdline**: exibe os argumentos da linha de comando de cada processo.
- **sockets**: lista os sockets de rede abertos.
- **connections**: exibe as conexões de rede ativas.
- **malfind**: localiza possíveis artefatos de malware na memória.
- **apihooks**: identifica possíveis ganchos de API.
- **ldrmodules**: lista os módulos carregados em cada processo.
- **modscan**: localiza módulos do kernel no despejo de memória.
- **ssdt**: exibe a Tabela de Despacho de Serviços do Sistema.
- **callbacks**: lista os callbacks do kernel.
- **devicetree**: exibe a árvore de dispositivos.
- **driverirp**: lista os IRPs de driver.
- **printkey**: exibe as chaves do Registro de impressão.
- **privs**: lista os privilégios de cada processo.
- **getsids**: exibe os SIDs associados a cada processo.
- **dumpfiles**: extrai arquivos do despejo de memória.
- **memmap**: exibe um mapa de memória do despejo.
- **vadinfo**: exibe informações sobre regiões de memória virtuais.
- **vaddump**: extrai regiões de memória virtuais específicas.
- **yarascan**: executa varreduras YARA na memória.
- **malfind**: localiza possíveis artefatos de malware na memória.
- **apihooks**: identifica possíveis ganchos de API.
- **ldrmodules**: lista os módulos carregados em cada processo.
- **modscan**: localiza módulos do kernel no despejo de memória.
- **ssdt**: exibe a Tabela de Despacho de Serviços do Sistema.
- **callbacks**: lista os callbacks do kernel.
- **devicetree**: exibe a árvore de dispositivos.
- **driverirp**: lista os IRPs de driver.
- **printkey**: exibe as chaves do Registro de impressão.
- **privs**: lista os privilégios de cada processo.
- **getsids**: exibe os SIDs associados a cada processo.
- **dumpfiles**: extrai arquivos do despejo de memória.
- **memmap**: exibe um mapa de memória do despejo.
- **vadinfo**: exibe informações sobre regiões de memória virtuais.
- **vaddump**: extrai regiões de memória virtuais específicas.
- **yarascan**: executa varreduras YARA na memória.
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
## Registro do registro

### Imprimir registros disponíveis

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endtab %}

{% tab title="vol2" %}A seguir estão alguns comandos úteis do Volatility para análise de despejo de memória:

- **imageinfo**: exibe informações gerais sobre a imagem de memória.
- **pslist**: lista os processos em execução.
- **pstree**: exibe os processos em formato de árvore.
- **psscan**: verifica os processos ocultos.
- **dlllist**: lista as DLLs carregadas em cada processo.
- **handles**: exibe os identificadores de objeto aberto para cada processo.
- **cmdline**: mostra os argumentos da linha de comando de cada processo.
- **consoles**: lista os consoles associados a cada processo.
- **malfind**: procura por possíveis malwares na memória.
- **apihooks**: identifica possíveis ganchos de API.
- **ldrmodules**: lista os módulos carregados em cada processo.
- **svcscan**: verifica os serviços do Windows.
- **connections**: exibe as conexões de rede.
- **sockets**: lista os sockets de rede.
- **devicetree**: mostra a árvore de dispositivos.
- **modscan**: verifica módulos do kernel.
- **ssdt**: exibe a Tabela de Despacho de Serviços do Sistema.
- **callbacks**: lista os callbacks do kernel.
- **driverirp**: exibe as estruturas de solicitação de pacote (IRP) do driver.
- **printkey**: exibe as subchaves e valores de uma chave do Registro.
- **filescan**: procura por arquivos abertos.
- **dumpfiles**: extrai arquivos do espaço de endereço do processo.
- **memmap**: exibe o mapeamento de memória física.
- **memdump**: cria um despejo de memória de um processo específico.
- **hashdump**: extrai hashes de senha do SAM ou do LSASS.
- **hivelist**: lista os hives do Registro.
- **hivedump**: extrai um hive do Registro.
- **userassist**: exibe entradas do UserAssist.
- **shellbags**: lista as pastas acessadas recentemente.
- **getsids**: exibe os SIDs dos usuários.
- **getsidbysubject**: encontra SIDs com base em um nome de usuário.
- **getsidbytype**: encontra SIDs com base em um tipo.
- **getsidbyname**: encontra SIDs com base em um nome.
- **apihooks**: identifica possíveis ganchos de API.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: procura por possíveis malwares na memória.
- **malfind**: pro
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
### Obter um valor

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endtab %}

{% tab title="vol2" %}A seguir estão alguns comandos úteis do Volatility para análise de despejo de memória:

- **imageinfo**: exibe informações gerais sobre a imagem de memória.
- **pslist**: lista os processos em execução.
- **pstree**: exibe os processos em formato de árvore.
- **dlllist**: lista as DLLs carregadas em cada processo.
- **handles**: exibe os identificadores de objeto aberto para cada processo.
- **cmdline**: exibe os argumentos da linha de comando de cada processo.
- **filescan**: escaneia a memória em busca de estruturas de dados de arquivos.
- **dumpfiles**: extrai arquivos da memória.
- **malfind**: encontra possíveis malwares na memória.
- **apihooks**: exibe ganchos de API em cada processo.
- **ldrmodules**: lista os módulos carregados em cada processo.
- **svcscan**: lista os serviços do Windows.
- **connections**: exibe informações de conexão de rede.
- **connscan**: escaneia a memória em busca de objetos de conexão de rede.
- **netscan**: exibe informações de rede.
- **sockets**: lista os sockets de rede.
- **devicetree**: exibe a árvore de dispositivos.
- **modscan**: escaneia a memória em busca de módulos do kernel.
- **moddump**: extrai módulos do kernel da memória.
- **callbacks**: lista os callbacks do kernel.
- **driverirp**: exibe IRPs de driver.
- **ssdt**: exibe a Tabela de Despacho de Serviços do Sistema.
- **gdt**: exibe a Tabela de Descritores Globais.
- **idt**: exibe a Tabela de Descritores de Interrupção.
- **userassist**: exibe informações do UserAssist.
- **mbrparser**: analisa o Registro Mestre de Inicialização.
- **yarascan**: escaneia a memória em busca de padrões YARA.
- **yarascan**: escaneia a memória em busca de padrões YARA.
- **yara**: executa regras YARA na memória.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
- **atomscan**: escaneia a memória em busca de objetos de espaço de usuário atômicos.
-
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% endtab %}
{% endtabs %}

### Despejar
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Sistema de Arquivos

### Montagem

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
{% endtab %}

{% tab title="vol2" %}O seguinte é um resumo das principais funções do Volatility para análise de despejo de memória:

- **imageinfo**: Exibe informações gerais sobre o despejo de memória.
- **kdbgscan**: Localiza o valor do depurador do kernel (KDBG).
- **pslist**: Lista os processos em execução.
- **pstree**: Exibe os processos em forma de árvore.
- **dlllist**: Lista os módulos DLL carregados em cada processo.
- **handles**: Exibe os identificadores de objeto abertos por cada processo.
- **cmdline**: Exibe os argumentos da linha de comando de cada processo.
- **psscan**: Examina os processos em busca de sinais de rootkit.
- **netscan**: Exibe informações sobre sockets de rede.
- **connections**: Lista as conexões de rede.
- **sockets**: Exibe informações sobre sockets.
- **filescan**: Localiza arquivos no despejo de memória.
- **dumpfiles**: Extrai arquivos do despejo de memória.
- **malfind**: Identifica possíveis injeções de código malicioso.
- **apihooks**: Lista os ganchos de API.
- **ldrmodules**: Exibe informações sobre módulos carregados.
- **modscan**: Localiza módulos no despejo de memória.
- **ssdt**: Exibe a Tabela de Despacho de Serviços do Sistema (SSDT).
- **callbacks**: Lista os callbacks do kernel.
- **devicetree**: Exibe informações sobre a árvore de dispositivos.
- **driverirp**: Exibe IRPs de driver.
- **printkey**: Exibe informações sobre chaves do Registro.
- **svcscan**: Lista os serviços.
- **userassist**: Analisa as entradas do UserAssist.
- **mbrparser**: Analisa o Registro Mestre de Boot (MBR).
- **yarascan**: Executa uma varredura com Yara.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre tabelas de átomos.
- **atomscan**: Exibe informações sobre
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{% endtab %}
{% endtabs %}

### Análise de despejo de memória

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endtab %}

{% tab title="vol2" %}O Volatility é uma ferramenta poderosa para análise de dumps de memória. Abaixo estão alguns comandos úteis para análise de dumps de memória com o Volatility:

- **Identificar o perfil do sistema operacional:**
  ```
  volatility -f memdump.mem imageinfo
  ```

- **Listar processos em execução:**
  ```
  volatility -f memdump.mem pslist
  ```

- **Analisar processos e identificar possíveis atividades maliciosas:**
  ```
  volatility -f memdump.mem pstree
  ```

- **Analisar conexões de rede:**
  ```
  volatility -f memdump.mem connections
  ```

- **Analisar registros de eventos:**
  ```
  volatility -f memdump.mem evtlogs
  ```

- **Analisar drivers carregados:**
  ```
  volatility -f memdump.mem ldrmodules
  ```

- **Analisar portas abertas:**
  ```
  volatility -f memdump.mem sockets
  ```

- **Analisar cache DNS:**
  ```
  volatility -f memdump.mem cachedump
  ```

- **Analisar chaves de registro recentemente modificadas:**
  ```
  volatility -f memdump.mem hivelist
  ```
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
### Tabela Mestre de Arquivos

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{% endtab %}

{% tab title="vol2" %}O Volatility é uma ferramenta poderosa para análise de dumps de memória. Abaixo estão alguns comandos úteis para análise de dumps de memória com o Volatility:

- **Identificar o perfil do sistema operacional:**
  ```
  volatility -f memdump.mem imageinfo
  ```

- **Listar processos em execução:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 pslist
  ```

- **Analisar os sockets de rede:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 netscan
  ```

- **Analisar os registros de registro:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 hivelist
  ```

- **Extrair um arquivo específico da memória:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 dumpfiles -Q 0x000000007efdd000 -D .
  ```

- **Analisar os drivers carregados:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 ldrmodules
  ```

- **Analisar as conexões de rede:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 connscan
  ```

- **Analisar os processos e DLLs injetados:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 malfind
  ```

- **Analisar os handlers de objetos:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 handles
  ```

- **Analisar os tokens de segurança:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 tokens
  ```

- **Analisar os módulos do kernel:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 modules
  ```

- **Analisar os processos e threads:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 pstree
  ```

- **Analisar os registros de eventos:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 evnets
  ```

- **Analisar os serviços e drivers:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 svcscan
  ```

- **Analisar os arquivos abertos por processos:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 filescan
  ```

- **Analisar os objetos de memória física:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 physmap
  ```

- **Analisar os processos e suas DLLs:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 dlllist
  ```

- **Analisar os registros de registro:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 printkey -K "ControlSet001\Services"
  ```

- **Analisar os processos e suas threads:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 threads
  ```

- **Analisar os processos e suas handles:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 handles
  ```

- **Analisar os processos e suas conexões de rede:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 connscan
  ```

- **Analisar os processos e suas DLLs injetadas:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 malfind
  ```

- **Analisar os processos e seus tokens de segurança:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 tokens
  ```

- **Analisar os processos e seus arquivos abertos:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 filescan
  ```

- **Analisar os processos e seus objetos de memória física:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 physmap
  ```

- **Analisar os processos e seus registros de registro:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 printkey -K "ControlSet001\Services"
  ```

- **Analisar os processos e seus registros de eventos:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 evnets
  ```

- **Analisar os processos e seus serviços e drivers:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 svcscan
  ```

- **Analisar os processos e seus módulos do kernel:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 modules
  ```

- **Analisar os processos e suas conexões de rede:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 connscan
  ```

- **Analisar os processos e suas DLLs injetadas:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 malfind
  ```

- **Analisar os processos e seus tokens de segurança:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 tokens
  ```

- **Analisar os processos e seus arquivos abertos:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 filescan
  ```

- **Analisar os processos e seus objetos de memória física:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 physmap
  ```

- **Analisar os processos e seus registros de registro:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 printkey -K "ControlSet001\Services"
  ```

- **Analisar os processos e seus registros de eventos:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 evnets
  ```

- **Analisar os processos e seus serviços e drivers:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 svcscan
  ```

- **Analisar os processos e seus módulos do kernel:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 modules
  ```

- **Analisar os processos e suas threads:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 threads
  ```

- **Analisar os processos e suas handles:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 handles
  ```

- **Analisar os processos e suas conexões de rede:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 connscan
  ```

- **Analisar os processos e suas DLLs injetadas:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 malfind
  ```

- **Analisar os processos e seus tokens de segurança:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 tokens
  ```

- **Analisar os processos e seus arquivos abertos:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 filescan
  ```

- **Analisar os processos e seus objetos de memória física:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 physmap
  ```

- **Analisar os processos e seus registros de registro:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 printkey -K "ControlSet001\Services"
  ```

- **Analisar os processos e seus registros de eventos:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 evnets
  ```

- **Analisar os processos e seus serviços e drivers:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 svcscan
  ```
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

O sistema de arquivos **NTFS** utiliza um componente crítico conhecido como _tabela de arquivos mestre_ (MFT). Esta tabela inclui pelo menos uma entrada para cada arquivo em um volume, cobrindo também o próprio MFT. Detalhes vitais sobre cada arquivo, como **tamanho, carimbos de data/hora, permissões e dados reais**, são encapsulados dentro das entradas do MFT ou em áreas externas ao MFT, mas referenciadas por essas entradas. Mais detalhes podem ser encontrados na [documentação oficial](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table). 

### Chaves/Certificados SSL

{% tabs %}
{% tab title="vol3" %}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% endtab %}

{% tab title="vol2" %}## Folha de dicas do Volatility

### Comandos básicos
- `imageinfo`: exibe informações sobre a imagem de memória
- `pslist`: lista os processos em execução
- `pstree`: exibe os processos em formato de árvore
- `psscan`: escaneia todos os processos
- `dlllist`: lista as DLLs carregadas por cada processo
- `cmdline`: exibe os argumentos da linha de comando de um processo
- `filescan`: escaneia os handles de arquivo
- `handles`: exibe os handles de arquivo de um processo
- `vadinfo`: exibe informações sobre regiões de memória alocadas
- `vadtree`: exibe as regiões de memória alocadas em formato de árvore
- `malfind`: procura por possíveis malwares na memória
- `apihooks`: exibe os ganchos de API
- `ldrmodules`: lista os módulos carregados
- `modscan`: escaneia os módulos carregados
- `ssdt`: exibe a Tabela de Despacho de Serviços do Sistema
- `callbacks`: exibe os callbacks do kernel
- `devicetree`: exibe a árvore de dispositivos
- `driverirp`: exibe os IRPs de drivers
- `svcscan`: escaneia os serviços
- `connections`: exibe as conexões de rede
- `connscan`: escaneia as conexões de rede
- `sockets`: exibe informações sobre os sockets
- `sockscan`: escaneia os sockets
- `mutantscan`: escaneia os objetos de mutante
- `atomscan`: escaneia os objetos de átomo
- `userhandles`: exibe os handles de usuário
- `privs`: exibe os privilégios de processo
- `getsids`: exibe os SIDs de processo
- `psxview`: exibe os processos ocultos
- `cmdscan`: escaneia os comandos do console
- `consoles`: exibe informações sobre os consoles
- `desktops`: exibe informações sobre as áreas de trabalho
- `idt`: exibe a Tabela de Descritores Interruptores
- `gdt`: exibe a Tabela de Descritores Globais
- `drives`: exibe informações sobre os drivers
- `ss`: exibe informações sobre os esquemas de segurança
- `modules`: exibe informações sobre os módulos
- `moddump`: faz o dump de um módulo específico
- `modscan`: escaneia os módulos carregados
- `moddump`: faz o dump de um módulo específico
- `modload`: carrega um módulo específico
- `modunload`: descarrega um módulo específico
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlldump`: faz o dump de uma DLL específica
- `dlld
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
## Malware

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% endtab %}

{% tab title="vol2" %}O seguinte é um resumo das principais funções do Volatility para análise de despejo de memória:

- **imageinfo**: exibe informações gerais sobre o despejo de memória.
- **kdbgscan**: localiza o depurador do kernel (KDBG) na memória.
- **pslist**: lista os processos em execução.
- **pstree**: exibe os processos em forma de árvore.
- **dlllist**: lista as DLLs carregadas em cada processo.
- **handles**: exibe os identificadores de objeto aberto para cada processo.
- **cmdline**: exibe os argumentos da linha de comando de cada processo.
- **filescan**: localiza arquivos na memória.
- **malfind**: encontra possíveis malwares na memória.
- **apihooks**: identifica possíveis ganchos de API.
- **svcscan**: lista os serviços do Windows.
- **connections**: exibe informações de conexão de rede.
- **sockets**: lista os sockets de rede.
- **devicetree**: exibe a árvore de dispositivos.
- **modscan**: lista os módulos do kernel carregados.
- **ssdt**: exibe a Tabela de Despacho de Serviço do Sistema (SSDT).
- **callbacks**: lista os callbacks do kernel.
- **mutantscan**: identifica objetos de mutante.
- **driverirp**: exibe IRPs de driver.
- **printkey**: exibe chaves do Registro de impressão.
- **privs**: lista os privilégios do processo.
- **getsids**: exibe os SIDs de segurança.
- **dumpfiles**: extrai arquivos do despejo de memória.
- **yarascan**: executa varredura YARA em processos ou arquivos.
- **memmap**: exibe um mapa de memória do processo.
- **vadinfo**: exibe informações sobre regiões de memória virtuais.
- **vaddump**: extrai regiões de memória virtuais.
- **vadtree**: exibe regiões de memória virtuais em forma de árvore.
- **vadwalk**: exibe regiões de memória virtuais em um processo.
- **dlldump**: extrai DLLs da memória.
- **moddump**: extrai módulos do kernel da memória.
- **modscan**: lista os módulos do kernel carregados.
- **moddump**: extrai módulos do kernel da memória.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atomscan**: identifica objetos de átomo.
- **atom
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{% endtab %}
{% endtabs %}

### Escaneando com yara

Use este script para baixar e mesclar todas as regras de malware yara do github: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Crie o diretório _**rules**_ e execute-o. Isso criará um arquivo chamado _**malware\_rules.yar**_ que contém todas as regras yara para malware.
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{% endtab %}

{% tab title="vol2" %}Volatility Cheat Sheet

### Basic Forensic Methodology

1. **Memory Dump Analysis**
   - **Identify Profile**: `volatility -f memory_dump.raw imageinfo`
   - **Analyze Processes**: `volatility -f memory_dump.raw --profile=PROFILE pslist`
   - **Analyze Process Memory**: `volatility -f memory_dump.raw --profile=PROFILE memmap -p PID`
   - **Dump Process Memory**: `volvolatile -f memory_dump.raw --profile=PROFILE memdump -p PID -D .`
   - **Analyze DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Registry**: `volatility -f memory_dump.raw --profile=PROFILE printkey -o OFFSET`
   - **Analyze Network Connections**: `volatility -f memory_dump.raw --profile=PROFILE connections`
   - **Analyze Sockets**: `volatility -f memory_dump.raw --profile=PROFILE sockets`
   - **Analyze Drivers**: `volatility -f memory_dump.raw --profile=PROFILE drivers`
   - **Analyze Services**: `volatility -f memory_dump.raw --profile=PROFILE svcscan`
   - **Analyze Timelime**: `volatility -f memory_dump.raw --profile=PROFILE timeliner`
   - **Analyze User Information**: `volatility -f memory_dump.raw --profile=PROFILE getsids`
   - **Analyze User Sessions**: `volatility -f memory_dump.raw --profile=PROFILE consoles`
   - **Analyze Autostart Locations**: `volatility -f memory_dump.raw --profile=PROFILE hivelist`
   - **Analyze Mutants**: `volatility -f memory_dump.raw --profile=PROFILE mutantscan`
   - **Analyze Malware Artifacts**: `volatility -f memory_dump.raw --profile=PROFILE malfind`
   - **Analyze Rootkits**: `volatility -f memory_dump.raw --profile=PROFILE ldrmodules`
   - **Analyze Kernel Modules**: `volatility -f memory_dump.raw --profile=PROFILE modules`
   - **Analyze Crashed Processes**: `volatility -f memory_dump.raw --profile=PROFILE psxview`
   - **Analyze Process Environment Variables**: `volatility -f memory_dump.raw --profile=PROFILE envars -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
   - **Analyze Process Threads**: `volatility -f memory_dump.raw --profile=PROFILE threads -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process DLLs**: `volatility -f memory_dump.raw --profile=PROFILE dlllist -p PID`
   - **Analyze Process Handles**: `volatility -f memory_dump.raw --profile=PROFILE handles -p PID`
   - **Analyze Process PEB**: `volatility -f memory_dump.raw --profile=PROFILE psscan -p PID`
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
## MISC

### Plugins externos

Se deseja usar plugins externos, certifique-se de que as pastas relacionadas aos plugins sejam o primeiro parâmetro utilizado.
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{% endtab %}

{% tab title="vol2" %}O Volatility é uma ferramenta poderosa para análise de dumps de memória. Abaixo estão alguns comandos úteis para análise de dumps de memória com o Volatility:

- **Identificar o perfil do sistema operacional:**
  ```
  volatility -f memdump.mem imageinfo
  ```

- **Listar processos em execução:**
  ```
  volatility -f memdump.mem pslist
  ```

- **Analisar processos e identificar possíveis atividades maliciosas:**
  ```
  volatility -f memdump.mem pstree
  ```

- **Analisar conexões de rede:**
  ```
  volatility -f memdump.mem connections
  ```

- **Analisar registros de eventos:**
  ```
  volatility -f memdump.mem evtlogs
  ```

- **Analisar drivers carregados:**
  ```
  volatility -f memdump.mem ldrmodules
  ```

- **Analisar portas abertas:**
  ```
  volatility -f memdump.mem sockets
  ```

- **Analisar cache DNS:**
  ```
  volatility -f memdump.mem cachedump
  ```

- **Analisar chaves de registro recentemente modificadas:**
  ```
  volatility -f memdump.mem hivelist
  volatility -f memdump.mem printkey -o OFFSET
  ```

- **Analisar arquivos abertos:**
  ```
  volatility -f memdump.mem filescan
  ```

- **Extrair arquivos do dump de memória:**
  ```
  volatility -f memdump.mem dumpfiles -Q OFFSET -D <output_directory>
  ```

- **Analisar tokens de acesso:**
  ```
  volatility -f memdump.mem tokens
  ```

- **Analisar processos e módulos injetados:**
  ```
  volatility -f memdump.mem malfind
  ```

- **Analisar o registro do Windows:**
  ```
  volatility -f memdump.mem printkey -o OFFSET
  ```

- **Analisar o cache de credenciais:**
  ```
  volatility -f memdump.mem hashdump
  ```

- **Analisar o cache de senhas:**
  ```
  volatility -f memdump.mem mimikatz
  ```

- **Analisar o cache de senhas (alternativa):**
  ```
  volatility -f memdump.mem hashdump
  ```

- **Analisar o cache de senhas (outra alternativa):**
  ```
  volatility -f memdump.mem cachedump
  ```

- **Analisar o cache de senhas (outra alternativa):**
  ```
  volatility -f memdump.mem lsadump
  ```

- **Analisar o cache de senhas (outra alternativa):**
  ```
  volatility -f memdump.mem hashdump
  ```

- **Analisar o cache de senhas (outra alternativa):**
  ```
  volatility -f memdump.mem hashdump
  ```

- **Analisar o cache de senhas (outra alternativa):**
  ```
  volatility -f memdump.mem hashdump
  ```

- **Analisar o cache de senhas (outra alternativa):**
  ```
  volatility -f memdump.mem hashdump
  ```

- **Analisar o cache de senhas (outra alternativa):**
  ```
  volatility -f memdump.mem hashdump
  ```

- **Analisar o cache de senhas (outra alternativa):**
  ```
  volatility -f memdump.mem hashdump
  ```

- **Analisar o cache de senhas (outra alternativa):**
  ```
  volatility -f memdump.mem hashdump
  ```

- **Analisar o cache de senhas (outra alternativa):**
  ```
  volatility -f memdump.mem hashdump
  ```
{% endtab %}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

Baixe em [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexes

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% endtab %}

{% tab title="vol2" %}O Volatility é uma ferramenta poderosa para análise de dumps de memória. Abaixo estão alguns comandos úteis para análise de dumps de memória com o Volatility:

- **Identificar o perfil do sistema operacional:**
  ```
  volatility -f memdump.mem imageinfo
  ```

- **Listar todos os processos em execução:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 pslist
  ```

- **Analisar os sockets de rede:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 netscan
  ```

- **Analisar os registros de eventos:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 evnets
  ```

- **Analisar os drivers carregados:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 driverscan
  ```

- **Analisar os módulos do kernel:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 modules
  ```

- **Analisar os handles abertos por processos:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 handles
  ```

- **Analisar os objetos de segurança:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 getsids
  ```

- **Analisar os tokens de acesso:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 tokens
  ```

- **Analisar os processos e suas DLLs carregadas:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 dlllist
  ```

- **Analisar os registros do registro do Windows:**
  ```
  volatility -f memdump.mem --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"
  ```
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
### Links Simbólicos

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{% endtab %}

{% tab title="vol2" %}O Volatility é uma ferramenta poderosa para análise de dumps de memória. Abaixo estão alguns comandos úteis para análise de memória com o Volatility:

- **Identificar o perfil do sistema operacional:**
  ```bash
  volatility -f memdump.mem imageinfo
  ```

- **Listar processos em execução:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE pslist
  ```

- **Analisar sockets de rede:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE netscan
  ```

- **Analisar registros de eventos:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE evnets
  ```

- **Analisar registros de registro:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE printkey -K 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
  ```

- **Analisar arquivos abertos:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE filescan
  ```

- **Analisar conexões de rede:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE connscan
  ```

- **Analisar cache de DNS:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE dnscache
  ```

- **Analisar módulos carregados:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE modscan
  ```

- **Analisar handlers de IRP:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE irpfind
  ```

- **Analisar processos e DLLs injetados:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE malfind
  ```

- **Analisar pool de tags:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE poolscan
  ```

- **Analisar objetos de kernel:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE kdbgscan
  ```

- **Analisar handlers de objetos:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE handles
  ```

- **Analisar drivers de kernel:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE driverscan
  ```

- **Analisar objetos de arquivo:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE filescan
  ```

- **Analisar VAD tree:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE vadtree
  ```

- **Analisar VAD nodes:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE vadinfo
  ```

- **Analisar VAD walker:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE vadwalk
  ```

- **Analisar VAD cross view:**
  ```bash
  volatility -f memdump.mem --profile=PROFILE vad
  ```
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
### Bash

É possível **ler do histórico do bash na memória.** Você também pode fazer dump do arquivo _.bash\_history_, mas se estiver desativado, você ficará feliz em saber que pode usar este módulo de volatilidade.
```
./vol.py -f file.dmp linux.bash.Bash
```
{% endtab %}

{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
### Linha do Tempo

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{% endtab %}

{% tab title="vol2" %}O Volatility é uma ferramenta poderosa para análise de dumps de memória. Abaixo estão alguns comandos úteis para análise de dumps de memória com o Volatility:

- **Identificar o perfil do sistema operacional:**
  ```
  volatility -f memdump.mem imageinfo
  ```

- **Listar todos os processos em execução:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema pslist
  ```

- **Analisar os sockets de rede abertos:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema sockscan
  ```

- **Analisar os drivers carregados:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema ldrmodules
  ```

- **Analisar os registros de eventos:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema evnets
  ```

- **Analisar os arquivos abertos por processos:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema filescan
  ```

- **Analisar os registros do registro do Windows:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema hivelist
  ```

- **Extrair um arquivo específico da memória:**
  ```
  volatility -f memdump.mem --profile=PerfilDoSistema dumpfiles -Q EndereçoDoArquivo -D DiretórioDestino
  ```

Certifique-se de substituir `memdump.mem` pelo nome do arquivo de dump de memória e `PerfilDoSistema` pelo perfil do sistema operacional alvo.
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
### Drivers

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endtab %}

{% tab title="vol2" %}A seguir estão alguns comandos úteis do Volatility para análise de despejo de memória:

- **imageinfo**: exibe informações gerais sobre a imagem de memória.
- **pslist**: lista os processos em execução.
- **pstree**: exibe os processos em formato de árvore.
- **psscan**: verifica os processos ocultos.
- **dlllist**: lista as DLLs carregadas em cada processo.
- **handles**: exibe os identificadores de objeto aberto para cada processo.
- **cmdline**: exibe os argumentos da linha de comando de cada processo.
- **consoles**: lista os consoles associados a cada processo.
- **filescan**: verifica os arquivos mapeados na memória.
- **svcscan**: lista os serviços do Windows.
- **connections**: exibe as conexões de rede.
- **malfind**: procura por possíveis malwares na memória.
- **apihooks**: identifica possíveis ganchos de API.
- **ldrmodules**: lista os módulos carregados em cada processo.
- **modscan**: verifica os módulos do kernel.
- **ssdt**: exibe a Tabela de Despacho de Serviço do Sistema.
- **callbacks**: lista os callbacks do kernel.
- **driverirp**: exibe as IRPs (Pacotes de Solicitação de E/S) de drivers do kernel.
- **devicetree**: exibe a árvore de dispositivos.
- **printkey**: exibe as chaves do Registro de impressão.
- **privs**: lista os privilégios de cada processo.
- **getsids**: exibe os SIDs (Identificadores de Segurança) de cada processo.
- **dumpfiles**: extrai arquivos do espaço de endereço de um processo.
- **yarascan**: executa uma varredura YARA na memória.
- **memmap**: exibe os intervalos de endereços mapeados na memória.
- **vadinfo**: exibe informações sobre regiões de memória virtuais.
- **vaddump**: extrai uma região de memória virtual específica.
- **vadtree**: exibe as regiões de memória virtuais em formato de árvore.
- **vadwalk**: exibe as páginas de memória em uma região de memória virtual.
- **dlldump**: extrai uma DLL específica da memória.
- **dumpregistry**: extrai uma parte ou todo o Registro do Windows da memória.
- **hivelist**: lista os hives do Registro do Windows.
- **printkey**: exibe as chaves do Registro de impressão.
- **hashdump**: extrai hashes de senha do SAM e do sistema.
- **kdbgscan**: verifica a presença de estruturas KDBG.
- **kpcrscan**: verifica a presença de estruturas KPCR.
- **gdt**: exibe a Tabela de Descritores Globais.
- **idt**: exibe a Tabela de Descritores de Interrupção.
- **ss**: exibe a Tabela de Seletores de Segmento.
- **userassist**: exibe informações do UserAssist.
- **shellbags**: exibe informações do ShellBags.
- **mbrparser**: analisa o Registro de Mestre de Boot.
- **mftparser**: analisa a Tabela de Arquivos Mestres.
- **usnparser**: analisa o Jornal de Atualização do Sistema.
- **$logfile**: analisa o arquivo $LogFile.
- **$mft**: analisa o arquivo $MFT.
- **$boot**: analisa o arquivo $Boot.
- **$bitmap**: analisa o arquivo $Bitmap.
- **$logfile**: analisa o arquivo $LogFile.
- **$volume**: analisa o arquivo $Volume.
- **$attrdef**: analisa o arquivo $AttrDef.
- **$data**: analisa o arquivo $DATA.
- **$boot**: analisa o arquivo $Boot.
- **$badclus**: analisa o arquivo $BadClus.
- **$secure**: analisa o arquivo $Secure.
- **$upcase**: analisa o arquivo $UpCase.
- **$extend**: analisa o arquivo $Extend.
- **$quota**: analisa o arquivo $Quota.
- **$objid**: analisa o arquivo $ObjId.
- **$reparse**: analisa o arquivo $Reparse.
- **$quota
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
### Obter área de transferência
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### Obter histórico do IE
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Obter texto do bloco de notas
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Captura de tela
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Registro Mestre de Inicialização (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
O **Master Boot Record (MBR)** desempenha um papel crucial na gestão das partições lógicas de um meio de armazenamento, que são estruturadas com diferentes [sistemas de arquivos](https://en.wikipedia.org/wiki/File_system). Ele não apenas mantém informações de layout de partição, mas também contém código executável atuando como um carregador de inicialização. Esse carregador de inicialização inicia diretamente o processo de carregamento da segunda etapa do SO (consulte [carregador de inicialização de segunda etapa](https://en.wikipedia.org/wiki/Second-stage_boot_loader)) ou trabalha em harmonia com o [registro de inicialização de volume](https://en.wikipedia.org/wiki/Volume_boot_record) (VBR) de cada partição. Para conhecimento mais aprofundado, consulte a [página da Wikipedia sobre MBR](https://en.wikipedia.org/wiki/Master_boot_record).

## Referências
* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
​* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

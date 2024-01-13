<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que importam mais para que você possa corrigi-las mais rapidamente. Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha tecnológica, de APIs a aplicativos web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

# Ferramentas de Carving & Recuperação

Mais ferramentas em [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

## Autopsy

A ferramenta mais comum usada em forense para extrair arquivos de imagens é o [**Autopsy**](https://www.autopsy.com/download/). Baixe-o, instale-o e faça-o processar o arquivo para encontrar arquivos "ocultos". Note que o Autopsy é construído para suportar imagens de disco e outros tipos de imagens, mas não arquivos simples.

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** é uma ferramenta para pesquisar arquivos binários como imagens e arquivos de áudio em busca de arquivos e dados embutidos.\
Pode ser instalado com `apt`, no entanto, o [código-fonte](https://github.com/ReFirmLabs/binwalk) pode ser encontrado no github.\
**Comandos úteis**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Outra ferramenta comum para encontrar arquivos ocultos é o **foremost**. Você pode encontrar o arquivo de configuração do foremost em `/etc/foremost.conf`. Se você deseja procurar apenas por alguns arquivos específicos, descomente-os. Se você não descomentar nada, o foremost procurará pelos tipos de arquivos configurados por padrão.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** é outra ferramenta que pode ser usada para encontrar e extrair **arquivos embutidos em um arquivo**. Neste caso, será necessário descomentar do arquivo de configuração (_/etc/scalpel/scalpel.conf_) os tipos de arquivo que deseja que ela extraia.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Esta ferramenta está incluída no Kali, mas você pode encontrá-la aqui: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Esta ferramenta pode escanear uma imagem e irá **extrair pcaps** dentro dela, **informações de rede (URLs, domínios, IPs, MACs, e-mails)** e mais **arquivos**. Você só precisa fazer:
```
bulk_extractor memory.img -o out_folder
```
Navegue por **todas as informações** que a ferramenta coletou (senhas?), **analise** os **pacotes** (leia[ **Análise de Pcaps**](../pcap-inspection/)), procure por **domínios estranhos** (domínios relacionados a **malware** ou **inexistentes**).

## PhotoRec

Você pode encontrá-lo em [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Vem com versões GUI e CLI. Você pode selecionar os **tipos de arquivo** que deseja que o PhotoRec procure.

![](<../../../.gitbook/assets/image (524).png>)

## binvis

Confira o [código](https://code.google.com/archive/p/binvis/) e a [ferramenta de página web](https://binvis.io/#/).

### Características do BinVis

* Visualizador de estrutura **ativo e visual**
* Múltiplos gráficos para diferentes pontos de foco
* Foco em porções de uma amostra
* **Visualização de strings e recursos**, em executáveis PE ou ELF, por exemplo.
* Obtenção de **padrões** para criptoanálise em arquivos
* **Detecção** de algoritmos de empacotamento ou codificação
* **Identificação** de Esteganografia por padrões
* **Diferenciação binária visual**

BinVis é um ótimo **ponto de partida para se familiarizar com um alvo desconhecido** em um cenário de caixa-preta.

# Ferramentas Específicas para Carving de Dados

## FindAES

Procura por chaves AES buscando seus agendamentos de chave. Capaz de encontrar chaves de 128, 192 e 256 bits, como as usadas por TrueCrypt e BitLocker.

Baixe [aqui](https://sourceforge.net/projects/findaes/).

# Ferramentas Complementares

Você pode usar [**viu**](https://github.com/atanunq/viu) para ver imagens a partir do terminal.\
Você pode usar a ferramenta de linha de comando do Linux **pdftotext** para transformar um PDF em texto e lê-lo.


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que importam mais para que você possa corrigi-las mais rapidamente. Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha de tecnologia, de APIs a aplicativos web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

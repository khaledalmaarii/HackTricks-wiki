# File/Data Carving & Recovery Tools

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Carving & Recovery tools

Mais ferramentas em [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

A ferramenta mais comum usada em forense para extrair arquivos de imagens é [**Autopsy**](https://www.autopsy.com/download/). Baixe, instale e faça com que ela ingira o arquivo para encontrar arquivos "ocultos". Note que o Autopsy é projetado para suportar imagens de disco e outros tipos de imagens, mas não arquivos simples.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** é uma ferramenta para analisar arquivos binários para encontrar conteúdo embutido. É instalável via `apt` e seu código-fonte está no [GitHub](https://github.com/ReFirmLabs/binwalk).

**Comandos úteis**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Outra ferramenta comum para encontrar arquivos ocultos é **foremost**. Você pode encontrar o arquivo de configuração do foremost em `/etc/foremost.conf`. Se você quiser apenas procurar por alguns arquivos específicos, descomente-os. Se você não descomentar nada, o foremost irá procurar pelos tipos de arquivos configurados por padrão.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** é outra ferramenta que pode ser usada para encontrar e extrair **arquivos incorporados em um arquivo**. Neste caso, você precisará descomentar no arquivo de configuração (_/etc/scalpel/scalpel.conf_) os tipos de arquivo que deseja que ele extraia.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Esta ferramenta vem dentro do kali, mas você pode encontrá-la aqui: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Esta ferramenta pode escanear uma imagem e **extrair pcaps** dentro dela, **informações de rede (URLs, domínios, IPs, MACs, e-mails)** e mais **arquivos**. Você só precisa fazer:
```
bulk_extractor memory.img -o out_folder
```
Navegue por **todas as informações** que a ferramenta coletou (senhas?), **analise** os **pacotes** (leia[ **análise de Pcaps**](../pcap-inspection/)), procure por **domínios estranhos** (domínios relacionados a **malware** ou **inexistentes**).

### PhotoRec

Você pode encontrá-lo em [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Ele vem com versões GUI e CLI. Você pode selecionar os **tipos de arquivo** que deseja que o PhotoRec procure.

![](<../../../.gitbook/assets/image (524).png>)

### binvis

Verifique o [código](https://code.google.com/archive/p/binvis/) e a [página da ferramenta](https://binvis.io/#/).

#### Recursos do BinVis

* Visual e ativo **visualizador de estrutura**
* Múltiplos gráficos para diferentes pontos de foco
* Focando em porções de uma amostra
* **Vendo strings e recursos**, em executáveis PE ou ELF, por exemplo.
* Obtendo **padrões** para criptoanálise em arquivos
* **Identificando** algoritmos de empacotamento ou codificação
* **Identificar** Esteganografia por padrões
* **Diferença** binária visual

BinVis é um ótimo **ponto de partida para se familiarizar com um alvo desconhecido** em um cenário de caixa-preta.

## Ferramentas Específicas de Carving de Dados

### FindAES

Procura por chaves AES buscando por seus cronogramas de chaves. Capaz de encontrar chaves de 128, 192 e 256 bits, como as usadas pelo TrueCrypt e BitLocker.

Baixe [aqui](https://sourceforge.net/projects/findaes/).

## Ferramentas Complementares

Você pode usar [**viu** ](https://github.com/atanunq/viu) para ver imagens a partir do terminal.\
Você pode usar a ferramenta de linha de comando linux **pdftotext** para transformar um pdf em texto e lê-lo.

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

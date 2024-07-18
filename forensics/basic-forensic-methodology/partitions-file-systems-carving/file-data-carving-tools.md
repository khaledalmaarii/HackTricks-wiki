{% hint style="success" %}
Aprenda e pratique AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}


# Ferramentas de Carving

## Autopsy

A ferramenta mais comum usada em forense para extrair arquivos de imagens é o [**Autopsy**](https://www.autopsy.com/download/). Baixe, instale e faça com que ele ingira o arquivo para encontrar arquivos "ocultos". Note que o Autopsy é construído para suportar imagens de disco e outros tipos de imagens, mas não arquivos simples.

## Binwalk <a id="binwalk"></a>

**Binwalk** é uma ferramenta para buscar arquivos binários como imagens e arquivos de áudio para encontrar arquivos e dados embutidos.
Pode ser instalado com `apt`, no entanto, a [fonte](https://github.com/ReFirmLabs/binwalk) pode ser encontrada no github.
**Comandos úteis**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Outra ferramenta comum para encontrar arquivos ocultos é o **foremost**. Você pode encontrar o arquivo de configuração do foremost em `/etc/foremost.conf`. Se você deseja procurar por arquivos específicos, descomente-os. Se você não descomentar nada, o foremost procurará pelos tipos de arquivos configurados por padrão.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** é outra ferramenta que pode ser usada para encontrar e extrair **arquivos incorporados em um arquivo**. Neste caso, você precisará descomentar no arquivo de configuração \(_/etc/scalpel/scalpel.conf_\) os tipos de arquivo que deseja extrair.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Esta ferramenta vem dentro do kali mas você pode encontrá-la aqui: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Esta ferramenta pode escanear uma imagem e irá **extrair pcaps** dentro dela, **informações de rede\(URLs, domínios, IPs, MACs, e-mails\)** e mais **arquivos**. Você só precisa fazer:
```text
bulk_extractor memory.img -o out_folder
```
Navegue por **todas as informações** que a ferramenta coletou \(senhas?\), **analise** os **pacotes** \(leia [**Análise de Pcaps**](../pcap-inspection/)\), procure por **domínios estranhos** \(domínios relacionados a **malware** ou **não existentes**\).

## PhotoRec

Você pode encontrá-lo em [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Ele vem com versões GUI e CLI. Você pode selecionar os **tipos de arquivo** que deseja que o PhotoRec pesquise.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Ferramentas Específicas de Escultura de Dados

## FindAES

Procura por chaves AES pesquisando por suas tabelas de chaves. Capaz de encontrar chaves de 128, 192 e 256 bits, como as usadas pelo TrueCrypt e BitLocker.

Baixe [aqui](https://sourceforge.net/projects/findaes/).

# Ferramentas complementares

Você pode usar [**viu**](https://github.com/atanunq/viu) para ver imagens a partir do terminal.
Você pode usar a ferramenta de linha de comando do Linux **pdftotext** para transformar um PDF em texto e lê-lo.



{% hint style="success" %}
Aprenda e pratique Hacking na AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking no GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

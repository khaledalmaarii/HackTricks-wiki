<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Ferramentas de Carving

## Autopsy

A ferramenta mais comum usada em forense para extrair arquivos de imagens é o [**Autopsy**](https://www.autopsy.com/download/). Baixe-o, instale-o e faça-o processar o arquivo para encontrar arquivos "ocultos". Note que o Autopsy é construído para suportar imagens de disco e outros tipos de imagens, mas não arquivos simples.

## Binwalk <a id="binwalk"></a>

**Binwalk** é uma ferramenta para procurar arquivos binários como imagens e arquivos de áudio em busca de arquivos e dados embutidos.
Pode ser instalado com `apt`, no entanto, o [código-fonte](https://github.com/ReFirmLabs/binwalk) pode ser encontrado no github.
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

**Scalpel** é outra ferramenta que pode ser usada para encontrar e extrair **arquivos embutidos em um arquivo**. Neste caso, você precisará descomentar do arquivo de configuração \(_/etc/scalpel/scalpel.conf_\) os tipos de arquivo que deseja extrair.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Esta ferramenta está inclusa no Kali, mas você pode encontrá-la aqui: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Esta ferramenta pode escanear uma imagem e irá **extrair pcaps** dentro dela, **informações de rede \(URLs, domínios, IPs, MACs, e-mails\)** e mais **arquivos**. Você só precisa fazer:
```text
bulk_extractor memory.img -o out_folder
```
Navegue por **todas as informações** que a ferramenta coletou \(senhas?\), **analise** os **pacotes** \(leia [**Análise de Pcaps**](../pcap-inspection/)\), procure por **domínios estranhos** \(domínios relacionados a **malware** ou **inexistentes**\).

## PhotoRec

Você pode encontrá-lo em [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Ele vem com versão GUI e CLI. Você pode selecionar os **tipos de arquivo** que deseja que o PhotoRec procure.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Ferramentas Específicas para Carving de Dados

## FindAES

Procura por chaves AES buscando seus agendamentos de chave. Capaz de encontrar chaves de 128, 192 e 256 bits, como as usadas por TrueCrypt e BitLocker.

Baixe [aqui](https://sourceforge.net/projects/findaes/).

# Ferramentas Complementares

Você pode usar [**viu**](https://github.com/atanunq/viu) para ver imagens do terminal.
Você pode usar a ferramenta de linha de comando do Linux **pdftotext** para transformar um PDF em texto e lê-lo.



<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

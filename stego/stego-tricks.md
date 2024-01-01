# Técnicas de Esteganografia

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que importam mais para que você possa corrigi-las mais rapidamente. Intruder monitora sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha tecnológica, de APIs a aplicativos web e sistemas em nuvem. [**Experimente grátis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Extraindo dados de todos os arquivos

### Binwalk <a href="#binwalk" id="binwalk"></a>

Binwalk é uma ferramenta para pesquisar arquivos binários, como imagens e arquivos de áudio, em busca de arquivos ocultos e dados embutidos.\
Pode ser instalado com `apt`, e o [código-fonte](https://github.com/ReFirmLabs/binwalk) está disponível no Github.\
**Comandos úteis**:\
`binwalk arquivo` : Exibe os dados embutidos no arquivo especificado\
`binwalk -e arquivo` : Exibe e extrai os dados do arquivo especificado\
`binwalk --dd ".*" arquivo` : Exibe e extrai todos os dados do arquivo especificado

### Foremost <a href="#foremost" id="foremost"></a>

Foremost é um programa que recupera arquivos baseados em seus cabeçalhos, rodapés e estruturas de dados internas. Acho especialmente útil ao lidar com imagens png. Você pode selecionar os arquivos que o Foremost irá extrair alterando o arquivo de configuração em **/etc/foremost.conf.**\
Pode ser instalado com `apt`, e o [código-fonte](https://github.com/korczis/foremost) está disponível no Github.\
**Comandos úteis:**\
`foremost -i arquivo` : extrai dados do arquivo especificado.

### Exiftool <a href="#exiftool" id="exiftool"></a>

Às vezes, informações importantes estão ocultas nos metadados de uma imagem ou arquivo; exiftool pode ser muito útil para visualizar metadados de arquivos.\
Você pode obtê-lo [aqui](https://www.sno.phy.queensu.ca/\~phil/exiftool/)\
**Comandos úteis:**\
`exiftool arquivo` : mostra os metadados do arquivo especificado

### Exiv2 <a href="#exiv2" id="exiv2"></a>

Uma ferramenta semelhante ao exiftool.\
Pode ser instalado com `apt`, e o [código-fonte](https://github.com/Exiv2/exiv2) está disponível no Github.\
[Site oficial](http://www.exiv2.org/)\
**Comandos úteis:**\
`exiv2 arquivo` : mostra os metadados do arquivo especificado

### File

Verifique que tipo de arquivo você tem

### Strings

Extraia strings do arquivo.\
Comandos úteis:\
`strings -n 6 arquivo`: Extrai strings com comprimento mínimo de 6\
`strings -n 6 arquivo | head -n 20`: Extrai as primeiras 20 strings com comprimento mínimo de 6\
`strings -n 6 arquivo | tail -n 20`: Extrai as últimas 20 strings com comprimento mínimo de 6\
`strings -e s -n 6 arquivo`: Extrai strings de 7 bits\
`strings -e S -n 6 arquivo`: Extrai strings de 8 bits\
`strings -e l -n 6 arquivo`: Extrai strings de 16 bits (little-endian)\
`strings -e b -n 6 arquivo`: Extrai strings de 16 bits (big-endian)\
`strings -e L -n 6 arquivo`: Extrai strings de 32 bits (little-endian)\
`strings -e B -n 6 arquivo`: Extrai strings de 32 bits (big-endian)

### cmp - Comparação

Se você tem alguma imagem/áudio/vídeo **modificado**, verifique se consegue **encontrar o original exato** na internet, depois **compare ambos** arquivos com:
```
cmp original.jpg stego.jpg -b -l
```
## Extraindo dados ocultos em texto

### Dados ocultos em espaços

Se você encontrar que uma **linha de texto** está **maior** do que deveria ser, então algumas **informações ocultas** podem estar incluídas dentro dos **espaços** usando caracteres invisíveis.󐁈󐁥󐁬󐁬󐁯󐀠󐁴󐁨\
Para **extrair** os **dados**, você pode usar: [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente, alimentados pelas ferramentas comunitárias **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Extraindo dados de imagens

### identify

Ferramenta [GraphicMagick](https://imagemagick.org/script/download.php) para verificar que tipo de imagem um arquivo é. Também verifica se a imagem está corrompida.
```
./magick identify -verbose stego.jpg
```
Se a imagem estiver danificada, você pode ser capaz de restaurá-la simplesmente adicionando um comentário de metadados a ela (se estiver muito danificada, isso não funcionará):
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### Steghide \[JPEG, BMP, WAV, AU] <a href="#steghide" id="steghide"></a>

Steghide é um programa de esteganografia que oculta dados em vários tipos de arquivos de imagem e áudio. Ele suporta os seguintes formatos de arquivo: `JPEG, BMP, WAV e AU`. Também é útil para extrair dados embutidos e criptografados de outros arquivos.\
Pode ser instalado com `apt`, e o [código-fonte](https://github.com/StefanoDeVuono/steghide) pode ser encontrado no Github.\
**Comandos úteis:**\
`steghide info file` : exibe informações sobre se um arquivo tem dados embutidos ou não.\
`steghide extract -sf file [--passphrase password]` : extrai dados embutidos de um arquivo \[usando uma senha]

Você também pode extrair conteúdo do steghide usando a web: [https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html)

**Força bruta** no Steghide: [stegcracker](https://github.com/Paradoxis/StegCracker.git) `stegcracker <file> [<wordlist>]`

### Zsteg \[PNG, BMP] <a href="#zsteg" id="zsteg"></a>

zsteg é uma ferramenta que pode detectar dados ocultos em arquivos png e bmp.\
Para instalá-lo: `gem install zsteg`. O código-fonte também pode ser encontrado no [Github](https://github.com/zed-0xff/zsteg)\
**Comandos úteis:**\
`zsteg -a file` : Executa todos os métodos de detecção no arquivo fornecido\
`zsteg -E file` : Extrai dados com o payload fornecido (exemplo: zsteg -E b4,bgr,msb,xy name.png)

### stegoVeritas JPG, PNG, GIF, TIFF, BMP

Capaz de uma ampla variedade de truques simples e avançados, esta ferramenta pode verificar metadados de arquivos, criar imagens transformadas, força bruta em LSB e mais. Confira `stegoveritas.py -h` para ler sobre suas capacidades completas. Execute `stegoveritas.py stego.jpg` para rodar todas as verificações.

### Stegsolve

Às vezes, há uma mensagem ou um texto oculto na própria imagem que, para visualizá-lo, deve ter filtros de cores aplicados ou alguns níveis de cores alterados. Embora você possa fazer isso com algo como GIMP ou Photoshop, Stegsolve facilita. É uma pequena ferramenta Java que aplica muitos filtros de cores úteis em imagens; Em desafios de CTF, Stegsolve é frequentemente um grande economizador de tempo.\
Você pode obtê-lo no [Github](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)\
Para usá-lo, basta abrir a imagem e clicar nos botões `<` `>`.

### FFT

Para encontrar conteúdo oculto usando Transformada Rápida de Fourier (FFT):

* [http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [https://www.ejectamenta.com/Fourifier-fullscreen/](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [https://github.com/0xcomposure/FFTStegPic](https://github.com/0xcomposure/FFTStegPic)
* `pip3 install opencv-python`

### Stegpy \[PNG, BMP, GIF, WebP, WAV]

Um programa para codificar informações em arquivos de imagem e áudio através de esteganografia. Pode armazenar os dados como texto simples ou criptografado.\
Encontre-o no [Github](https://github.com/dhsdshdhk/stegpy).

### Pngcheck

Obtenha detalhes sobre um arquivo PNG (ou até descubra se é na verdade algo diferente!).\
`apt-get install pngcheck`: Instale a ferramenta\
`pngcheck stego.png` : Obtenha informações sobre o PNG

### Algumas outras ferramentas de imagem que valem a pena mencionar

* [http://magiceye.ecksdee.co.uk/](http://magiceye.ecksdee.co.uk/)
* [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [https://github.com/resurrecting-open-source-projects/outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [https://www.openstego.com/](https://www.openstego.com/)
* [https://diit.sourceforge.net/](https://diit.sourceforge.net/)

## Extraindo dados de áudios

### [Steghide \[JPEG, BMP, WAV, AU\]](stego-tricks.md#steghide) <a href="#steghide" id="steghide"></a>

### [Stegpy \[PNG, BMP, GIF, WebP, WAV\]](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)

### ffmpeg

ffmpeg pode ser usado para verificar a integridade de arquivos de áudio, relatando várias informações sobre o arquivo, bem como quaisquer erros encontrados.\
`ffmpeg -v info -i stego.mp3 -f null -`

### Wavsteg \[WAV] <a href="#wavsteg" id="wavsteg"></a>

WavSteg é uma ferramenta Python3 que pode ocultar dados, usando o bit menos significativo, em arquivos wav. Também pode procurar e extrair dados de arquivos wav.\
Você pode obtê-lo no [Github](https://github.com/ragibson/Steganography#WavSteg)\
Comandos úteis:\
`python3 WavSteg.py -r -b 1 -s soundfile -o outputfile` : Extrai para um arquivo de saída (pegando apenas 1 lsb)\
`python3 WavSteg.py -r -b 2 -s soundfile -o outputfile` : Extrai para um arquivo de saída (pegando apenas 2 lsb)

### Deepsound

Oculte e verifique informações criptografadas com AES-265 em arquivos de som. Baixe da [página oficial](http://jpinsoft.net/deepsound/download.aspx).\
Para procurar informações ocultas, basta executar o programa e abrir o arquivo de som. Se o DeepSound encontrar dados ocultos, você precisará fornecer a senha para desbloqueá-los.

### Sonic visualizer <a href="#sonic-visualizer" id="sonic-visualizer"></a>

Sonic visualizer é uma ferramenta para visualizar e analisar o conteúdo de arquivos de áudio. Pode ser muito útil ao enfrentar desafios de esteganografia de áudio; você pode revelar formas ocultas em arquivos de áudio que muitas outras ferramentas não detectam.\
Se estiver com dificuldades, sempre verifique o espectrograma do áudio. [Site Oficial](https://www.sonicvisualiser.org/)

### Tons DTMF - Tons de discagem

* [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
* [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Outros truques

### Comprimento binário SQRT - Código QR

Se você receber dados binários com um comprimento SQRT de um número inteiro, pode ser algum tipo de código QR:
```
import math
math.sqrt(2500) #50
```
Para converter binários "1"s e "0"s em uma imagem adequada: [https://www.dcode.fr/binary-image](https://github.com/carlospolop/hacktricks/tree/32fa51552498a17d266ff03e62dfd1e2a61dcd10/binary-image/README.md)\
Para ler um código QR: [https://online-barcode-reader.inliteresearch.com/](https://online-barcode-reader.inliteresearch.com/)

### Braile

[https://www.branah.com/braille-translator](https://www.branah.com/braille-translator\))

## **Referências**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que importam mais para que você possa corrigi-las mais rápido. Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha tecnológica, de APIs a aplicativos web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Aprenda hacking em AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

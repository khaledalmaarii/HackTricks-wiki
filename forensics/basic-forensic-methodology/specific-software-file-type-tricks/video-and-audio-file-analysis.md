<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

**Manipulação de arquivos de áudio e vídeo** é um elemento básico nos desafios de **forense CTF**, aproveitando a **esteganografia** e a análise de metadados para ocultar ou revelar mensagens secretas. Ferramentas como **[mediainfo](https://mediaarea.net/en/MediaInfo)** e **`exiftool`** são essenciais para inspecionar metadados de arquivos e identificar tipos de conteúdo.

Para desafios de áudio, **[Audacity](http://www.audacityteam.org/)** se destaca como uma ferramenta principal para visualizar formas de onda e analisar espectrogramas, essenciais para descobrir texto codificado em áudio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** é altamente recomendado para análise detalhada de espectrogramas. **Audacity** permite a manipulação de áudio, como desacelerar ou reverter faixas para detectar mensagens ocultas. **[Sox](http://sox.sourceforge.net/)**, um utilitário de linha de comando, se destaca na conversão e edição de arquivos de áudio.

A manipulação dos **Bits Menos Significativos (LSB)** é uma técnica comum na esteganografia de áudio e vídeo, explorando os pedaços de tamanho fixo dos arquivos de mídia para incorporar dados discretamente. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** é útil para decodificar mensagens ocultas como tons **DTMF** ou **código Morse**.

Desafios de vídeo frequentemente envolvem formatos de contêiner que agrupam fluxos de áudio e vídeo. **[FFmpeg](http://ffmpeg.org/)** é a escolha para analisar e manipular esses formatos, capaz de desmultiplexar e reproduzir conteúdo. Para desenvolvedores, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integra as capacidades do FFmpeg no Python para interações scriptáveis avançadas.

Essa variedade de ferramentas destaca a versatilidade necessária nos desafios CTF, onde os participantes devem empregar um amplo espectro de técnicas de análise e manipulação para descobrir dados ocultos dentro de arquivos de áudio e vídeo.

# Referências
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) 

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


De: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

Assim como nos formatos de arquivo de imagem, a manipulação de arquivos de áudio e vídeo é um tema comum em desafios de forense CTF, não porque hacking ou ocultação de dados aconteçam dessa forma no mundo real, mas apenas porque áudio e vídeo são divertidos. Assim como nos formatos de arquivo de imagem, a esteganografia pode ser usada para incorporar uma mensagem secreta nos dados de conteúdo, e novamente você deve verificar as áreas de metadados do arquivo em busca de pistas. Seu primeiro passo deve ser dar uma olhada com a ferramenta [mediainfo](https://mediaarea.net/en/MediaInfo) \(ou `exiftool`\) e identificar o tipo de conteúdo e examinar seus metadados.

[Audacity](http://www.audacityteam.org/) é a principal ferramenta de visualização de arquivos de áudio de código aberto. Os autores de desafios CTF adoram codificar texto em formas de onda de áudio, que você pode ver usando a visualização de espectrograma \(embora uma ferramenta especializada chamada [Sonic Visualiser](http://www.sonicvisualiser.org/) seja melhor para essa tarefa em particular\). O Audacity também pode permitir que você diminua a velocidade, reverta e faça outras manipulações que podem revelar uma mensagem oculta se você suspeitar que haja uma \(se você ouvir áudio distorcido, interferência ou estática\). [Sox](http://sox.sourceforge.net/) é outra ferramenta útil de linha de comando para converter e manipular arquivos de áudio.

Também é comum verificar os Bits Menos Significativos (LSB) em busca de uma mensagem secreta. A maioria dos formatos de mídia de áudio e vídeo usa "pedaços" discretos (de tamanho fixo) para que possam ser transmitidos; os LSBs desses pedaços são um local comum para contrabandear alguns dados sem afetar visivelmente o arquivo.

Às vezes, uma mensagem pode ser codificada no áudio como tons [DTMF](http://dialabc.com/sound/detect/index.html) ou código morse. Para esses casos, tente trabalhar com o [multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng) para decodificá-los.

Os formatos de arquivo de vídeo são formatos de contêiner, que contêm fluxos separados de áudio e vídeo que são multiplexados juntos para reprodução. Para analisar e manipular formatos de arquivo de vídeo, é recomendado o uso do [FFmpeg](http://ffmpeg.org/). `ffmpeg -i` fornece uma análise inicial do conteúdo do arquivo. Ele também pode desmultiplexar ou reproduzir os fluxos de conteúdo. O poder do FFmpeg é exposto ao Python usando [ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html).

</details>

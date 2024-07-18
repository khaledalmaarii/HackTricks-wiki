{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

A manipulação de arquivos de áudio e vídeo é fundamental em desafios de **forense CTF**, aproveitando a **esteganografia** e a análise de metadados para ocultar ou revelar mensagens secretas. Ferramentas como **[mediainfo](https://mediaarea.net/en/MediaInfo)** e **`exiftool`** são essenciais para inspecionar metadados de arquivos e identificar tipos de conteúdo.

Para desafios de áudio, **[Audacity](http://www.audacityteam.org/)** se destaca como uma ferramenta principal para visualizar formas de onda e analisar espectrogramas, essenciais para descobrir texto codificado em áudio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** é altamente recomendado para análise detalhada de espectrogramas. **Audacity** permite a manipulação de áudio, como desacelerar ou reverter faixas para detectar mensagens ocultas. **[Sox](http://sox.sourceforge.net/)**, um utilitário de linha de comando, se destaca na conversão e edição de arquivos de áudio.

A manipulação dos **Bits Menos Significativos (LSB)** é uma técnica comum em esteganografia de áudio e vídeo, explorando os pedaços de tamanho fixo dos arquivos de mídia para incorporar dados discretamente. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** é útil para decodificar mensagens ocultas como tons **DTMF** ou **código Morse**.

Desafios de vídeo frequentemente envolvem formatos de contêiner que agrupam fluxos de áudio e vídeo. **[FFmpeg](http://ffmpeg.org/)** é a ferramenta padrão para analisar e manipular esses formatos, capaz de desmultiplexar e reproduzir conteúdo. Para desenvolvedores, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integra as capacidades do FFmpeg no Python para interações scriptáveis avançadas.

Essa variedade de ferramentas destaca a versatilidade necessária em desafios CTF, onde os participantes devem empregar um amplo espectro de técnicas de análise e manipulação para descobrir dados ocultos em arquivos de áudio e vídeo.

## Referências
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)
  
{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Entrenamiento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Entrenamiento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoia a HackTricks</summary>

* ¡Consulta los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

La **manipulación de archivos de audio y video** es fundamental en los desafíos de **forense CTF**, aprovechando la **esteganografía** y el análisis de metadatos para ocultar o revelar mensajes secretos. Herramientas como **[mediainfo](https://mediaarea.net/en/MediaInfo)** y **`exiftool`** son esenciales para inspeccionar metadatos de archivos e identificar tipos de contenido.

Para desafíos de audio, **[Audacity](http://www.audacityteam.org/)** destaca como una herramienta principal para ver formas de onda y analizar espectrogramas, esencial para descubrir texto codificado en audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** es muy recomendado para un análisis detallado de espectrogramas. **Audacity** permite la manipulación de audio como ralentizar o revertir pistas para detectar mensajes ocultos. **[Sox](http://sox.sourceforge.net/)**, una utilidad de línea de comandos, sobresale en la conversión y edición de archivos de audio.

La manipulación de **Bits Menos Significativos (LSB)** es una técnica común en la esteganografía de audio y video, explotando los fragmentos de tamaño fijo de los archivos multimedia para incrustar datos discretamente. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** es útil para decodificar mensajes ocultos como tonos **DTMF** o **código Morse**.

Los desafíos de video a menudo involucran formatos de contenedor que agrupan flujos de audio y video. **[FFmpeg](http://ffmpeg.org/)** es la herramienta principal para analizar y manipular estos formatos, capaz de desmultiplexar y reproducir contenido. Para desarrolladores, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integra las capacidades de FFmpeg en Python para interacciones avanzadas scriptables.

Esta variedad de herramientas subraya la versatilidad requerida en los desafíos de CTF, donde los participantes deben emplear un amplio espectro de técnicas de análisis y manipulación para descubrir datos ocultos dentro de archivos de audio y video.

## Referencias
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)
{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Entrenamiento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Entrenamiento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoia a HackTricks</summary>

* ¡Consulta los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

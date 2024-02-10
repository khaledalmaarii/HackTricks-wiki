<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>

La **manipolazione di file audio e video** è una pratica comune nelle **sfide di forensics CTF**, che sfrutta la steganografia e l'analisi dei metadati per nascondere o rivelare messaggi segreti. Strumenti come **[mediainfo](https://mediaarea.net/en/MediaInfo)** e **`exiftool`** sono essenziali per ispezionare i metadati dei file e identificare i tipi di contenuto.

Per le sfide audio, **[Audacity](http://www.audacityteam.org/)** si distingue come uno strumento di primo piano per visualizzare le forme d'onda e analizzare gli spettrogrammi, essenziali per scoprire testo codificato nell'audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** è altamente consigliato per l'analisi dettagliata degli spettrogrammi. **Audacity** consente la manipolazione audio come rallentare o invertire le tracce per rilevare messaggi nascosti. **[Sox](http://sox.sourceforge.net/)**, un'utilità a riga di comando, eccelle nella conversione e modifica dei file audio.

La manipolazione dei **Least Significant Bits (LSB)** è una tecnica comune nella steganografia audio e video, sfruttando le porzioni di dimensione fissa dei file multimediali per incorporare dati in modo discreto. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** è utile per decodificare messaggi nascosti come toni **DTMF** o codice **Morse**.

Le sfide video spesso coinvolgono formati di contenitore che raggruppano flussi audio e video. **[FFmpeg](http://ffmpeg.org/)** è lo strumento principale per analizzare e manipolare questi formati, in grado di demultiplexare e riprodurre i contenuti. Per gli sviluppatori, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integra le capacità di FFmpeg in Python per interazioni avanzate scriptabili.

Questa serie di strumenti sottolinea la versatilità richiesta nelle sfide CTF, in cui i partecipanti devono utilizzare un'ampia gamma di tecniche di analisi e manipolazione per scoprire dati nascosti all'interno di file audio e video.

## Riferimenti
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>

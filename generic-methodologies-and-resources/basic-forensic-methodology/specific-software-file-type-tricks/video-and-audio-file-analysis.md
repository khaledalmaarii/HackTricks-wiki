{% hint style="success" %}
**Manipolazione di file audio e video** è un pilastro nelle sfide di **forensics CTF**, sfruttando **steganografia** e analisi dei metadati per nascondere o rivelare messaggi segreti. Strumenti come **[mediainfo](https://mediaarea.net/en/MediaInfo)** e **`exiftool`** sono essenziali per ispezionare i metadati dei file e identificare i tipi di contenuto.

Per le sfide audio, **[Audacity](http://www.audacityteam.org/)** si distingue come uno strumento principale per visualizzare le forme d'onda e analizzare gli spettrogrammi, essenziale per scoprire testo codificato nell'audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** è altamente raccomandato per un'analisi dettagliata degli spettrogrammi. **Audacity** consente la manipolazione audio come rallentare o invertire le tracce per rilevare messaggi nascosti. **[Sox](http://sox.sourceforge.net/)**, un'utilità a riga di comando, eccelle nella conversione e modifica di file audio.

La manipolazione dei **Least Significant Bits (LSB)** è una tecnica comune nella steganografia audio e video, sfruttando i chunk di dimensioni fisse dei file multimediali per incorporare dati in modo discreto. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** è utile per decodificare messaggi nascosti come toni **DTMF** o **codice Morse**.

Le sfide video spesso coinvolgono formati di contenitore che raggruppano flussi audio e video. **[FFmpeg](http://ffmpeg.org/)** è lo strumento principale per analizzare e manipolare questi formati, in grado di demultiplexare e riprodurre i contenuti. Per gli sviluppatori, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integra le capacità di FFmpeg in Python per interazioni script avanzate.

Questa serie di strumenti sottolinea la versatilità richiesta nelle sfide CTF, dove i partecipanti devono impiegare un'ampia gamma di tecniche di analisi e manipolazione per scoprire dati nascosti all'interno di file audio e video.

## Riferimenti
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)
{% endhint %}

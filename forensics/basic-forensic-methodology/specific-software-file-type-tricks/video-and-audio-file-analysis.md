{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

La manipulation de fichiers audio et vidéo est un élément essentiel dans les défis de **forensics CTF**, exploitant la **stéganographie** et l'analyse des métadonnées pour cacher ou révéler des messages secrets. Des outils tels que **[mediainfo](https://mediaarea.net/en/MediaInfo)** et **`exiftool`** sont essentiels pour inspecter les métadonnées des fichiers et identifier les types de contenu.

Pour les défis audio, **[Audacity](http://www.audacityteam.org/)** se distingue comme un outil de premier plan pour visualiser les formes d'onde et analyser les spectrogrammes, essentiel pour découvrir du texte encodé dans l'audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** est fortement recommandé pour une analyse détaillée des spectrogrammes. **Audacity** permet la manipulation audio comme ralentir ou inverser les pistes pour détecter des messages cachés. **[Sox](http://sox.sourceforge.net/)**, un utilitaire en ligne de commande, excelle dans la conversion et l'édition de fichiers audio.

La manipulation des **bits de poids faible (LSB)** est une technique courante en stéganographie audio et vidéo, exploitant les morceaux de taille fixe des fichiers multimédias pour intégrer discrètement des données. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** est utile pour décoder des messages cachés sous forme de **tonalités DTMF** ou de **code Morse**.

Les défis vidéo impliquent souvent des formats de conteneurs qui regroupent des flux audio et vidéo. **[FFmpeg](http://ffmpeg.org/)** est l'outil de référence pour analyser et manipuler ces formats, capable de démultiplexer et de lire le contenu. Pour les développeurs, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** intègre les capacités de FFmpeg dans Python pour des interactions scriptables avancées.

Cet ensemble d'outils souligne la polyvalence requise dans les défis CTF, où les participants doivent utiliser un large éventail de techniques d'analyse et de manipulation pour découvrir des données cachées dans des fichiers audio et vidéo.

## Références
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)
  
{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


From: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

Comme pour les formats de fichiers image, la manipulation de fichiers audio et vidéo est un thème courant dans les défis de forensics CTF, non pas parce que le piratage ou la dissimulation de données se produisent de cette manière dans le monde réel, mais simplement parce que l'audio et la vidéo sont amusants. Comme pour les formats de fichiers image, la stéganographie peut être utilisée pour incorporer un message secret dans les données de contenu, et vous devriez à nouveau vérifier les zones de métadonnées du fichier pour des indices. Votre première étape devrait être de jeter un coup d'œil avec l'outil [mediainfo](https://mediaarea.net/en/MediaInfo) \(ou `exiftool`\) et d'identifier le type de contenu et de regarder ses métadonnées.

[Audacity](http://www.audacityteam.org/) est l'outil premier open-source pour les fichiers audio et l'affichage des formes d'onde. Les auteurs de défis CTF aiment encoder du texte dans les formes d'onde audio, que vous pouvez voir en utilisant la vue spectrogramme \(bien qu'un outil spécialisé appelé [Sonic Visualiser](http://www.sonicvisualiser.org/) soit meilleur pour cette tâche en particulier\). Audacity peut également vous permettre de ralentir, inverser et effectuer d'autres manipulations qui pourraient révéler un message caché si vous soupçonnez qu'il y en a un \(si vous entendez un audio brouillé, des interférences ou du bruit\). [Sox](http://sox.sourceforge.net/) est un autre outil en ligne de commande utile pour convertir et manipuler des fichiers audio.

Il est également courant de vérifier les bits de poids faible (LSB) pour un message secret. La plupart des formats de médias audio et vidéo utilisent des "chunks" discrets (de taille fixe) afin qu'ils puissent être diffusés en continu ; les LSB de ces chunks sont un endroit commun pour faire passer des données sans affecter visiblement le fichier.

Parfois, un message peut être encodé dans l'audio sous forme de [tonalités DTMF](http://dialabc.com/sound/detect/index.html) ou de code morse. Pour cela, essayez de travailler avec [multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng) pour les décoder.

Les formats de fichiers vidéo sont des formats de conteneur, qui contiennent des flux séparés à la fois audio et vidéo qui sont multiplexés ensemble pour la lecture. Pour analyser et manipuler les formats de fichiers vidéo, [FFmpeg](http://ffmpeg.org/) est recommandé. `ffmpeg -i` donne une analyse initiale du contenu du fichier. Il peut également démultiplexer ou lire en continu les flux de contenu. La puissance de FFmpeg est exposée à Python en utilisant [ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html).

</details>

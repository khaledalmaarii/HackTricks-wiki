# Analyse de fichiers PDF

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.io/) pour créer et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

À partir de : [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

Le format de fichier PDF est extrêmement compliqué, avec suffisamment de trucs et de cachettes [pour écrire pendant des années](https://www.sultanik.com/pocorgtfo/). Cela le rend également populaire pour les défis de forensique CTF. La NSA a écrit un guide sur ces cachettes en 2008 intitulé "Données cachées et métadonnées dans les fichiers Adobe PDF : Risques de publication et contre-mesures". Il n'est plus disponible à son URL d'origine, mais vous pouvez [trouver une copie ici](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf). Ange Albertini tient également un wiki sur GitHub de [trucs de format de fichier PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md).

Le format PDF est partiellement en texte brut, comme HTML, mais avec de nombreux "objets" binaires dans le contenu. Didier Stevens a écrit [un bon matériel introductif](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) sur le format. Les objets binaires peuvent être des données compressées ou même chiffrées, et incluent du contenu dans des langages de script comme JavaScript ou Flash. Pour afficher la structure d'un PDF, vous pouvez soit le parcourir avec un éditeur de texte, soit l'ouvrir avec un éditeur de format de fichier PDF comme Origami.

[qpdf](https://github.com/qpdf/qpdf) est un outil qui peut être utile pour explorer un PDF et transformer ou extraire des informations de celui-ci. Un autre est un framework en Ruby appelé [Origami](https://github.com/mobmewireless/origami-pdf).

Lors de l'exploration du contenu PDF pour des données cachées, certains des endroits à vérifier incluent :

* les couches non visibles
* le format de métadonnées d'Adobe "XMP"
* la fonctionnalité de "génération incrémentielle" de PDF dans laquelle une version précédente est conservée mais pas visible pour l'utilisateur
* texte blanc sur un fond blanc
* texte derrière des images
* une image derrière une image superposée
* commentaires non affichés

Il existe également plusieurs packages Python pour travailler avec le format de fichier PDF, comme [PeepDF](https://github.com/jesparza/peepdf), qui vous permettent d'écrire vos propres scripts d'analyse. 

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

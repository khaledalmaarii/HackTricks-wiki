# Analyse de fichier PDF

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

À partir de : [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

Le format de fichier PDF est extrêmement compliqué, avec suffisamment de trucs et de cachettes [pour écrire pendant des années](https://www.sultanik.com/pocorgtfo/). Cela le rend également populaire pour les défis de forensics CTF. La NSA a rédigé un guide sur ces cachettes en 2008 intitulé "Données cachées et métadonnées dans les fichiers Adobe PDF : Risques de publication et contre-mesures". Il n'est plus disponible à son URL d'origine, mais vous pouvez [trouver une copie ici](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf). Ange Albertini tient également un wiki sur GitHub des [trucs du format de fichier PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md).

Le format PDF est partiellement en texte brut, comme HTML, mais avec de nombreux "objets" binaires dans le contenu. Didier Stevens a écrit [du matériel introductif de qualité](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) sur le format. Les objets binaires peuvent être des données compressées ou même chiffrées, et incluent du contenu dans des langages de script comme JavaScript ou Flash. Pour afficher la structure d'un PDF, vous pouvez soit le parcourir avec un éditeur de texte, soit l'ouvrir avec un éditeur de format de fichier PDF comme Origami.

[qpdf](https://github.com/qpdf/qpdf) est un outil qui peut être utile pour explorer un PDF et transformer ou extraire des informations de celui-ci. Un autre est un framework en Ruby appelé [Origami](https://github.com/mobmewireless/origami-pdf).

Lors de l'exploration du contenu PDF pour trouver des données cachées, certains des endroits à vérifier incluent :

* les couches non visibles
* le format de métadonnées "XMP" d'Adobe
* la fonction de "génération incrémentielle" du PDF où une version précédente est conservée mais n'est pas visible pour l'utilisateur
* texte blanc sur un fond blanc
* texte derrière des images
* une image derrière une image superposée
* des commentaires non affichés

Il existe également plusieurs packages Python pour travailler avec le format de fichier PDF, comme [PeepDF](https://github.com/jesparza/peepdf), qui vous permettent d'écrire vos propres scripts d'analyse. 

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

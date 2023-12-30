# Analyse de fichiers PDF

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et **automatiser des workflows** grâce aux outils communautaires **les plus avancés**.\
Accédez-y dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

Source : [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

Le format PDF est un format de fichier document extrêmement compliqué, avec suffisamment d'astuces et de cachettes [pour en écrire pendant des années](https://www.sultanik.com/pocorgtfo/). Cela le rend également populaire pour les défis de forensics en CTF. La NSA a écrit un guide sur ces cachettes en 2008 intitulé "Hidden Data and Metadata in Adobe PDF Files: Publication Risks and Countermeasures." Il n'est plus disponible à son URL d'origine, mais vous pouvez [trouver une copie ici](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf). Ange Albertini maintient également un wiki sur GitHub des [astuces de format de fichier PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md).

Le format PDF est partiellement en texte clair, comme le HTML, mais contient de nombreux "objets" binaires dans le contenu. Didier Stevens a écrit [un bon matériel d'introduction](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) sur le format. Les objets binaires peuvent être des données compressées ou même cryptées, et inclure du contenu dans des langages de script comme JavaScript ou Flash. Pour afficher la structure d'un PDF, vous pouvez le parcourir avec un éditeur de texte ou l'ouvrir avec un éditeur de format de fichier conscient du PDF comme Origami.

[qpdf](https://github.com/qpdf/qpdf) est un outil qui peut être utile pour explorer un PDF et transformer ou extraire des informations de celui-ci. Un autre est un framework en Ruby appelé [Origami](https://github.com/mobmewireless/origami-pdf).

Lors de l'exploration du contenu PDF à la recherche de données cachées, certains des endroits à vérifier incluent :

* les couches non visibles
* le format de métadonnées d'Adobe "XMP"
* la fonctionnalité de "génération incrémentielle" de PDF où une version précédente est conservée mais non visible par l'utilisateur
* du texte blanc sur un fond blanc
* du texte derrière des images
* une image derrière une image superposée
* des commentaires non affichés

Il existe également plusieurs packages Python pour travailler avec le format de fichier PDF, comme [PeepDF](https://github.com/jesparza/peepdf), qui vous permettent d'écrire vos propres scripts d'analyse.

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

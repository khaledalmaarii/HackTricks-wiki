# Analyse de fichiers Office

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires **les plus avancés**.\
Accédez-y dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Introduction

Microsoft a créé **des dizaines de formats de fichiers de documents Office**, dont beaucoup sont populaires pour la distribution d'attaques de phishing et de malwares en raison de leur capacité à **inclure des macros** (scripts VBA).

De manière générale, il existe deux générations de formats de fichiers Office : les formats **OLE** (extensions de fichiers comme RTF, DOC, XLS, PPT), et les formats "**Office Open XML**" (extensions de fichiers qui incluent DOCX, XLSX, PPTX). **Les deux** formats sont des formats binaires de fichiers composés structurés qui **permettent le contenu Lié ou Intégré** (Objets). Les fichiers OOXML sont des conteneurs de fichiers zip, ce qui signifie que l'une des façons les plus simples de vérifier la présence de données cachées est de simplement `dézipper` le document :
```
$ unzip example.docx
Archive:  example.docx
inflating: [Content_Types].xml
inflating: _rels/.rels
inflating: word/_rels/document.xml.rels
inflating: word/document.xml
inflating: word/theme/theme1.xml
extracting: docProps/thumbnail.jpeg
inflating: word/comments.xml
inflating: word/settings.xml
inflating: word/fontTable.xml
inflating: word/styles.xml
inflating: word/stylesWithEffects.xml
inflating: docProps/app.xml
inflating: docProps/core.xml
inflating: word/webSettings.xml
inflating: word/numbering.xml
$ tree
.
├── [Content_Types].xml
├── _rels
├── docProps
│   ├── app.xml
│   ├── core.xml
│   └── thumbnail.jpeg
└── word
├── _rels
│   └── document.xml.rels
├── comments.xml
├── document.xml
├── fontTable.xml
├── numbering.xml
├── settings.xml
├── styles.xml
├── stylesWithEffects.xml
├── theme
│   └── theme1.xml
└── webSettings.xml
```
Comme vous pouvez le voir, une partie de la structure est créée par la hiérarchie des fichiers et des dossiers. Le reste est spécifié à l'intérieur des fichiers XML. [_New Steganographic Techniques for the OOXML File Format_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d) détaille certaines idées pour les techniques de dissimulation de données, mais les auteurs de défis CTF seront toujours en train de trouver de nouvelles.

Encore une fois, un ensemble d'outils Python existe pour l'examen et **l'analyse des documents OLE et OOXML** : [oletools](http://www.decalage.info/python/oletools). Pour les documents OOXML en particulier, [OfficeDissector](https://www.officedissector.com) est un cadre d'analyse très puissant (et une bibliothèque Python). Ce dernier comprend un [guide rapide de son utilisation](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt).

Parfois, le défi n'est pas de trouver des données statiques cachées, mais d'**analyser une macro VBA** pour déterminer son comportement. C'est un scénario plus réaliste et une tâche que les analystes sur le terrain effectuent tous les jours. Les outils de dissection mentionnés peuvent indiquer si une macro est présente, et probablement l'extraire pour vous. Une macro VBA typique dans un document Office, sous Windows, téléchargera un script PowerShell dans %TEMP% et tentera de l'exécuter, auquel cas vous avez également une tâche d'analyse de script PowerShell. Mais les macros VBA malveillantes sont rarement compliquées puisque VBA est [généralement juste utilisé comme une plateforme de lancement pour démarrer l'exécution de code](https://www.lastline.com/labsblog/party-like-its-1999-comeback-of-vba-malware-downloaders-part-3/). Dans le cas où vous devez comprendre une macro VBA compliquée, ou si la macro est obfusquée et possède une routine de dépaquetage, vous n'avez pas besoin de posséder une licence pour Microsoft Office pour déboguer cela. Vous pouvez utiliser [Libre Office](http://libreoffice.org) : [son interface](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/) sera familière à quiconque a débogué un programme ; vous pouvez placer des points d'arrêt et créer des variables de surveillance et capturer des valeurs après qu'elles aient été dépaquetées mais avant que le comportement de la charge utile ne se soit exécuté. Vous pouvez même démarrer une macro d'un document spécifique à partir d'une ligne de commande :
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## Exécution Automatique

Les fonctions de macro telles que `AutoOpen`, `AutoExec` ou `Document_Open` seront **exécutées** **automatiquement**.

## Références

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires **les plus avancés**.\
Obtenez l'Accès Aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

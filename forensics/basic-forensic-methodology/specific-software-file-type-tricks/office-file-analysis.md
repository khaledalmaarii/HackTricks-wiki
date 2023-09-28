# Analyse des fichiers Office

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser facilement des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Introduction

Microsoft a créé **des dizaines de formats de fichiers de documents Office**, dont beaucoup sont populaires pour la distribution d'attaques de phishing et de logiciels malveillants en raison de leur capacité à **inclure des macros** (scripts VBA).

De manière générale, il existe deux générations de formats de fichiers Office : les formats **OLE** (extensions de fichiers comme RTF, DOC, XLS, PPT) et les formats "**Office Open XML**" (extensions de fichiers incluant DOCX, XLSX, PPTX). **Les deux** formats sont des formats binaires de fichiers composés et structurés qui permettent d'inclure du contenu lié ou intégré (objets). Les fichiers OOXML sont des conteneurs de fichiers zip, ce qui signifie que l'une des façons les plus simples de vérifier la présence de données cachées est de simplement `dézipper` le document :
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
Comme vous pouvez le voir, une partie de la structure est créée par le fichier et la hiérarchie des dossiers. Le reste est spécifié à l'intérieur des fichiers XML. [_Nouvelles techniques de stéganographie pour le format de fichier OOXML_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d) détaille certaines idées de techniques de dissimulation de données, mais les auteurs de défis CTF en inventeront toujours de nouvelles.

Encore une fois, un ensemble d'outils Python existe pour l'examen et l'analyse des documents OLE et OOXML : [oletools](http://www.decalage.info/python/oletools). Pour les documents OOXML en particulier, [OfficeDissector](https://www.officedissector.com) est un framework d'analyse très puissant (et une bibliothèque Python). Ce dernier comprend un [guide rapide sur son utilisation](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt).

Parfois, le défi n'est pas de trouver des données statiques cachées, mais d'analyser une macro VBA pour déterminer son comportement. Il s'agit d'un scénario plus réaliste et que les analystes sur le terrain effectuent tous les jours. Les outils de disséction mentionnés précédemment peuvent indiquer si une macro est présente et probablement l'extraire pour vous. Une macro VBA typique dans un document Office, sur Windows, téléchargera un script PowerShell vers %TEMP% et tentera de l'exécuter, auquel cas vous aurez maintenant une tâche d'analyse de script PowerShell. Mais les macros VBA malveillantes sont rarement compliquées car VBA est [généralement utilisé comme une plateforme de lancement pour l'exécution de code](https://www.lastline.com/labsblog/party-like-its-1999-comeback-of-vba-malware-downloaders-part-3/). Dans le cas où vous devez comprendre une macro VBA compliquée, ou si la macro est obfusquée et a une routine de déballage, vous n'avez pas besoin de posséder une licence Microsoft Office pour la déboguer. Vous pouvez utiliser [Libre Office](http://libreoffice.org) : [son interface](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/) sera familière à toute personne ayant déjà débogué un programme ; vous pouvez définir des points d'arrêt, créer des variables de surveillance et capturer des valeurs après qu'elles aient été déballées mais avant que le comportement de la charge utile ne s'exécute. Vous pouvez même démarrer une macro d'un document spécifique à partir d'une ligne de commande :
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)

Les **oletools** sont un ensemble d'outils pour analyser les fichiers Office (Word, Excel, PowerPoint) et autres formats de fichiers basés sur OLE. Ces outils peuvent être utilisés pour effectuer des analyses forensiques sur des fichiers Office afin de détecter des macros malveillantes, des liens externes suspects, des objets intégrés, des fichiers cachés et d'autres indicateurs de compromission.

Les **oletools** comprennent plusieurs outils tels que :

- **olebrowse** : un outil pour parcourir la structure interne des fichiers OLE et examiner les objets intégrés.
- **oleid** : un outil pour identifier les fichiers OLE et déterminer les versions des applications Office utilisées pour les créer.
- **olevba** : un outil pour extraire et analyser les macros VBA à partir de fichiers Office.
- **rtfobj** : un outil pour extraire et analyser les objets OLE incorporés dans les fichiers RTF.
- **olemap** : un outil pour cartographier les objets OLE dans un fichier et générer un rapport détaillé.

Les **oletools** sont très utiles pour les analystes de sécurité, les chercheurs en sécurité et les professionnels de la sécurité informatique qui souhaitent analyser les fichiers Office et détecter les menaces potentielles. Ils peuvent également être utilisés dans le cadre de tests de pénétration pour identifier les vulnérabilités et les failles de sécurité dans les fichiers Office.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## Exécution automatique

Les fonctions macro telles que `AutoOpen`, `AutoExec` ou `Document_Open` seront **automatiquement exécutées**.

## Références

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser facilement des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

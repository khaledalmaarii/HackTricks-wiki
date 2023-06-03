# Analyse de fichiers Office

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

## Introduction

Microsoft a créé **des dizaines de formats de fichiers de documents Office**, dont beaucoup sont populaires pour la distribution d'attaques de phishing et de logiciels malveillants en raison de leur capacité à **inclure des macros** (scripts VBA).

De manière générale, il existe deux générations de formats de fichiers Office : les **formats OLE** (extensions de fichier telles que RTF, DOC, XLS, PPT) et les formats "**Office Open XML**" (extensions de fichier qui incluent DOCX, XLSX, PPTX). **Les deux** formats sont des formats binaires de fichiers composés et structurés qui **permettent le contenu lié ou intégré** (objets). Les fichiers OOXML sont des conteneurs de fichiers zip, ce qui signifie que l'un des moyens les plus simples de vérifier la présence de données cachées est simplement de `dézipper` le document :
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
Comme vous pouvez le constater, une partie de la structure est créée par la hiérarchie des fichiers et des dossiers. Le reste est spécifié à l'intérieur des fichiers XML. [_New Steganographic Techniques for the OOXML File Format_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d) détaille certaines idées pour les techniques de dissimulation de données, mais les auteurs de défis CTF en inventeront toujours de nouvelles.

Encore une fois, un ensemble d'outils Python existe pour l'examen et l'analyse des documents OLE et OOXML: [oletools](http://www.decalage.info/python/oletools). Pour les documents OOXML en particulier, [OfficeDissector](https://www.officedissector.com) est un cadre d'analyse très puissant (et une bibliothèque Python). Ce dernier inclut un [guide rapide sur son utilisation](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt).

Parfois, le défi n'est pas de trouver des données statiques cachées, mais d'analyser une macro VBA pour déterminer son comportement. C'est un scénario plus réaliste et que les analystes sur le terrain effectuent tous les jours. Les outils de dissémination mentionnés ci-dessus peuvent indiquer si une macro est présente et probablement l'extraire pour vous. Une macro VBA typique dans un document Office, sur Windows, téléchargera un script PowerShell vers %TEMP% et tentera de l'exécuter, auquel cas vous avez maintenant une tâche d'analyse de script PowerShell. Mais les macros VBA malveillantes sont rarement compliquées car VBA est [généralement utilisé comme une plate-forme de lancement pour l'exécution de code](https://www.lastline.com/labsblog/party-like-its-1999-comeback-of-vba-malware-downloaders-part-3/). Dans le cas où vous devez comprendre une macro VBA compliquée, ou si la macro est obfusquée et a une routine de déballage, vous n'avez pas besoin de posséder une licence Microsoft Office pour déboguer cela. Vous pouvez utiliser [Libre Office](http://libreoffice.org): [son interface](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/) sera familière à quiconque a débogué un programme; vous pouvez définir des points d'arrêt et créer des variables de surveillance et capturer des valeurs après qu'elles ont été déballées mais avant que le comportement de la charge utile ne soit exécuté. Vous pouvez même démarrer une macro d'un document spécifique à partir d'une ligne de commande:
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)

Les `oletools` sont un ensemble d'outils pour analyser les fichiers OLE (Object Linking and Embedding), tels que les fichiers Microsoft Office. Ces outils peuvent être utilisés pour extraire des informations à partir de fichiers Office, telles que les macros, les objets intégrés, les scripts VBA, etc. Les outils `oletools` peuvent également être utilisés pour détecter les fichiers Office malveillants et les exploiter.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## Exécution automatique

Les fonctions de macro comme `AutoOpen`, `AutoExec` ou `Document_Open` seront **automatiquement** **exécutées**.

## Références

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

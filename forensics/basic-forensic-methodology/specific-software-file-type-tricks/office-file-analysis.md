# Análise de arquivos do Office

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente com as **ferramentas comunitárias mais avançadas do mundo**.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Introdução

A Microsoft criou **dezenas de formatos de arquivos de documentos do Office**, muitos dos quais são populares para a distribuição de ataques de phishing e malware devido à sua capacidade de **incluir macros** (scripts VBA).

De maneira geral, existem duas gerações de formatos de arquivos do Office: os **formatos OLE** (extensões de arquivo como RTF, DOC, XLS, PPT) e os formatos "**Office Open XML**" (extensões de arquivo que incluem DOCX, XLSX, PPTX). **Ambos** os formatos são estruturados, formatos de arquivo binário composto que **permitem conteúdo vinculado ou incorporado** (Objetos). Os arquivos OOXML são contêineres de arquivos zip, o que significa que uma das maneiras mais fáceis de verificar dados ocultos é simplesmente `descompactar` o documento:
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
Como pode ver, parte da estrutura é criada pelo arquivo e pela hierarquia de pastas. O restante é especificado dentro dos arquivos XML. [_Novas Técnicas Esteganográficas para o Formato de Arquivo OOXML_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d) detalha algumas ideias para técnicas de ocultação de dados, mas os autores de desafios CTF sempre estarão criando novas.

Mais uma vez, existe um conjunto de ferramentas em Python para a **exame e análise de documentos OLE e OOXML**: [oletools](http://www.decalage.info/python/oletools). Para documentos OOXML em particular, [OfficeDissector](https://www.officedissector.com) é um framework de análise muito poderoso (e uma biblioteca Python). Este último inclui um [guia rápido para seu uso](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt).

Às vezes, o desafio não é encontrar dados estáticos ocultos, mas **analisar uma macro VBA** para determinar seu comportamento. Este é um cenário mais realista e algo que os analistas de campo realizam todos os dias. As ferramentas de dissector mencionadas podem indicar se uma macro está presente e provavelmente extraí-la para você. Uma macro VBA típica em um documento do Office, no Windows, irá baixar um script do PowerShell para %TEMP% e tentar executá-lo, caso em que você agora tem uma tarefa de análise de script do PowerShell também. Mas as macros VBA maliciosas raramente são complicadas, já que o VBA é [tipicamente usado apenas como uma plataforma de lançamento para a execução de código](https://www.lastline.com/labsblog/party-like-its-1999-comeback-of-vba-malware-downloaders-part-3/). No caso de precisar entender uma macro VBA complicada, ou se a macro estiver ofuscada e tiver um rotina de descompactação, você não precisa ter uma licença do Microsoft Office para depurar isso. Você pode usar o [Libre Office](http://libreoffice.org): [sua interface](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/) será familiar para quem já depurou um programa; você pode definir pontos de interrupção, criar variáveis de observação e capturar valores depois que eles foram descompactados, mas antes que o comportamento do payload tenha sido executado. Você até pode iniciar uma macro de um documento específico a partir de uma linha de comando:
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## Execução Automática

Funções de macro como `AutoOpen`, `AutoExec` ou `Document_Open` serão **executadas automaticamente**.

## Referências

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou nos siga no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# Análise de arquivo Office

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente, com ferramentas da comunidade **mais avançadas**.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Introdução

A Microsoft criou **dezenas de formatos de arquivo de documento Office**, muitos dos quais são populares para a distribuição de ataques de phishing e malware devido à sua capacidade de **incluir macros** (scripts VBA).

Falando de forma ampla, existem duas gerações de formato de arquivo Office: os formatos **OLE** (extensões de arquivo como RTF, DOC, XLS, PPT), e os formatos "**Office Open XML**" (extensões de arquivo que incluem DOCX, XLSX, PPTX). **Ambos** os formatos são estruturados, formatos binários de arquivo composto que **permitem conteúdo Vinculado ou Embutido** (Objetos). Arquivos OOXML são contêineres de arquivo zip, o que significa que uma das maneiras mais fáceis de verificar dados ocultos é simplesmente `unzip` o documento:
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
Como você pode ver, parte da estrutura é criada pela hierarquia de arquivos e pastas. O restante é especificado dentro dos arquivos XML. [_Novas Técnicas Esteganográficas para o Formato de Arquivo OOXML_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d) detalha algumas ideias para técnicas de ocultação de dados, mas os autores de desafios de CTF estarão sempre inventando novas.

Mais uma vez, existe um conjunto de ferramentas Python para a **análise de documentos OLE e OOXML**: [oletools](http://www.decalage.info/python/oletools). Especificamente para documentos OOXML, [OfficeDissector](https://www.officedissector.com) é um framework de análise muito poderoso (e biblioteca Python). Este último inclui um [guia rápido para seu uso](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt).

Às vezes, o desafio não é encontrar dados estáticos ocultos, mas **analisar uma macro VBA** para determinar seu comportamento. Este é um cenário mais realista e uma tarefa que analistas de campo realizam todos os dias. As ferramentas de dissecação mencionadas podem indicar se uma macro está presente e, provavelmente, extraí-la para você. Uma macro VBA típica em um documento Office, no Windows, baixará um script PowerShell para %TEMP% e tentará executá-lo, caso em que você também terá uma tarefa de análise de script PowerShell. Mas macros VBA maliciosas raramente são complicadas, já que VBA é [tipicamente usado apenas como uma plataforma de lançamento para iniciar a execução de código](https://www.lastline.com/labsblog/party-like-its-1999-comeback-of-vba-malware-downloaders-part-3/). No caso de você precisar entender uma macro VBA complicada, ou se a macro estiver ofuscada e tiver uma rotina de desempacotamento, você não precisa ter uma licença do Microsoft Office para depurar isso. Você pode usar [Libre Office](http://libreoffice.org): [sua interface](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/) será familiar para qualquer um que já tenha depurado um programa; você pode definir pontos de interrupção e criar variáveis de observação e capturar valores depois que eles foram desempacotados, mas antes que qualquer comportamento da carga útil tenha sido executado. Você pode até iniciar uma macro de um documento específico a partir de uma linha de comando:
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## Execução Automática

Funções de macro como `AutoOpen`, `AutoExec` ou `Document_Open` serão **executadas** **automaticamente**.

## Referências

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e **automatizar fluxos de trabalho** com facilidade, utilizando as ferramentas comunitárias **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda AWS hacking do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo do** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo do [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

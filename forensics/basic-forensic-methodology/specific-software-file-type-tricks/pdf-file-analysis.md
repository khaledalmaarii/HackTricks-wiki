# Análise de Arquivo PDF

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Obtenha o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** repositórios [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente com as **ferramentas comunitárias mais avançadas do mundo**.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

De: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

O PDF é um formato de arquivo de documento extremamente complicado, com truques e lugares ocultos suficientes [para escrever sobre por anos](https://www.sultanik.com/pocorgtfo/). Isso também o torna popular para desafios de forense CTF. A NSA escreveu um guia sobre esses lugares ocultos em 2008 intitulado "Hidden Data and Metadata in Adobe PDF Files: Publication Risks and Countermeasures." Não está mais disponível em seu URL original, mas você pode [encontrar uma cópia aqui](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf). Ange Albertini também mantém um wiki no GitHub com [truques de formato de arquivo PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md).

O formato PDF é parcialmente texto simples, como HTML, mas com muitos "objetos" binários no conteúdo. Didier Stevens escreveu [bom material introdutório](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) sobre o formato. Os objetos binários podem ser dados comprimidos ou até mesmo criptografados, e incluem conteúdo em linguagens de script como JavaScript ou Flash. Para exibir a estrutura de um PDF, você pode navegá-lo com um editor de texto ou abri-lo com um editor de formato de arquivo PDF.

[qpdf](https://github.com/qpdf/qpdf) é uma ferramenta que pode ser útil para explorar um PDF e transformar ou extrair informações dele. Outra é um framework em Ruby chamado [Origami](https://github.com/mobmewireless/origami-pdf).

Ao explorar o conteúdo de um PDF em busca de dados ocultos, alguns dos lugares ocultos para verificar incluem:

* camadas não visíveis
* o formato de metadados da Adobe "XMP"
* o recurso de "geração incremental" do PDF, em que uma versão anterior é retida, mas não é visível para o usuário
* texto branco em um fundo branco
* texto atrás de imagens
* uma imagem atrás de uma imagem sobreposta
* comentários não exibidos

Existem também vários pacotes Python para trabalhar com o formato de arquivo PDF, como o [PeepDF](https://github.com/jesparza/peepdf), que permitem que você escreva seus próprios scripts de análise. 

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Obtenha o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** repositórios [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

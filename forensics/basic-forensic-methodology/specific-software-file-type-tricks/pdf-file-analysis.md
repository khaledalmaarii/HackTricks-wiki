# Análise de Arquivos PDF

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

De: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

PDF é um formato de arquivo de documento extremamente complicado, com truques e esconderijos suficientes [para escrever sobre por anos](https://www.sultanik.com/pocorgtfo/). Isso também o torna popular para desafios de forense em CTF. A NSA escreveu um guia sobre esses esconderijos em 2008 intitulado "Dados Ocultos e Metadados em Arquivos Adobe PDF: Riscos de Publicação e Contramedidas". Não está mais disponível em seu URL original, mas você pode [encontrar uma cópia aqui](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf). Ange Albertini também mantém um wiki no GitHub sobre [truques do formato de arquivo PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md).

O formato PDF é parcialmente em texto simples, como HTML, mas com muitos "objetos" binários no conteúdo. Didier Stevens escreveu [material introdutório bom](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) sobre o formato. Os objetos binários podem ser dados comprimidos ou até mesmo criptografados, e incluem conteúdo em linguagens de script como JavaScript ou Flash. Para exibir a estrutura de um PDF, você pode navegar nele com um editor de texto ou abri-lo com um editor de formato de arquivo ciente de PDF, como Origami.

[qpdf](https://github.com/qpdf/qpdf) é uma ferramenta que pode ser útil para explorar um PDF e transformar ou extrair informações dele. Outra é um framework em Ruby chamado [Origami](https://github.com/mobmewireless/origami-pdf).

Ao explorar o conteúdo de PDF em busca de dados ocultos, alguns dos esconderijos para verificar incluem:

* camadas não visíveis
* formato de metadados da Adobe "XMP"
* o recurso de "geração incremental" do PDF, no qual uma versão anterior é retida, mas não visível para o usuário
* texto branco em fundo branco
* texto atrás de imagens
* uma imagem atrás de outra imagem sobreposta
* comentários não exibidos

Existem também vários pacotes Python para trabalhar com o formato de arquivo PDF, como [PeepDF](https://github.com/jesparza/peepdf), que permitem escrever seus próprios scripts de análise.

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

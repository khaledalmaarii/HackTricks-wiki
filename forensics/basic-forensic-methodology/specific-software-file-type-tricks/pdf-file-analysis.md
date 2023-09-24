# Análise de Arquivos PDF

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo Telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

De: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

O formato de arquivo PDF é extremamente complicado, com truques e esconderijos suficientes [para escrever sobre por anos](https://www.sultanik.com/pocorgtfo/). Isso também o torna popular para desafios de forense em CTF. A NSA escreveu um guia sobre esses esconderijos em 2008 intitulado "Hidden Data and Metadata in Adobe PDF Files: Publication Risks and Countermeasures". Não está mais disponível em sua URL original, mas você pode [encontrar uma cópia aqui](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf). Ange Albertini também mantém um wiki no GitHub com [truques de formato de arquivo PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md).

O formato PDF é parcialmente texto simples, como HTML, mas com muitos "objetos" binários no conteúdo. Didier Stevens escreveu [bom material introdutório](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) sobre o formato. Os objetos binários podem ser dados comprimidos ou até mesmo criptografados, e incluem conteúdo em linguagens de script como JavaScript ou Flash. Para exibir a estrutura de um PDF, você pode navegá-lo com um editor de texto ou abri-lo com um editor de formato de arquivo PDF como o Origami.

[qpdf](https://github.com/qpdf/qpdf) é uma ferramenta que pode ser útil para explorar um PDF e transformar ou extrair informações dele. Outra é um framework em Ruby chamado [Origami](https://github.com/mobmewireless/origami-pdf).

Ao explorar o conteúdo de um PDF em busca de dados ocultos, alguns dos esconderijos a serem verificados incluem:

* camadas não visíveis
* o formato de metadados "XMP" da Adobe
* o recurso de "geração incremental" do PDF, em que uma versão anterior é retida, mas não visível para o usuário
* texto branco em um fundo branco
* texto atrás de imagens
* uma imagem atrás de uma imagem sobreposta
* comentários não exibidos

Existem também vários pacotes Python para trabalhar com o formato de arquivo PDF, como o [PeepDF](https://github.com/jesparza/peepdf), que permite que você escreva seus próprios scripts de análise.

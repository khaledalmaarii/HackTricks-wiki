# Análise de arquivos de escritório

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis) para construir e **automatizar fluxos de trabalho** facilmente com as **ferramentas comunitárias mais avançadas do mundo**.\
Tenha acesso hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

Para mais informações, acesse [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Este é apenas um resumo:

A Microsoft criou muitos formatos de documentos de escritório, com dois tipos principais sendo os formatos **OLE** (como RTF, DOC, XLS, PPT) e os formatos **Office Open XML (OOXML)** (como DOCX, XLSX, PPTX). Esses formatos podem incluir macros, tornando-os alvos para phishing e malware. Arquivos OOXML são estruturados como contêineres zip, permitindo inspeção por meio de descompactação, revelando o arquivo e a hierarquia de pastas e conteúdos de arquivos XML.

Para explorar as estruturas de arquivos OOXML, é fornecido o comando para descompactar um documento e a estrutura de saída. Técnicas para ocultar dados nesses arquivos foram documentadas, indicando inovação contínua na ocultação de dados nos desafios CTF.

Para análise, **oletools** e **OfficeDissector** oferecem conjuntos abrangentes de ferramentas para examinar documentos OLE e OOXML. Essas ferramentas ajudam na identificação e análise de macros incorporadas, que frequentemente servem como vetores para entrega de malware, geralmente baixando e executando cargas maliciosas adicionais. A análise de macros VBA pode ser realizada sem o Microsoft Office utilizando o Libre Office, que permite a depuração com pontos de interrupção e variáveis de observação.

A instalação e o uso do **oletools** são diretos, com comandos fornecidos para instalação via pip e extração de macros de documentos. A execução automática de macros é acionada por funções como `AutoOpen`, `AutoExec` ou `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis) para construir e **automatizar fluxos de trabalho** facilmente com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

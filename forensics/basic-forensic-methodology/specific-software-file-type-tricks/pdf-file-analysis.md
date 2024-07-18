# Análise de Arquivos PDF

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas** comunitárias **mais avançadas** do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

**Para mais detalhes, confira:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

O formato PDF é conhecido por sua complexidade e potencial para ocultar dados, tornando-se um ponto focal para desafios de forense em CTF. Ele combina elementos de texto simples com objetos binários, que podem estar comprimidos ou criptografados, e pode incluir scripts em linguagens como JavaScript ou Flash. Para entender a estrutura do PDF, pode-se consultar o [material introdutório de Didier Stevens](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/), ou usar ferramentas como um editor de texto ou um editor específico de PDF, como o Origami.

Para exploração ou manipulação aprofundada de PDFs, ferramentas como [qpdf](https://github.com/qpdf/qpdf) e [Origami](https://github.com/mobmewireless/origami-pdf) estão disponíveis. Dados ocultos dentro de PDFs podem estar escondidos em:

* Camadas invisíveis
* Formato de metadados XMP da Adobe
* Gerações incrementais
* Texto com a mesma cor do fundo
* Texto atrás de imagens ou imagens sobrepostas
* Comentários não exibidos

Para análise personalizada de PDF, bibliotecas Python como [PeepDF](https://github.com/jesparza/peepdf) podem ser usadas para criar scripts de parsing sob medida. Além disso, o potencial do PDF para armazenamento de dados ocultos é tão vasto que recursos como o guia da NSA sobre riscos e contramedidas de PDF, embora não esteja mais hospedado em sua localização original, ainda oferecem insights valiosos. Uma [cópia do guia](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) e uma coleção de [truques de formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) de Ange Albertini podem fornecer mais leitura sobre o assunto.

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

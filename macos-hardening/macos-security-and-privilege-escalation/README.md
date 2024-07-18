# Segurança e Escalação de Privilégios no macOS

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Junte-se ao servidor [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para se comunicar com hackers experientes e caçadores de bugs!

**Visão sobre Hacking**\
Engaje-se com conteúdo que explora a emoção e desafios do hacking

**Notícias de Hacking em Tempo Real**\
Mantenha-se atualizado com o mundo acelerado do hacking através de notícias e insights em tempo real

**Últimos Anúncios**\
Fique informado sobre os novos programas de recompensas por bugs lançados e atualizações cruciais nas plataformas

**Junte-se a nós no** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e comece a colaborar com os melhores hackers hoje!

## MacOS Básico

Se você não está familiarizado com o macOS, você deve começar aprendendo o básico do macOS:

* Arquivos e permissões especiais do macOS:

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Usuários comuns do macOS

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* A **arquitetura** do **kernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Serviços e protocolos de rede comuns do macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* macOS **Open Source**: [https://opensource.apple.com/](https://opensource.apple.com/)
* Para baixar um `tar.gz`, altere uma URL como [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) para [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM no macOS

Nas empresas, os sistemas macOS são altamente prováveis de serem **gerenciados com um MDM**. Portanto, do ponto de vista de um atacante, é interessante saber **como isso funciona**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### macOS - Inspeção, Debugging e Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Proteções de Segurança do macOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Superfície de Ataque

### Permissões de Arquivo

Se um **processo em execução como root escreve** um arquivo que pode ser controlado por um usuário, o usuário poderia abusar disso para **escalar privilégios**.\
Isso poderia ocorrer nas seguintes situações:

* Arquivo usado já foi criado por um usuário (propriedade do usuário)
* Arquivo usado é gravável pelo usuário por causa de um grupo
* Arquivo usado está dentro de um diretório de propriedade do usuário (o usuário poderia criar o arquivo)
* Arquivo usado está dentro de um diretório de propriedade do root, mas o usuário tem acesso de escrita sobre ele por causa de um grupo (o usuário poderia criar o arquivo)

Ser capaz de **criar um arquivo** que será **usado por root**, permite a um usuário **aproveitar seu conteúdo** ou até mesmo criar **symlinks/hardlinks** para apontá-lo para outro lugar.

Para esse tipo de vulnerabilidades, não se esqueça de **verificar instaladores `.pkg` vulneráveis**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Extensão de Arquivo e Manipuladores de Aplicativos de Esquema de URL

Aplicativos estranhos registrados por extensões de arquivo podem ser abusados e diferentes aplicativos podem ser registrados para abrir protocolos específicos

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Escalação de Privilégios TCC / SIP no macOS

No macOS, **aplicativos e binários podem ter permissões** para acessar pastas ou configurações que os tornam mais privilegiados do que outros.

Portanto, um atacante que deseja comprometer com sucesso uma máquina macOS precisará **escalar seus privilégios TCC** (ou até mesmo **burlar o SIP**, dependendo de suas necessidades).

Esses privilégios geralmente são concedidos na forma de **entitlements** com os quais o aplicativo é assinado, ou o aplicativo pode solicitar alguns acessos e após o **usuário aprová-los** eles podem ser encontrados nos **bancos de dados TCC**. Outra maneira de um processo obter esses privilégios é sendo um **filho de um processo** com esses **privilégios**, pois eles geralmente são **herdados**.

Siga estes links para encontrar diferentes maneiras de [**escalar privilégios no TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), para [**burlar o TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) e como no passado [**o SIP foi burlado**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalação de Privilégios Tradicional no macOS

Claro, do ponto de vista de equipes de red team, você também deve estar interessado em escalar para root. Confira o seguinte post para algumas dicas:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Referências

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Junte-se ao servidor [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para se comunicar com hackers experientes e caçadores de bugs!

**Percepções de Hacking**\
Engaje-se com conteúdo que explora a emoção e os desafios do hacking

**Notícias de Hacking em Tempo Real**\
Mantenha-se atualizado com o mundo acelerado do hacking através de notícias e insights em tempo real

**Últimos Anúncios**\
Fique informado sobre os mais recentes programas de recompensas por bugs lançados e atualizações cruciais na plataforma

**Junte-se a nós no** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e comece a colaborar com os melhores hackers hoje!

{% hint style="success" %}
Aprenda e pratique Hacking na AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking no GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

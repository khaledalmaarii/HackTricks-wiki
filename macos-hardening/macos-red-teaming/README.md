# macOS Red Teaming

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Abusando de MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Se você conseguir **comprometer credenciais de administrador** para acessar a plataforma de gerenciamento, você pode **potencialmente comprometer todos os computadores** distribuindo seu malware nas máquinas.

Para red teaming em ambientes MacOS, é altamente recomendável ter algum entendimento de como os MDMs funcionam:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Usando MDM como um C2

Um MDM terá permissão para instalar, consultar ou remover perfis, instalar aplicativos, criar contas de administrador locais, definir senha de firmware, alterar a chave FileVault...

Para executar seu próprio MDM, você precisa **ter seu CSR assinado por um fornecedor**, o que você poderia tentar obter com [**https://mdmcert.download/**](https://mdmcert.download/). E para executar seu próprio MDM para dispositivos Apple, você poderia usar [**MicroMDM**](https://github.com/micromdm/micromdm).

No entanto, para instalar um aplicativo em um dispositivo inscrito, ainda é necessário que ele seja assinado por uma conta de desenvolvedor... no entanto, após a inscrição no MDM, o **dispositivo adiciona o certificado SSL do MDM como uma CA confiável**, então agora você pode assinar qualquer coisa.

Para inscrever o dispositivo em um MDM, você precisa instalar um arquivo **`mobileconfig`** como root, que pode ser entregue via um arquivo **pkg** (você poderia comprimi-lo em zip e quando baixado pelo safari ele será descomprimido).

**O agente Mythic Orthrus** usa essa técnica.

### Abusando do JAMF PRO

O JAMF pode executar **scripts personalizados** (scripts desenvolvidos pelo sysadmin), **payloads nativos** (criação de conta local, definição de senha EFI, monitoramento de arquivo/processo...) e **MDM** (configurações do dispositivo, certificados do dispositivo...).

#### Autoinscrição no JAMF

Vá para uma página como `https://<nome-da-empresa>.jamfcloud.com/enroll/` para ver se eles têm **autoinscrição habilitada**. Se tiverem, pode **pedir credenciais para acesso**.

Você poderia usar o script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) para realizar um ataque de password spraying.

Além disso, após encontrar credenciais adequadas, você poderia ser capaz de forçar bruta outros nomes de usuário com o seguinte formulário:

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### Autenticação de dispositivo JAMF

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

O binário **`jamf`** continha o segredo para abrir o keychain que, no momento da descoberta, era **compartilhado** entre todos e era: **`jk23ucnq91jfu9aj`**.\
Além disso, o jamf **persiste** como um **LaunchDaemon** em **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Tomada de Controle de Dispositivo JAMF

A **URL** do **JSS** (Jamf Software Server) que o **`jamf`** usará está localizada em **`/Library/Preferences/com.jamfsoftware.jamf.plist`**. \
Esse arquivo basicamente contém a URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Assim, um atacante poderia inserir um pacote malicioso (`pkg`) que **sobrescreve este arquivo** quando instalado, configurando a **URL para um ouvinte Mythic C2 de um agente Typhon** para agora poder abusar do JAMF como C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Impersonação JAMF

Para **impersonar a comunicação** entre um dispositivo e JMF, você precisa:

* O **UUID** do dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* O **keychain JAMF** de: `/Library/Application\ Support/Jamf/JAMF.keychain` que contém o certificado do dispositivo

Com essa informação, **crie uma VM** com o **UUID** do Hardware **roubado** e com **SIP desativado**, insira o **keychain JAMF,** **intercepte** o agente Jamf e roube suas informações.

#### Roubo de segredos

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

Você também pode monitorar o local `/Library/Application Support/Jamf/tmp/` para os **scripts personalizados** que os administradores podem querer executar via Jamf, pois são **colocados aqui, executados e removidos**. Esses scripts **podem conter credenciais**.

No entanto, **credenciais** podem ser passadas para esses scripts como **parâmetros**, então você precisaria monitorar `ps aux | grep -i jamf` (sem mesmo ser root).

O script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) pode escutar por novos arquivos sendo adicionados e novos argumentos de processos.

### Acesso Remoto no macOS

E também sobre os **protocolos de rede** "especiais" do **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Em algumas ocasiões, você descobrirá que o **computador MacOS está conectado a um AD**. Neste cenário, você deve tentar **enumerar** o active directory como está acostumado. Encontre **ajuda** nas seguintes páginas:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Uma **ferramenta local do MacOS** que também pode ajudá-lo é `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Também existem algumas ferramentas preparadas para o MacOS para enumerar automaticamente o AD e interagir com o kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound é uma extensão da ferramenta de auditoria Bloodhound que permite coletar e ingerir relações do Active Directory em hosts MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost é um projeto em Objective-C projetado para interagir com as APIs krb5 do Heimdal no macOS. O objetivo do projeto é possibilitar testes de segurança aprimorados em torno do Kerberos em dispositivos macOS usando APIs nativas, sem a necessidade de qualquer outro framework ou pacotes no alvo.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Ferramenta JavaScript for Automation (JXA) para fazer enumeração do Active Directory.

### Informações do Domínio
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Usuários

Os três tipos de usuários MacOS são:

* **Usuários Locais** — Gerenciados pelo serviço local OpenDirectory, eles não estão conectados de forma alguma ao Active Directory.
* **Usuários de Rede** — Usuários voláteis do Active Directory que requerem uma conexão com o servidor DC para autenticação.
* **Usuários Móveis** — Usuários do Active Directory com um backup local para suas credenciais e arquivos.

As informações locais sobre usuários e grupos são armazenadas na pasta _/var/db/dslocal/nodes/Default._\
Por exemplo, as informações sobre o usuário chamado _mark_ estão armazenadas em _/var/db/dslocal/nodes/Default/users/mark.plist_ e as informações sobre o grupo _admin_ estão em _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Além de usar as arestas HasSession e AdminTo, **MacHound adiciona três novas arestas** ao banco de dados Bloodhound:

* **CanSSH** - entidade permitida para SSH ao host
* **CanVNC** - entidade permitida para VNC ao host
* **CanAE** - entidade permitida para executar scripts AppleEvent no host
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Mais informações em [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## Acessando o Keychain

O Keychain provavelmente contém informações sensíveis que, se acessadas sem gerar um aviso, podem ajudar a avançar um exercício de red team:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Serviços Externos

O Red Teaming no MacOS é diferente do Red Teaming regular no Windows, pois geralmente **o MacOS é integrado diretamente com várias plataformas externas**. Uma configuração comum do MacOS é acessar o computador usando **credenciais sincronizadas do OneLogin e acessar vários serviços externos** (como github, aws...) via OneLogin:

![](<../../.gitbook/assets/image (563).png>)

## Técnicas Diversas de Red Team

### Safari

Quando um arquivo é baixado no Safari, se for um arquivo "seguro", ele será **aberto automaticamente**. Então, por exemplo, se você **baixar um zip**, ele será automaticamente descomprimido:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## Referências

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Venha para o Lado Negro, Temos Maçãs: Tornando o Gerenciamento do macOS Maléfico**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "Uma Perspectiva do Atacante sobre Configurações do Jamf" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

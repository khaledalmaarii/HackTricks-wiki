# Red Team no macOS

<details>

<summary><strong>Aprenda a hackear a AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Abusando de MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Se você conseguir **comprometer as credenciais de administrador** para acessar a plataforma de gerenciamento, você pode **potencialmente comprometer todos os computadores** distribuindo seu malware nas máquinas.

Para red teaming em ambientes MacOS, é altamente recomendado ter um entendimento de como os MDMs funcionam:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Usando MDM como C2

Um MDM terá permissão para instalar, consultar ou remover perfis, instalar aplicativos, criar contas de administrador locais, definir senha de firmware, alterar a chave do FileVault...

Para executar seu próprio MDM, você precisa **do seu CSR assinado por um fornecedor**, que você poderia tentar obter em [**https://mdmcert.download/**](https://mdmcert.download/). E para executar seu próprio MDM para dispositivos Apple, você poderia usar [**MicroMDM**](https://github.com/micromdm/micromdm).

No entanto, para instalar um aplicativo em um dispositivo inscrito, você ainda precisa que ele seja assinado por uma conta de desenvolvedor... no entanto, após a inscrição no MDM, o **dispositivo adiciona o certificado SSL do MDM como uma CA confiável**, então agora você pode assinar qualquer coisa.

Para inscrever o dispositivo em um MDM, você precisa instalar um arquivo **`mobileconfig`** como root, que poderia ser entregue via um arquivo **pkg** (você poderia compactá-lo em zip e quando baixado do safari ele será descompactado).

O **agente Mythic Orthrus** usa essa técnica.

### Abusando do JAMF PRO

O JAMF pode executar **scripts personalizados** (scripts desenvolvidos pelo sysadmin), **cargas nativas** (criação de contas locais, definir senha EFI, monitoramento de arquivo/processo...) e **MDM** (configurações de dispositivo, certificados de dispositivo...).

#### Autoinscrição do JAMF

Acesse uma página como `https://<nome-da-empresa>.jamfcloud.com/enroll/` para ver se eles têm a **autoinscrição ativada**. Se tiver, pode **solicitar credenciais para acessar**.

Você poderia usar o script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) para realizar um ataque de pulverização de senha.

Além disso, após encontrar as credenciais adequadas, você pode ser capaz de fazer força bruta em outros nomes de usuário com o próximo formulário:

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### Autenticação de Dispositivo JAMF

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

O binário **`jamf`** continha o segredo para abrir o keychain que, na época da descoberta, era **compartilhado** entre todos e era: **`jk23ucnq91jfu9aj`**.\
Além disso, o jamf **persiste** como um **LaunchDaemon** em **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Tomada de Controle de Dispositivo JAMF

A **URL do JSS** (Jamf Software Server) que o **`jamf`** usará está localizada em **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Este arquivo basicamente contém a URL:

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
Portanto, um atacante poderia inserir um pacote malicioso (`pkg`) que **sobrescreve este arquivo** ao ser instalado, configurando o **URL para um ouvinte Mythic C2 de um agente Typhon** para agora poder abusar do JAMF como C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Impersonação do JAMF

Para **impersonar a comunicação** entre um dispositivo e o JMF você precisa:

* O **UUID** do dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* O **keychain do JAMF** em: `/Library/Application\ Support/Jamf/JAMF.keychain` que contém o certificado do dispositivo

Com essas informações, **crie uma VM** com o **UUID de Hardware roubado** e com o **SIP desativado**, deixe cair o **keychain do JAMF**, **intercepte** o **agente do Jamf** e roube suas informações.

#### Roubo de Segredos

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

Você também pode monitorar o local `/Library/Application Support/Jamf/tmp/` para os **scripts personalizados** que os administradores podem querer executar via Jamf, pois eles são **colocados aqui, executados e removidos**. Esses scripts **podem conter credenciais**.

No entanto, as **credenciais** podem ser passadas para esses scripts como **parâmetros**, então você precisaria monitorar `ps aux | grep -i jamf` (sem nem mesmo ser root).

O script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) pode ouvir novos arquivos sendo adicionados e novos argumentos de processo.

### Acesso Remoto ao macOS

E também sobre os **protocolos de rede** "especiais" do **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Em algumas ocasiões, você descobrirá que o **computador MacOS está conectado a um AD**. Nesse cenário, você deve tentar **enumerar** o active directory como está acostumado. Encontre alguma **ajuda** nas seguintes páginas:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Alguma **ferramenta local do MacOS** que também pode ajudá-lo é `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Também existem algumas ferramentas preparadas para MacOS para enumerar automaticamente o AD e interagir com o kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound é uma extensão da ferramenta de auditoria Bloodhound que permite coletar e ingerir relacionamentos do Active Directory em hosts MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost é um projeto Objective-C projetado para interagir com as APIs Heimdal krb5 no macOS. O objetivo do projeto é permitir testes de segurança melhores em torno do Kerberos em dispositivos macOS usando APIs nativas sem exigir nenhum outro framework ou pacotes no alvo.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Ferramenta JavaScript for Automation (JXA) para enumeração do Active Directory.

### Informações de Domínio
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Usuários

Os três tipos de usuários do MacOS são:

- **Usuários Locais** — Gerenciados pelo serviço local OpenDirectory, não estão conectados de forma alguma ao Active Directory.
- **Usuários de Rede** — Usuários voláteis do Active Directory que requerem uma conexão com o servidor DC para autenticação.
- **Usuários Móveis** — Usuários do Active Directory com um backup local de suas credenciais e arquivos.

As informações locais sobre usuários e grupos são armazenadas na pasta _/var/db/dslocal/nodes/Default._\
Por exemplo, as informações sobre o usuário chamado _mark_ são armazenadas em _/var/db/dslocal/nodes/Default/users/mark.plist_ e as informações sobre o grupo _admin_ estão em _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Além de usar as arestas HasSession e AdminTo, o **MacHound adiciona três novas arestas** ao banco de dados Bloodhound:

- **CanSSH** - entidade autorizada a fazer SSH para o host
- **CanVNC** - entidade autorizada a fazer VNC para o host
- **CanAE** - entidade autorizada a executar scripts AppleEvent no host
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

O Keychain provavelmente contém informações sensíveis que, se acessadas sem gerar um prompt, poderiam ajudar a avançar em um exercício de red team:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Serviços Externos

O Red Teaming do MacOS é diferente de um Red Teaming regular do Windows, pois geralmente **o MacOS está integrado a várias plataformas externas diretamente**. Uma configuração comum do MacOS é acessar o computador usando **credenciais sincronizadas do OneLogin e acessar vários serviços externos** (como github, aws...) via OneLogin.

## Técnicas Misc de Red Team

### Safari

Quando um arquivo é baixado no Safari, se for um arquivo "seguro", ele será **aberto automaticamente**. Por exemplo, se você **baixar um arquivo zip**, ele será descompactado automaticamente:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## Referências

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

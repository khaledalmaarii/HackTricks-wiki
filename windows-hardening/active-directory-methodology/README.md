# Metodologia do Active Directory

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Visão geral básica

O **Active Directory** serve como uma tecnologia fundamental, permitindo que **administradores de rede** criem e gerenciem eficientemente **domínios**, **usuários** e **objetos** dentro de uma rede. Ele é projetado para escalar, facilitando a organização de um grande número de usuários em **grupos** e **subgrupos** gerenciáveis, enquanto controla **direitos de acesso** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domínios**, **árvores** e **florestas**. Um **domínio** engloba uma coleção de objetos, como **usuários** ou **dispositivos**, compartilhando um banco de dados comum. **Árvores** são grupos desses domínios ligados por uma estrutura compartilhada, e uma **floresta** representa a coleção de várias árvores, interconectadas por meio de **relacionamentos de confiança**, formando a camada mais alta da estrutura organizacional. Direitos específicos de **acesso** e **comunicação** podem ser designados em cada um desses níveis.

Conceitos-chave dentro do **Active Directory** incluem:

1. **Diretório** – Armazena todas as informações relacionadas aos objetos do Active Directory.
2. **Objeto** – Denota entidades dentro do diretório, incluindo **usuários**, **grupos** ou **pastas compartilhadas**.
3. **Domínio** – Serve como um contêiner para objetos de diretório, com a capacidade de vários domínios coexistirem dentro de uma **floresta**, cada um mantendo sua própria coleção de objetos.
4. **Árvore** – Um agrupamento de domínios que compartilham um domínio raiz comum.
5. **Floresta** – O ápice da estrutura organizacional no Active Directory, composta por várias árvores com **relacionamentos de confiança** entre elas.

**Serviços de Domínio do Active Directory (AD DS)** englobam uma variedade de serviços críticos para o gerenciamento centralizado e comunicação dentro de uma rede. Esses serviços incluem:

1. **Serviços de Domínio** – Centraliza o armazenamento de dados e gerencia interações entre **usuários** e **domínios**, incluindo funcionalidades de **autenticação** e **busca**.
2. **Serviços de Certificado** – Supervisiona a criação, distribuição e gerenciamento de **certificados digitais** seguros.
3. **Serviços de Diretório Leve** – Suporta aplicativos habilitados para diretório por meio do protocolo **LDAP**.
4. **Serviços de Federação de Diretórios** – Fornece capacidades de **login único** para autenticar usuários em várias aplicações web em uma única sessão.
5. **Gerenciamento de Direitos** – Auxilia na proteção de material protegido por direitos autorais, regulando sua distribuição e uso não autorizado.
6. **Serviço DNS** – Crucial para a resolução de **nomes de domínio**.

Para uma explicação mais detalhada, consulte: [**TechTerms - Definição de Active Directory**](https://techterms.com/definition/active_directory)


### **Autenticação Kerberos**

Para aprender como **atacar um AD**, você precisa **entender** muito bem o processo de **autenticação Kerberos**.\
[**Leia esta página se ainda não sabe como funciona.**](kerberos-authentication.md)

## Cheat Sheet

Você pode acessar [https://wadcoms.github.io/](https://wadcoms.github.io) para ter uma visão rápida dos comandos que você pode executar para enumerar/explorar um AD.

## Reconhecimento do Active Directory (Sem credenciais/sessões)

Se você apenas tem acesso a um ambiente AD, mas não possui credenciais/sessões, você poderia:

* **Testar a rede:**
* Escanear a rede, encontrar máquinas e portas abertas e tentar **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [as impressoras podem ser alvos muito interessantes](ad-information-in-printers.md).
* Enumerar o DNS pode fornecer informações sobre servidores-chave no domínio, como web, impressoras, compartilhamentos, VPN, mídia, etc.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Dê uma olhada na [**Metodologia de Pentest**](../../generic-methodologies-and-resources/pentesting-methodology.md) geral para encontrar mais informações sobre como fazer isso.
* **Verificar o acesso nulo e de Convidado nos serviços SMB** (isso não funcionará em versões modernas do Windows):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Um guia mais detalhado sobre como enumerar um servidor SMB pode ser encontrado aqui:

{% content-ref url="../../network-services-pentesting/pentesting-smb.md" %}
[pentesting-smb.md](../../network-services-pentesting/pentesting-smb.md)
{% endcontent-ref %}

* **Enumerar Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Um guia mais detalhado sobre como enumerar o LDAP pode ser encontrado aqui (preste **atenção especial ao acesso anônimo**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Envenenar a rede**
* Obter credenciais [**se passando por serviços com Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Acessar o host [**abusando do ataque de relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Obter credenciais **expondo** [**serviços UPnP falsos com evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Extrair nomes de usuários de documentos internos, redes sociais, serviços (principalmente web) dentro dos ambientes de domínio e também dos disponíveis publicamente.
* Se encontrar os nomes completos dos funcionários da empresa, você poderia tentar diferentes **convenções de nome de usuário do AD (**[**leia isso**](https://activedirectorypro.com/active-directory-user-naming-convention/)). As convenções mais comuns são: _NomeSobrenome_, _Nome.Sobrenome_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSobrenome_, _N.Sobrenome_, _SobrenomeNome_, _Sobrenome.Nome_, _SobrenomeN_, _Sobrenome.N_, 3 _letras aleatórias e 3 números aleatórios_ (abc123).
* Ferramentas:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeração de Usuários

* **Enumeração anônima SMB/LDAP:** Consulte as páginas de [**pentest SMB**](../../network-services-pentesting/pentesting-smb.md) e [**pentest LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Enumeração Kerbrute**: Quando um **nome de usuário inválido é solicitado**, o servidor responderá usando o código de erro do Kerberos _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, permitindo-nos determinar que o nome de usuário era inválido. **Nomes de usuário válidos** irão gerar ou o **TGT em uma resposta AS-REP** ou o erro _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, indicando que o usuário precisa realizar pré-autenticação.
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
Você pode encontrar listas de nomes de usuário em [**este repositório do github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) e neste ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

No entanto, você deve ter o **nome das pessoas que trabalham na empresa** da etapa de reconhecimento que você deveria ter realizado antes disso. Com o nome e sobrenome, você pode usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar possíveis nomes de usuário válidos.
{% endhint %}

### Conhecendo um ou vários nomes de usuário

Ok, então você já sabe que tem um nome de usuário válido, mas não tem senhas... Então tente:

* [**ASREPRoast**](asreproast.md): Se um usuário **não tiver** o atributo _DONT\_REQ\_PREAUTH_, você pode **solicitar uma mensagem AS\_REP** para esse usuário que conterá alguns dados criptografados por uma derivação da senha do usuário.
* [**Password Spraying**](password-spraying.md): Vamos tentar as senhas mais **comuns** com cada um dos usuários descobertos, talvez algum usuário esteja usando uma senha fraca (lembre-se da política de senhas!).
* Note que você também pode **atacar servidores OWA** para tentar acessar os servidores de e-mail dos usuários.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Envenenamento LLMNR/NBT-NS

Você pode ser capaz de **obter** alguns **hashes de desafio** para quebrar **envenenando** alguns protocolos da **rede**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### Revezamento NTML

Se você conseguiu enumerar o active directory, terá **mais e-mails e uma melhor compreensão da rede**. Você pode tentar forçar ataques de revezamento NTML [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obter acesso ao ambiente AD.

### Roubo de Credenciais NTLM

Se você pode **acessar outros PCs ou compartilhamentos** com o **usuário nulo ou convidado**, você pode **colocar arquivos** (como um arquivo SCF) que, se acessados de alguma forma, irão **disparar uma autenticação NTML contra você** para que você possa **roubar** o **desafio NTLM** para quebrá-lo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Enumerando Active Directory COM credenciais/sessão

Para esta fase, você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida**. Se você tiver algumas credenciais válidas ou um shell como usuário de domínio, **lembre-se de que as opções dadas anteriormente ainda são opções para comprometer outros usuários**.

Antes de começar a enumeração autenticada, você deve saber o que é o **problema de duplo salto do Kerberos**.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Enumeração

Ter comprometido uma conta é um **grande passo para começar a comprometer todo o domínio**, porque você será capaz de iniciar a **Enumeração do Active Directory:**

Em relação ao [**ASREPRoast**](asreproast.md), agora você pode encontrar todos os possíveis usuários vulneráveis, e em relação ao [**Password Spraying**](password-spraying.md), você pode obter uma **lista de todos os nomes de usuário** e tentar a senha da conta comprometida, senhas em branco e novas senhas promissoras.

* Você pode usar o [**CMD para realizar um reconhecimento básico**](../basic-cmd-for-pentesters.md#domain-info)
* Você também pode usar [**powershell para reconhecimento**](../basic-powershell-for-pentesters/) que será mais furtivo
* Você também pode [**usar o powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
* Outra ferramenta incrível para reconhecimento em um active directory é o [**BloodHound**](bloodhound.md). Não é muito furtivo (dependendo dos métodos de coleta que você usa), mas **se você não se importa** com isso, você deve definitivamente experimentar. Encontre onde os usuários podem fazer RDP, encontre o caminho para outros grupos, etc.
* **Outras ferramentas automatizadas de enumeração AD são:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Registros DNS do AD**](ad-dns-records.md) pois podem conter informações interessantes.
* Uma **ferramenta com GUI** que você pode usar para enumerar o diretório é o **AdExplorer.exe** da **SysInternal** Suite.
* Você também pode pesquisar no banco de dados LDAP com **ldapsearch** para procurar credenciais nos campos _userPassword_ & _unixUserPassword_, ou até mesmo em _Description_. cf. [Senha no comentário do usuário AD em PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
* Se você estiver usando **Linux**, você também pode enumerar o domínio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
* Você também pode tentar ferramentas automatizadas como:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Extraindo todos os usuários do domínio**

É muito fácil obter todos os nomes de usuário do domínio no Windows (`net user /domain`, `Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção de Enumeração pareça pequena, este é o momento mais importante de todos. Acesse os links (principalmente o de cmd, powershell, powerview e BloodHound), aprenda como enumerar um domínio e pratique até se sentir confortável. Durante uma avaliação, este será o momento-chave para encontrar o caminho para DA ou decidir que nada pode ser feito.

### Kerberoast

O Kerberoasting envolve a obtenção de **tickets TGS** usados por serviços vinculados a contas de usuário e a quebra de sua criptografia—que é baseada nas senhas dos usuários—**offline**.

Mais sobre isso em:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Conexão remota (RDP, SSH, FTP, Win-RM, etc)

Depois de obter algumas credenciais, você pode verificar se tem acesso a alguma **máquina**. Para isso, você pode usar o **CrackMapExec** para tentar se conectar em vários servidores com diferentes protocolos, de acordo com suas varreduras de portas.

### Escalação de Privilégios Local

Se você tiver credenciais comprometidas ou uma sessão como um usuário de domínio regular e tiver **acesso** com este usuário a **qualquer máquina no domínio**, você deve tentar encontrar seu caminho para **escalar privilégios localmente e roubar credenciais**. Isso ocorre porque somente com privilégios de administrador local você poderá **extrair hashes de outros usuários** na memória (LSASS) e localmente (SAM).

Há uma página completa neste livro sobre [**escalação de privilégios local no Windows**](../windows-local-privilege-escalation/) e uma [**lista de verificação**](../checklist-windows-privilege-escalation.md). Além disso, não se esqueça de usar o [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets da Sessão Atual

É muito **improvável** que você encontre **tickets** no usuário atual **dando permissão para acessar** recursos inesperados, mas você pode verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Se você conseguiu enumerar o active directory, terá **mais e-mails e uma melhor compreensão da rede**. Você pode ser capaz de forçar ataques de **retransmissão NTML**.

### Procurando Credenciais em Compartilhamentos de Computadores

Agora que você tem algumas credenciais básicas, você deve verificar se consegue **encontrar** arquivos **interessantes sendo compartilhados dentro do AD**. Você poderia fazer isso manualmente, mas é uma tarefa muito entediante e repetitiva (ainda mais se encontrar centenas de documentos para verificar).

[**Siga este link para aprender sobre ferramentas que você poderia usar.**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### Roubo de Credenciais NTLM

Se você pode **acessar outros PCs ou compartilhamentos**, você poderia **colocar arquivos** (como um arquivo SCF) que, se acessados de alguma forma, irão **disparar uma autenticação NTML contra você** para que você possa **roubar** o **desafio NTLM** para quebrá-lo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Essa vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o controlador de domínio**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Escalação de Privilégios no Active Directory COM credenciais/sessão privilegiadas

**Para as técnicas a seguir, um usuário de domínio regular não é suficiente, você precisa de alguns privilégios/credenciais especiais para realizar esses ataques.**

### Extração de Hash

Com sorte, você conseguiu **comprometer alguma conta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo retransmissão, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilégios localmente](../windows-local-privilege-escalation/).\
Então, é hora de despejar todos os hashes na memória e localmente.\
[**Leia esta página sobre diferentes maneiras de obter os hashes.**](broken-reference/)

### Pass the Hash

**Uma vez que você tenha o hash de um usuário**, você pode usá-lo para **se passar por ele**.\
Você precisa usar alguma **ferramenta** que irá **realizar** a **autenticação NTLM usando** esse **hash**, **ou** você poderia criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, para que quando qualquer **autenticação NTLM seja realizada**, esse **hash será usado**. A última opção é o que o mimikatz faz.\
[**Leia esta página para mais informações.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque visa **usar o hash NTLM do usuário para solicitar tickets Kerberos**, como uma alternativa ao comum Pass The Hash sobre o protocolo NTLM. Portanto, isso poderia ser especialmente **útil em redes onde o protocolo NTLM está desativado** e apenas **Kerberos é permitido** como protocolo de autenticação.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

No método de ataque **Pass The Ticket (PTT)**, os invasores **roubam o ticket de autenticação de um usuário** em vez de suas senhas ou valores de hash. Esse ticket roubado é então usado para **se passar pelo usuário**, obtendo acesso não autorizado a recursos e serviços dentro de uma rede.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Reutilização de Credenciais

Se você tiver o **hash** ou **senha** de um **administrador local**, você deve tentar **fazer login localmente** em outros **PCs** com ele.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Note que isso é bastante **ruidoso** e o **LAPS** poderia **mitigar** isso.
{% endhint %}

### Abuso de MSSQL e Links Confiáveis

Se um usuário tem privilégios para **acessar instâncias MSSQL**, ele poderia ser capaz de usá-lo para **executar comandos** no host MSSQL (se estiver sendo executado como SA), **roubar** o **hash** NetNTLM ou até mesmo realizar um **ataque** de **relé**.\
Além disso, se uma instância MSSQL é confiável (link de banco de dados) por uma instância MSSQL diferente. Se o usuário tiver privilégios sobre o banco de dados confiável, ele poderá **usar o relacionamento de confiança para executar consultas também na outra instância**. Essas confianças podem ser encadeadas e, em algum momento, o usuário pode ser capaz de encontrar um banco de dados mal configurado onde ele pode executar comandos.\
**Os links entre bancos de dados funcionam mesmo através de confianças entre florestas.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Delegação Não Restrita

Se você encontrar algum objeto de Computador com o atributo [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) e tiver privilégios de domínio no computador, você poderá extrair TGTs da memória de todos os usuários que fizerem login no computador.\
Portanto, se um **Administrador de Domínio fizer login no computador**, você poderá extrair o TGT dele e se passar por ele usando [Pass the Ticket](pass-the-ticket.md).\
Graças à delegação restrita, você poderia até mesmo **comprometer automaticamente um Servidor de Impressão** (esperançosamente será um DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Delegação Restrita

Se um usuário ou computador tem permissão para "Delegação Restrita", ele poderá **se passar por qualquer usuário para acessar alguns serviços em um computador**.\
Então, se você **comprometer o hash** desse usuário/computador, você poderá **se passar por qualquer usuário** (até mesmo administradores de domínio) para acessar alguns serviços.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Delegação Baseada em Recursos

Ter privilégio de **ESCRITA** em um objeto Active Directory de um computador remoto permite a obtenção de execução de código com **privilégios elevados**:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Abuso de ACLs

O usuário comprometido pode ter alguns **privilégios interessantes sobre alguns objetos de domínio** que podem permitir que você **se mova** lateralmente/**eleve** privilégios.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Abuso do Serviço de Spooler de Impressão

Descobrir um **serviço Spool** ouvindo dentro do domínio pode ser **abusado** para **adquirir novas credenciais** e **elevar privilégios**.

{% content-ref url="acl-persistence-abuse/" %}
[printers-spooler-service-abuse](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Abuso de Sessões de Terceiros

Se **outros usuários** **acessarem** a **máquina comprometida**, é possível **obter credenciais da memória** e até mesmo **injetar beacons em seus processos** para se passar por eles.\
Normalmente, os usuários acessarão o sistema via RDP, então aqui está como realizar alguns ataques sobre sessões RDP de terceiros:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** fornece um sistema para gerenciar a **senha do Administrador local** em computadores associados a domínio, garantindo que seja **aleatória**, única e frequentemente **alterada**. Essas senhas são armazenadas no Active Directory e o acesso é controlado por ACLs apenas para usuários autorizados. Com permissões suficientes para acessar essas senhas, é possível fazer pivoteamento para outros computadores.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Roubo de Certificados

**Reunir certificados** da máquina comprometida pode ser uma maneira de elevar privilégios dentro do ambiente:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Abuso de Modelos de Certificados

Se **modelos vulneráveis** estiverem configurados, é possível abusar deles para elevar privilégios:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Pós-exploração com conta de alto privilégio

### Despejo de Credenciais de Domínio

Uma vez que você obtém privilégios de **Administrador de Domínio** ou até mesmo **Administrador Empresarial**, você pode **despejar** o **banco de dados do domínio**: _ntds.dit_.

[**Mais informações sobre o ataque DCSync podem ser encontradas aqui**](dcsync.md).

[**Mais informações sobre como roubar o NTDS.dit podem ser encontradas aqui**](broken-reference/)

### Privesc como Persistência

Algumas das técnicas discutidas anteriormente podem ser usadas para persistência.\
Por exemplo, você poderia:

*   Tornar usuários vulneráveis ao [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <nome de usuário> -Set @{serviceprincipalname="falso/NADA"}r
```
*   Tornar usuários vulneráveis ao [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <nome de usuário> -XOR @{UserAccountControl=4194304}
```
*   Conceder privilégios de [**DCSync**](./#dcsync) a um usuário

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Ticket Silver

O ataque **Silver Ticket** cria um **legítimo ticket de serviço de concessão de tickets (TGS)** para um serviço específico usando o **hash NTLM** (por exemplo, o **hash da conta do PC**). Este método é empregado para **acessar os privilégios do serviço**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Ticket Dourado

Um **ataque de Ticket Dourado** envolve um invasor obtendo acesso ao **hash NTLM da conta krbtgt** em um ambiente de Active Directory (AD). Essa conta é especial porque é usada para assinar todos os **Tickets de Concessão de Tickets (TGTs)**, que são essenciais para autenticar dentro da rede AD.

Uma vez que o invasor obtém esse hash, ele pode criar **TGTs** para qualquer conta que escolher (ataque de ticket Silver).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Ticket de Diamante

Esses são como tickets dourados forjados de uma maneira que **burla os mecanismos de detecção comuns de tickets dourados**.

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Persistência de Conta de Certificados**

**Ter certificados de uma conta ou ser capaz de solicitá-los** é uma ótima maneira de poder persistir na conta dos usuários (mesmo que eles mudem a senha):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Persistência de Domínio de Certificados**

**Usar certificados também é possível para persistir com altos privilégios dentro do domínio:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Grupo AdminSDHolder

O objeto **AdminSDHolder** no Active Directory garante a segurança de **grupos privilegiados** (como Administradores de Domínio e Administradores Empresariais) aplicando uma **Lista de Controle de Acesso (ACL)** padrão em todos esses grupos para evitar alterações não autorizadas. No entanto, esse recurso pode ser explorado; se um invasor modificar a ACL do AdminSDHolder para conceder acesso total a um usuário comum, esse usuário ganha controle extensivo sobre todos os grupos privilegiados. Essa medida de segurança, destinada a proteger, pode se voltar contra, permitindo acesso não autorizado, a menos que seja monitorada de perto.

[**Mais informações sobre o Grupo AdminDSHolder aqui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciais DSRM

Dentro de cada **Controlador de Domínio (DC)**, existe uma conta de **Administrador local**. Ao obter direitos de administrador em tal máquina, o hash do Administrador local pode ser extraído usando **mimikatz**. Em seguida, é necessária uma modificação no registro para **habilitar o uso dessa senha**, permitindo o acesso remoto à conta de Administrador local.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Persistência de ACL

Você poderia **dar** algumas **permissões especiais** a um **usuário** sobre alguns objetos de domínio específicos que permitirão ao usuário **elevar privilégios no futuro**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref % %}

### Descritores de Segurança

Os **descritores de segurança** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** um **objeto**. Se você puder apenas **fazer** uma **pequena alteração** no **descritor de segurança** de um objeto, poderá obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Chave Esquelética

Alterar o **LSASS** na memória para estabelecer uma **senha universal**, concedendo acesso a todas as contas de domínio.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### SSP Personalizado

[Saiba o que é um SSP (Provedor de Suporte de Segurança) aqui.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
Você pode criar seu **próprio SSP** para **capturar** em **texto claro** as **credenciais** usadas para acessar a máquina.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Ele registra um **novo Controlador de Domínio** no AD e o usa para **inserir atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar **logs** sobre as **modificações**. Você **precisa de privilégios DA** e estar dentro do **domínio raiz**.\
Observe que se você usar dados incorretos, logs bastante feios aparecerão.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Persistência LAPS

Anteriormente discutimos sobre como elevar privilégios se você tiver **permissão suficiente para ler senhas LAPS**. No entanto, essas senhas também podem ser usadas para **manter a persistência**.\
Confira:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Escalonamento de Privilégios de Floresta - Confianças de Domínio

A Microsoft considera a **Floresta** como a fronteira de segurança. Isso implica que **comprometer um único domínio poderia potencialmente levar à comprometimento de toda a Floresta**.

### Informações Básicas

Uma [**confiança de domínio**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) é um mecanismo de segurança que permite a um usuário de um **domínio** acessar recursos em outro **domínio**. Essencialmente, cria uma ligação entre os sistemas de autenticação dos dois domínios, permitindo que as verificações de autenticação fluam sem problemas. Quando os domínios configuram uma confiança, eles trocam e mantêm chaves específicas em seus **Controladores de Domínio (DCs)**, que são cruciais para a integridade da confiança.

Em um cenário típico, se um usuário pretende acessar um serviço em um **domínio confiável**, ele deve primeiro solicitar um ticket especial conhecido como um **TGT inter-reino** do DC de seu próprio domínio. Este TGT é criptografado com uma **chave compartilhada** na qual ambos os domínios concordaram. O usuário então apresenta este TGT ao **DC do domínio confiável** para obter um ticket de serviço (**TGS**). Após a validação bem-sucedida do TGT inter-reino pelo DC do domínio confiável, ele emite um TGS, concedendo ao usuário acesso ao serviço.

**Passos**:

1. Um **computador cliente** no **Domínio 1** inicia o processo usando seu **hash NTLM** para solicitar um **Ticket Granting Ticket (TGT)** de seu **Controlador de Domínio (DC1)**.
2. DC1 emite um novo TGT se o cliente for autenticado com sucesso.
3. O cliente então solicita um **TGT inter-reino** do DC1, necessário para acessar recursos no **Domínio 2**.
4. O TGT inter-reino é criptografado com uma **chave de confiança** compartilhada entre DC1 e DC2 como parte da confiança de domínio bidirecional.
5. O cliente leva o TGT inter-reino ao **Controlador de Domínio do Domínio 2 (DC2)**.
6. DC2 verifica o TGT inter-reino usando sua chave de confiança compartilhada e, se válido, emite um **Ticket Granting Service (TGS)** para o servidor no Domínio 2 que o cliente deseja acessar.
7. Finalmente, o cliente apresenta este TGS ao servidor, que é criptografado com o hash da conta do servidor, para obter acesso ao serviço no Domínio 2.

### Diferentes confianças

É importante notar que **uma confiança pode ser de 1 via ou de 2 vias**. Nas opções de 2 vias, ambos os domínios confiarão um no outro, mas na relação de confiança de **1 via**, um dos domínios será o domínio confiável e o outro o domínio confiante. Neste último caso, **você só poderá acessar recursos dentro do domínio confiante a partir do confiável**.

Se o Domínio A confia no Domínio B, A é o domínio confiante e B é o domínio confiável. Além disso, no **Domínio A**, isso seria uma **confiança de saída**; e no **Domínio B**, isso seria uma **confiança de entrada**.

**Diferentes relacionamentos de confiança**

* **Confianças Pai-Filho**: Esta é uma configuração comum dentro da mesma floresta, onde um domínio filho automaticamente tem uma confiança bidirecional transitiva com seu domínio pai. Essencialmente, isso significa que as solicitações de autenticação podem fluir sem problemas entre o pai e o filho.
* **Confianças de Link Cruzado**: Chamadas de "confianças de atalho", essas são estabelecidas entre domínios filhos para acelerar os processos de referência. Em florestas complexas, as referências de autenticação geralmente têm que viajar até a raiz da
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
Existem **2 chaves confiáveis**, uma para _Filho --> Pai_ e outra para _Pai_ --> _Filho_.\
Você pode verificar a que está sendo usada pelo domínio atual com:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### Injeção de SID-History

Escalando como administrador empresarial para o domínio filho/pai abusando da confiança com a injeção de SID-History:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Explorar Configuração NC gravável

Compreender como a Contexto de Nomenclatura de Configuração (NC) pode ser explorada é crucial. O NC de Configuração serve como um repositório central para dados de configuração em toda a floresta em ambientes de Active Directory (AD). Esses dados são replicados para cada Controlador de Domínio (DC) dentro da floresta, com DCs graváveis mantendo uma cópia gravável do NC de Configuração. Para explorar isso, é necessário ter **privilégios do SISTEMA em um DC**, de preferência um DC filho.

**Vincular GPO ao site do DC raiz**

O contêiner de Sites do NC de Configuração inclui informações sobre todos os sites de computadores associados ao domínio dentro da floresta AD. Ao operar com privilégios do SISTEMA em qualquer DC, os atacantes podem vincular GPOs aos sites do DC raiz. Essa ação compromete potencialmente o domínio raiz ao manipular políticas aplicadas a esses sites.

Para informações mais detalhadas, é possível explorar a pesquisa sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Comprometer qualquer gMSA na floresta**

Um vetor de ataque envolve direcionar gMSAs privilegiados dentro do domínio. A chave KDS Root, essencial para calcular as senhas dos gMSAs, é armazenada dentro do NC de Configuração. Com privilégios do SISTEMA em qualquer DC, é possível acessar a chave KDS Root e calcular as senhas para qualquer gMSA em toda a floresta.

Uma análise detalhada pode ser encontrada na discussão sobre [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Ataque de alteração de esquema**

Este método requer paciência, aguardando a criação de novos objetos AD privilegiados. Com privilégios do SISTEMA, um atacante pode modificar o Esquema AD para conceder a qualquer usuário controle completo sobre todas as classes. Isso poderia resultar em acesso não autorizado e controle sobre objetos AD recém-criados.

Leituras adicionais estão disponíveis em [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**De DA para EA com ADCS ESC5**

A vulnerabilidade ADCS ESC5 visa o controle sobre objetos de Infraestrutura de Chave Pública (PKI) para criar um modelo de certificado que permite autenticação como qualquer usuário dentro da floresta. Como os objetos PKI residem no NC de Configuração, comprometer um DC filho gravável permite a execução de ataques ESC5.

Mais detalhes sobre isso podem ser lidos em [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Em cenários sem ADCS, o atacante tem a capacidade de configurar os componentes necessários, conforme discutido em [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Domínio Externo da Floresta - Unidirecional (Entrada) ou bidirecional
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
Neste cenário **seu domínio é confiável** por um externo, dando a você **permissões indeterminadas** sobre ele. Você precisará descobrir **quais princípios do seu domínio têm acesso sobre o domínio externo** e então tentar explorá-lo:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Domínio da Floresta Externa - Apenas um Sentido (Saída)
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

No entanto, quando um **domínio é confiado** pelo domínio confiante, o domínio confiado **cria um usuário** com um **nome previsível** que usa como **senha a senha confiada**. O que significa que é possível **acessar um usuário do domínio confiante para entrar no confiado** para enumerá-lo e tentar escalar mais privilégios:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Outra maneira de comprometer o domínio confiado é encontrar um [**link SQL confiável**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** da confiança do domínio (o que não é muito comum).

Outra maneira de comprometer o domínio confiado é esperar em uma máquina onde um **usuário do domínio confiado pode acessar** para fazer login via **RDP**. Em seguida, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir daí.\
Além disso, se a **vítima montou seu disco rígido**, a partir do processo da sessão RDP o atacante poderia armazenar **backdoors** na **pasta de inicialização do disco rígido**. Essa técnica é chamada de **RDPInception**.

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Mitigação de abuso de confiança de domínio

### **Filtragem de SID:**

- O risco de ataques aproveitando o atributo de histórico de SID em confianças entre florestas é mitigado pela Filtragem de SID, que é ativada por padrão em todas as confianças entre florestas. Isso é fundamentado na suposição de que as confianças dentro da floresta são seguras, considerando a floresta, em vez do domínio, como o limite de segurança, conforme a posição da Microsoft.
- No entanto, há um porém: a filtragem de SID pode interromper aplicativos e acesso de usuários, levando à sua desativação ocasional.

### **Autenticação Seletiva:**

- Para confianças entre florestas, empregar a Autenticação Seletiva garante que os usuários das duas florestas não sejam autenticados automaticamente. Em vez disso, permissões explícitas são necessárias para que os usuários acessem domínios e servidores dentro do domínio ou floresta confiante.
- É importante observar que essas medidas não protegem contra a exploração do Contexto de Nomes de Configuração gravável (NC) ou ataques à conta de confiança.

[**Mais informações sobre confianças de domínio em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Algumas Defesas Gerais

[**Saiba mais sobre como proteger credenciais aqui.**](../stealing-credentials/credentials-protections.md)\

### **Medidas Defensivas para Proteção de Credenciais**

- **Restrições de Administradores de Domínio**: É recomendável que os Administradores de Domínio só possam fazer login nos Controladores de Domínio, evitando seu uso em outros hosts.
- **Privilégios de Conta de Serviço**: Os serviços não devem ser executados com privilégios de Administrador de Domínio (DA) para manter a segurança.
- **Limitação Temporal de Privilégios**: Para tarefas que exigem privilégios de DA, sua duração deve ser limitada. Isso pode ser alcançado por: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementando Técnicas de Engano**

- Implementar engano envolve definir armadilhas, como usuários ou computadores falsos, com recursos como senhas que não expiram ou são marcadas como Confiáveis para Delegação. Uma abordagem detalhada inclui criar usuários com direitos específicos ou adicioná-los a grupos de alto privilégio.
- Um exemplo prático envolve o uso de ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mais sobre a implementação de técnicas de engano pode ser encontrado em [Deploy-Deception no GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando Engano**

- **Para Objetos de Usuário**: Indicadores suspeitos incluem ObjectSID atípico, logons infrequentes, datas de criação e baixas contagens de senhas incorretas.
- **Indicadores Gerais**: Comparar atributos de objetos de engano potenciais com os de objetos genuínos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar tais enganos.

### **Burlando Sistemas de Detecção**

- **Burla de Detecção do Microsoft ATA**:
- **Enumeração de Usuário**: Evitar a enumeração de sessão nos Controladores de Domínio para evitar a detecção do ATA.
- **Impersonação de Ticket**: Utilizar chaves **aes** para a criação de tickets ajuda a evitar a detecção ao não rebaixar para NTLM.
- **Ataques DCSync**: Executar a partir de um não-Controlador de Domínio para evitar a detecção do ATA é aconselhável, pois a execução direta de um Controlador de Domínio acionará alertas.


## Referências

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

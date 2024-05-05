# Checklist - Escalação de Privilégios no Linux

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Junte-se ao servidor [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para se comunicar com hackers experientes e caçadores de recompensas por bugs!

**Percepções de Hacking**\
Engaje-se com conteúdo que mergulha na emoção e nos desafios do hacking

**Notícias de Hacking em Tempo Real**\
Mantenha-se atualizado com o mundo do hacking em ritmo acelerado por meio de notícias e insights em tempo real

**Últimos Anúncios**\
Fique informado sobre os novos programas de recompensas por bugs lançados e atualizações cruciais na plataforma

**Junte-se a nós no** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e comece a colaborar com os melhores hackers hoje!

### **Melhor ferramenta para procurar vetores de escalonamento de privilégios locais no Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informações do Sistema](privilege-escalation/#system-information)

* [ ] Obter **informações do SO**
* [ ] Verificar o [**PATH**](privilege-escalation/#path), alguma **pasta gravável**?
* [ ] Verificar [**variáveis de ambiente**](privilege-escalation/#env-info), algum detalhe sensível?
* [ ] Procurar por [**exploits de kernel**](privilege-escalation/#kernel-exploits) **usando scripts** (DirtyCow?)
* [ ] **Verificar** se a [**versão do sudo é vulnerável**](privilege-escalation/#sudo-version)
* [ ] [**Falha na verificação de assinatura do Dmesg**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Mais enumeração do sistema ([data, estatísticas do sistema, informações da CPU, impressoras](privilege-escalation/#more-system-enumeration))
* [ ] [Enumerar mais defesas](privilege-escalation/#enumerate-possible-defenses)

### [Drives](privilege-escalation/#drives)

* [ ] **Listar** drives montados
* [ ] **Algum drive não montado?**
* [ ] **Alguma credencial em fstab?**

### [**Software Instalado**](privilege-escalation/#installed-software)

* [ ] **Verificar se há** [**software útil**](privilege-escalation/#useful-software) **instalado**
* [ ] **Verificar se há** [**software vulnerável**](privilege-escalation/#vulnerable-software-installed) **instalado**

### [Processos](privilege-escalation/#processes)

* [ ] Há algum **software desconhecido em execução**?
* [ ] Há algum software em execução com **mais privilégios do que deveria**?
* [ ] Procurar por **exploits de processos em execução** (especialmente a versão em execução).
* [ ] Você pode **modificar o binário** de algum processo em execução?
* [ ] **Monitorar processos** e verificar se algum processo interessante está sendo executado com frequência.
* [ ] Você pode **ler** alguma **memória de processo** interessante (onde senhas poderiam estar salvas)?

### [Tarefas Agendadas/Cron?](privilege-escalation/#scheduled-jobs)

* [ ] O [**PATH** ](privilege-escalation/#cron-path)está sendo modificado por algum cron e você pode **escrever** nele?
* [ ] Algum [**curinga** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)em uma tarefa cron?
* [ ] Algum [**script modificável** ](privilege-escalation/#cron-script-overwriting-and-symlink)está sendo **executado** ou está dentro de uma **pasta modificável**?
* [ ] Você detectou que algum **script** poderia estar sendo [**executado** muito **frequentemente**](privilege-escalation/#frequent-cron-jobs)? (a cada 1, 2 ou 5 minutos)

### [Serviços](privilege-escalation/#services)

* [ ] Algum arquivo **.service gravável**?
* [ ] Algum binário **gravável** executado por um **serviço**?
* [ ] Alguma **pasta gravável no PATH do systemd**?

### [Timers](privilege-escalation/#timers)

* [ ] Algum **timer gravável**?

### [Sockets](privilege-escalation/#sockets)

* [ ] Algum arquivo **.socket gravável**?
* [ ] Você pode **comunicar-se com algum socket**?
* [ ] **Sockets HTTP** com informações interessantes?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Você pode **comunicar-se com algum D-Bus**?

### [Rede](privilege-escalation/#network)

* [ ] Enumere a rede para saber onde você está
* [ ] **Portas abertas que você não conseguia acessar antes** de obter um shell dentro da máquina?
* [ ] Você pode **capturar tráfego** usando `tcpdump`?

### [Usuários](privilege-escalation/#users)

* [ ] Enumeração de usuários/grupos **genéricos**
* [ ] Você tem um **UID muito grande**? A **máquina** é **vulnerável**?
* [ ] Você pode [**escalar privilégios graças a um grupo**](privilege-escalation/interesting-groups-linux-pe/) ao qual pertence?
* [ ] Dados da **Área de Transferência**?
* [ ] Política de Senhas?
* [ ] Tente **usar** todas as **senhas conhecidas** que você descobriu anteriormente para fazer login **com cada** usuário **possível**. Tente fazer login também sem senha.

### [PATH Gravável](privilege-escalation/#writable-path-abuses)

* [ ] Se você tem **privilégios de escrita sobre alguma pasta no PATH** pode ser capaz de escalar privilégios

### [Comandos SUDO e SUID](privilege-escalation/#sudo-and-suid)

* [ ] Você pode executar **qualquer comando com sudo**? Pode usá-lo para LER, ESCREVER ou EXECUTAR algo como root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Existe algum **binário SUID explorável**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Os [**comandos sudo** são **limitados** pelo **caminho**? você pode **burlar** as restrições](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Binário Sudo/SUID sem caminho indicado**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**Binário SUID especificando caminho**](privilege-escalation/#suid-binary-with-command-path)? Bypass
* [ ] [**Vulnerabilidade LD\_PRELOAD**](privilege-escalation/#ld\_preload)
* [ ] [**Falta de biblioteca .so no binário SUID**](privilege-escalation/#suid-binary-so-injection) de uma pasta gravável?
* [ ] [**Tokens SUDO disponíveis**](privilege-escalation/#reusing-sudo-tokens)? [**Você pode criar um token SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Você pode [**ler ou modificar arquivos sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] Você pode [**modificar /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [**OpenBSD DOAS**](privilege-escalation/#doas) command
### [Capacidades](privilege-escalation/#capabilities)

* [ ] Algum binário possui alguma **capacidade inesperada**?

### [ACLs](privilege-escalation/#acls)

* [ ] Algum arquivo possui alguma **ACL inesperada**?

### [Sessões de Shell Abertas](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Valores de configuração SSH interessantes**](privilege-escalation/#ssh-interesting-configuration-values)

### [Arquivos Interessantes](privilege-escalation/#interesting-files)

* [ ] **Arquivos de perfil** - Ler dados sensíveis? Escrever para privesc?
* [ ] Arquivos **passwd/shadow** - Ler dados sensíveis? Escrever para privesc?
* [ ] **Verificar pastas comumente interessantes** para dados sensíveis
* [ ] **Localização/Estranheza de arquivos** que você pode ter acesso ou alterar arquivos executáveis
* [ ] **Modificado** nos últimos minutos
* [ ] Arquivos **Banco de Dados Sqlite**
* [ ] **Arquivos ocultos**
* [ ] **Script/Binários no PATH**
* [ ] **Arquivos Web** (senhas?)
* [ ] **Backups**?
* [ ] **Arquivos conhecidos que contêm senhas**: Usar **Linpeas** e **LaZagne**
* [ ] **Busca genérica**

### [**Arquivos Graváveis**](privilege-escalation/#writable-files)

* [ ] **Modificar biblioteca python** para executar comandos arbitrários?
* [ ] Pode **modificar arquivos de log**? Explorar **Logtotten**
* [ ] Pode **modificar /etc/sysconfig/network-scripts/**? Explorar vulnerabilidade no Centos/Redhat
* [ ] Pode [**escrever em arquivos ini, int.d, systemd ou rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Outros truques**](privilege-escalation/#other-tricks)

* [ ] Pode [**abusar do NFS para escalar privilégios**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Precisa [**escapar de um shell restritivo**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Junte-se ao servidor [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para se comunicar com hackers experientes e caçadores de bugs!

**Percepções de Hacking**\
Engaje-se com conteúdo que explora a emoção e os desafios do hacking

**Notícias de Hacking em Tempo Real**\
Mantenha-se atualizado com o mundo acelerado do hacking através de notícias e insights em tempo real

**Últimos Anúncios**\
Fique informado sobre os mais novos programas de recompensas por bugs lançados e atualizações cruciais na plataforma

**Junte-se a nós no** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e comece a colaborar com os melhores hackers hoje!

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou nos siga no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

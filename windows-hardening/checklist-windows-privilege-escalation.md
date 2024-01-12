# Checklist - Escalação de Privilégios Locais no Windows

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Participe do grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou do grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Melhor ferramenta para procurar vetores de escalação de privilégios locais no Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informações do Sistema](windows-local-privilege-escalation/#system-info)

* [ ] Obter [**Informações do sistema**](windows-local-privilege-escalation/#system-info)
* [ ] Procurar por **exploits de kernel** [**usando scripts**](windows-local-privilege-escalation/#version-exploits)
* [ ] Usar **Google para procurar** por exploits de **kernel**
* [ ] Usar **searchsploit para procurar** por exploits de **kernel**
* [ ] Informações interessantes em [**variáveis de ambiente**](windows-local-privilege-escalation/#environment)?
* [ ] Senhas no [**histórico do PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Informações interessantes nas [**configurações de Internet**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Unidades de disco**](windows-local-privilege-escalation/#drives)?
* [ ] [**Exploit WSUS**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Enumeração de Logging/AV](windows-local-privilege-escalation/#enumeration)

* [ ] Verificar configurações de [**Auditoria**](windows-local-privilege-escalation/#audit-settings) e [**WEF**](windows-local-privilege-escalation/#wef)
* [ ] Verificar [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Verificar se [**WDigest**](windows-local-privilege-escalation/#wdigest) está ativo
* [ ] [**Proteção LSA**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Guarda de Credenciais**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Credenciais em Cache**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Verificar se há algum [**AV**](windows-av-bypass)
* [ ] [**Política AppLocker**](authentication-credentials-uac-and-efs#applocker-policy)?
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**Privilégios de Usuário**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Verificar [**privilégios do usuário atual**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Você é [**membro de algum grupo privilegiado**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Verificar se você tem [algum desses tokens habilitados](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**?
* [ ] [**Sessões de Usuários**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Verificar [**homes dos usuários**](windows-local-privilege-escalation/#home-folders) (acesso?)
* [ ] Verificar [**Política de Senhas**](windows-local-privilege-escalation/#password-policy)
* [ ] O que está [**dentro da Área de Transferência**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Rede](windows-local-privilege-escalation/#network)

* [ ] Verificar [**informações atuais da rede**](windows-local-privilege-escalation/#network)
* [ ] Verificar **serviços locais ocultos** restritos ao exterior

### [Processos em Execução](windows-local-privilege-escalation/#running-processes)

* [ ] Permissões de [**arquivos e pastas de processos**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**Mineração de Senhas em Memória**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**Aplicativos GUI Inseguros**](windows-local-privilege-escalation/#insecure-gui-apps)

### [Serviços](windows-local-privilege-escalation/#services)

* [ ] [Você pode **modificar algum serviço**?](windows-local-privilege-escalation#permissions)
* [ ] [Você pode **modificar** o **binário** que é **executado** por algum **serviço**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Você pode **modificar** o **registro** de algum **serviço**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [Você pode se aproveitar de algum **caminho de binário de serviço não citado**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Aplicações**](windows-local-privilege-escalation/#applications)

* [ ] **Permissões de escrita em aplicações instaladas**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**Aplicações de Inicialização**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **Drivers** [**Vulneráveis**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Você pode **escrever em alguma pasta dentro do PATH**?
* [ ] Há algum serviço conhecido que **tenta carregar alguma DLL inexistente**?
* [ ] Você pode **escrever** em alguma **pasta de binários**?

### [Rede](windows-local-privilege-escalation/#network)

* [ ] Enumerar a rede (compartilhamentos, interfaces, rotas, vizinhos, ...)
* [ ] Observar especialmente os serviços de rede que escutam no localhost (127.0.0.1)

### [Credenciais do Windows](windows-local-privilege-escalation/#windows-credentials)

* [ ] Credenciais de [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)
* [ ] Credenciais do [**Cofre do Windows**](windows-local-privilege-escalation/#credentials-manager-windows-vault) que você poderia usar?
* [ ] Credenciais [**DPAPI**](windows-local-privilege-escalation/#dpapi) interessantes?
* [ ] Senhas de [**redes Wifi salvas**](windows-local-privilege-escalation/#wifi)?
* [ ] Informações interessantes em [**conexões RDP salvas**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Senhas em [**comandos recentemente executados**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] Senhas do [**Gerenciador de Credenciais de Área de Trabalho Remota**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
* [ ] [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe) existe? Credenciais?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? Carregamento Lateral de DLL?

### [Arquivos e Registro (Credenciais)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/#putty-creds) **e** [**Chaves de host SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**Chaves SSH no registro**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Senhas em [**arquivos não supervisionados**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Algum backup de [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
* [ ] [**Credenciais na nuvem**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] Arquivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [ ] [**Senha GPP em Cache**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Senha no [**arquivo de configuração do IIS Web**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Informações interessantes nos [**logs da web**](windows-local-privilege-escalation/#logs)?
* [ ] Você quer [**solicitar credenciais**](windows-local-privilege-escalation/#ask-for-credentials) ao usuário?
* [ ] Arquivos interessantes [**dentro da Lixeira**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Outros [**registros contendo credenciais**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Dentro dos dados do [**Navegador**](windows-local-privilege-escalation/#browsers-history) (dbs, histórico, favoritos, ...)?
* [ ] [**Busca genérica de senhas**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) em arquivos e registro
* [ ] [**Ferramentas**](windows-local-privilege-escalation/#tools-that-search-for-passwords) para busca automática de senhas

### [Manipuladores Vazados](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Você tem acesso a algum manipulador de um processo executado pelo administrador?

### [Impersonação de Cliente de Pipe](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Verifique se você pode abusar disso

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Participe do grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou do grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

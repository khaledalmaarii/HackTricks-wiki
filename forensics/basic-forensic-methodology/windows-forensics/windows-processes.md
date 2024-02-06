<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


## smss.exe

**Gerenciador de Sessão**.\
A Sessão 0 inicia **csrss.exe** e **wininit.exe** (**serviços do SO**) enquanto a Sessão 1 inicia **csrss.exe** e **winlogon.exe** (**sessão do usuário**). No entanto, você deve ver **apenas um processo** desse **binário** sem filhos na árvore de processos.

Além disso, sessões diferentes de 0 e 1 podem significar que sessões RDP estão ocorrendo.


## csrss.exe

**Processo de Subsistema de Execução Cliente/Servidor**.\
Ele gerencia **processos** e **threads**, disponibiliza a **API do Windows** para outros processos e também **mapeia letras de unidade**, cria **arquivos temporários** e lida com o **processo de desligamento**.

Há um **em execução na Sessão 0 e outro na Sessão 1** (então **2 processos** na árvore de processos). Outro é criado **por nova Sessão**.


## winlogon.exe

**Processo de Logon do Windows**.\
É responsável pelos **logons**/**logoffs** do usuário. Ele inicia **logonui.exe** para solicitar nome de usuário e senha e em seguida chama **lsass.exe** para verificá-los.

Em seguida, ele inicia **userinit.exe** que é especificado em **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** com a chave **Userinit**.

Além disso, o registro anterior deve ter **explorer.exe** na chave **Shell** ou pode ser abusado como um **método de persistência de malware**.


## wininit.exe

**Processo de Inicialização do Windows**. \
Ele inicia **services.exe**, **lsass.exe** e **lsm.exe** na Sessão 0. Deve haver apenas 1 processo.


## userinit.exe

**Aplicativo de Logon do Usuário**.\
Carrega o **ntduser.dat em HKCU** e inicializa o **ambiente do usuário** e executa **scripts de logon** e **GPO**.

Ele inicia **explorer.exe**.


## lsm.exe

**Gerenciador de Sessão Local**.\
Ele trabalha com smss.exe para manipular sessões de usuário: logon/logoff, inicialização do shell, bloqueio/desbloqueio da área de trabalho, etc.

Após o W7, lsm.exe foi transformado em um serviço (lsm.dll).

Deve haver apenas 1 processo no W7 e a partir deles um serviço executando o DLL.


## services.exe

**Gerenciador de Controle de Serviço**.\
Ele **carrega** **serviços** configurados como **início automático** e **drivers**.

É o processo pai de **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** e muitos mais.

Os serviços são definidos em `HKLM\SYSTEM\CurrentControlSet\Services` e este processo mantém um banco de dados na memória das informações do serviço que podem ser consultadas pelo sc.exe.

Observe como **alguns** **serviços** serão executados em um **processo próprio** e outros serão **compartilhados em um processo svchost.exe**.

Deve haver apenas 1 processo.


## lsass.exe

**Subsistema de Autoridade de Segurança Local**.\
É responsável pela autenticação do usuário e criação dos **tokens de segurança**. Ele usa pacotes de autenticação localizados em `HKLM\System\CurrentControlSet\Control\Lsa`.

Ele escreve no **log de eventos de segurança** e deve haver apenas 1 processo.

Lembre-se de que este processo é altamente atacado para extrair senhas.


## svchost.exe

**Processo de Hospedagem de Serviço Genérico**.\
Ele hospeda vários serviços DLL em um processo compartilhado.

Normalmente, você verá que **svchost.exe** é iniciado com a flag `-k`. Isso iniciará uma consulta ao registro **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** onde haverá uma chave com o argumento mencionado em -k que conterá os serviços a serem iniciados no mesmo processo.

Por exemplo: `-k UnistackSvcGroup` iniciará: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Se a **flag `-s`** também for usada com um argumento, então svchost é solicitado a **iniciar apenas o serviço especificado** neste argumento.

Haverá vários processos de `svchost.exe`. Se algum deles **não estiver usando a flag `-k`**, isso é muito suspeito. Se você descobrir que **services.exe não é o pai**, isso também é muito suspeito.


## taskhost.exe

Este processo atua como um host para processos em execução a partir de DLLs. Ele também carrega os serviços em execução a partir de DLLs.

No W8, isso é chamado de taskhostex.exe e no W10 de taskhostw.exe.


## explorer.exe

Este é o processo responsável pela **área de trabalho do usuário** e pela abertura de arquivos via extensões de arquivo.

Deve ser gerado **apenas 1** processo por **usuário conectado**.

Isso é executado a partir do **userinit.exe** que deve ser encerrado, então **nenhum processo pai** deve aparecer para este processo.


# Capturando Processos Maliciosos

* Está sendo executado no caminho esperado? (Nenhum binário do Windows é executado a partir de uma localização temporária)
* Está se comunicando com IPs estranhos?
* Verifique as assinaturas digitais (os artefatos da Microsoft devem ser assinados)
* Está escrito corretamente?
* Está sendo executado sob o SID esperado?
* O processo pai é o esperado (se houver)?
* Os processos filhos são os esperados? (sem cmd.exe, wscript.exe, powershell.exe..?)

</details>

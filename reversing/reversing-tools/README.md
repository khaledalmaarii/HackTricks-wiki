<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왑**](https://peass.creator-spring.com)을 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

# Wasm Decompilation and Wat Compilation Guide

**WebAssembly**의 영역에서 **디컴파일** 및 **컴파일** 도구는 개발자에게 필수적입니다. 이 가이드에서는 **Wasm (WebAssembly 바이너리)** 및 **Wat (WebAssembly 텍스트)** 파일을 처리하기 위한 온라인 리소스 및 소프트웨어를 소개합니다.

## 온라인 도구

- Wasm을 Wat으로 **디컴파일**하기 위해 [Wabt의 wasm2wat 데모](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) 도구를 사용할 수 있습니다.
- Wat을 Wasm으로 **컴파일**하기 위해 [Wabt의 wat2wasm 데모](https://webassembly.github.io/wabt/demo/wat2wasm/)를 사용할 수 있습니다.
- [web-wasmdec](https://wwwg.github.io/web-wasmdec/)에서 또 다른 디컴파일 옵션을 찾을 수 있습니다.

## 소프트웨어 솔루션

- 더 견고한 솔루션을 위해 [PNF Software의 JEB](https://www.pnfsoftware.com/jeb/demo)는 다양한 기능을 제공합니다.
- 오픈 소스 프로젝트인 [wasmdec](https://github.com/wwwg/wasmdec)도 디컴파일 작업에 사용할 수 있습니다.

# .Net 디컴파일 리소스

.Net 어셈블리의 디컴파일은 다음과 같은 도구를 사용하여 수행할 수 있습니다:

- [ILSpy](https://github.com/icsharpcode/ILSpy)는 [Visual Studio Code용 플러그인](https://github.com/icsharpcode/ilspy-vscode)도 제공하여 크로스 플랫폼 사용이 가능합니다.
- **디컴파일**, **수정**, **재컴파일** 작업에는 [dnSpy](https://github.com/0xd4d/dnSpy/releases)를 강력히 추천합니다. 메서드를 마우스 오른쪽 버튼으로 클릭하고 **Modify Method**를 선택하여 코드 변경을 활성화할 수 있습니다.
- [JetBrains의 dotPeek](https://www.jetbrains.com/es-es/decompiler/)은 .Net 어셈블리의 디컴파일을 위한 또 다른 대안입니다.

## 디버깅 및 로깅 개선하기

### DNSpy 로깅
DNSpy를 사용하여 파일에 정보를 기록하려면 다음 .Net 코드 스니펫을 포함하세요:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### DNSpy 디버깅
DNSpy를 사용한 효과적인 디버깅을 위해 디버깅을 방해할 수 있는 최적화를 비활성화하기 위해 **어셈블리 속성**을 조정하는 일련의 단계를 권장합니다. 이 프로세스에는 `DebuggableAttribute` 설정 변경, 어셈블리 재컴파일 및 변경 사항 저장이 포함됩니다.

또한 **IIS**에서 실행되는 .Net 애플리케이션을 디버깅하기 위해 `iisreset /noforce`를 실행하여 IIS를 다시 시작해야 합니다. DNSpy를 IIS 프로세스에 연결하여 디버깅 세션을 시작하는 방법에 대한 안내도 제공됩니다.

디버깅 중 로드된 모듈의 종합적인 보기를 위해 DNSpy의 **Modules** 창에 액세스한 다음 모든 모듈을 열고 탐색 및 디버깅을 쉽게하기 위해 어셈블리를 정렬하는 것이 좋습니다.

이 가이드는 WebAssembly 및 .Net 디컴파일의 본질을 포착하여 개발자가 이러한 작업을 쉽게 수행할 수 있는 방법을 제공합니다.

## **Java 디컴파일러**
Java 바이트코드를 디컴파일하기 위해 다음 도구들이 매우 유용할 수 있습니다:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **DLL 디버깅**
### IDA 사용
- 64비트 및 32비트 버전에 대한 특정 경로에서 **Rundll32**가 로드됩니다.
- 디버거로 **Windbg**가 선택되며 라이브러리 로드/언로드 시 중단 옵션이 활성화됩니다.
- 실행 매개변수에는 DLL 경로와 함수 이름이 포함됩니다. 이 설정은 각 DLL 로드 시 실행을 중지합니다.

### x64dbg/x32dbg 사용
- IDA와 유사하게 **rundll32**가 DLL 및 함수를 지정하기 위해 명령줄 수정과 함께 로드됩니다.
- DLL 진입점에서 중단점을 설정할 수 있도록 설정이 조정됩니다.

### 이미지
- 실행 중지 지점 및 구성은 스크린샷을 통해 설명됩니다.

## **ARM 및 MIPS**
- 에뮬레이션을 위해 [arm_now](https://github.com/nongiach/arm_now)은 유용한 리소스입니다.

## **쉘코드**
### 디버깅 기법
- **Blobrunner** 및 **jmp2it**는 메모리에 쉘코드를 할당하고 Ida 또는 x64dbg로 디버깅하는 도구입니다.
- Blobrunner [릴리스](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [컴파일된 버전](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter**는 파일 대 쉘코드로 처리하는 방식의 차이를 강조하는 GUI 기반의 쉘코드 에뮬레이션 및 검사를 제공합니다.

### 해독 및 분석
- **scdbg**는 쉘코드 함수 및 해독 기능에 대한 통찰력을 제공합니다.
%%%bash
scdbg.exe -f shellcode # 기본 정보
scdbg.exe -f shellcode -r # 분석 보고서
scdbg.exe -f shellcode -i -r # 대화식 후킹
scdbg.exe -f shellcode -d # 해독된 쉘코드 덤프
scdbg.exe -f shellcode /findsc # 시작 오프셋 찾기
scdbg.exe -f shellcode /foff 0x0000004D # 오프셋에서 실행
%%%

- 쉘코드를 분해하기 위한 **CyberChef**: [CyberChef 레시피](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- 모든 명령을 `mov`로 대체하는 난
## **Delphi**
- Delphi 이진 파일의 경우, [IDR](https://github.com/crypto2011/IDR)을(를) 추천합니다.


# 강의

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(이진 해독\)



<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기술을 공유하세요.

</details>

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}

# Wasm 디컴파일 및 Wat 컴파일 가이드

**WebAssembly** 영역에서 **디컴파일** 및 **컴파일** 도구는 개발자에게 필수적입니다. 이 가이드는 **Wasm (WebAssembly binary)** 및 **Wat (WebAssembly text)** 파일을 처리하기 위한 온라인 리소스와 소프트웨어를 소개합니다.

## 온라인 도구

- Wasm을 Wat으로 **디컴파일**하려면 [Wabt의 wasm2wat 데모](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)에서 제공하는 도구가 유용합니다.
- Wat을 다시 Wasm으로 **컴파일**하려면 [Wabt의 wat2wasm 데모](https://webassembly.github.io/wabt/demo/wat2wasm/)를 사용하면 됩니다.
- 또 다른 디컴파일 옵션은 [web-wasmdec](https://wwwg.github.io/web-wasmdec/)에서 찾을 수 있습니다.

## 소프트웨어 솔루션

- 보다 강력한 솔루션을 원한다면 [PNF Software의 JEB](https://www.pnfsoftware.com/jeb/demo)가 광범위한 기능을 제공합니다.
- 오픈 소스 프로젝트 [wasmdec](https://github.com/wwwg/wasmdec)도 디컴파일 작업에 사용할 수 있습니다.

# .Net 디컴파일 리소스

.Net 어셈블리를 디컴파일하는 데 사용할 수 있는 도구는 다음과 같습니다:

- [ILSpy](https://github.com/icsharpcode/ILSpy), 이 도구는 [Visual Studio Code용 플러그인](https://github.com/icsharpcode/ilspy-vscode)도 제공하여 크로스 플랫폼 사용이 가능합니다.
- **디컴파일**, **수정**, **재컴파일** 작업에 대해 [dnSpy](https://github.com/0xd4d/dnSpy/releases)를 강력히 추천합니다. **메서드에서 마우스 오른쪽 버튼 클릭** 후 **Modify Method**를 선택하면 코드 변경이 가능합니다.
- [JetBrains의 dotPeek](https://www.jetbrains.com/es-es/decompiler/)도 .Net 어셈블리를 디컴파일하는 또 다른 대안입니다.

## DNSpy로 디버깅 및 로깅 향상하기

### DNSpy 로깅
DNSpy를 사용하여 파일에 정보를 로깅하려면 다음 .Net 코드 스니펫을 포함하세요:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### DNSpy 디버깅
DNSpy로 효과적인 디버깅을 위해 **Assembly attributes**를 디버깅에 맞게 조정하는 일련의 단계를 권장합니다. 이 과정에는 `DebuggableAttribute` 설정 변경, 어셈블리 재컴파일 및 변경 사항 저장이 포함됩니다.

또한, **IIS**에서 실행되는 .Net 애플리케이션을 디버깅하기 위해 `iisreset /noforce`를 실행하여 IIS를 재시작합니다. DNSpy에서 IIS 프로세스에 DNSpy를 연결하여 디버깅을 시작하려면 **w3wp.exe** 프로세스를 선택하고 디버깅 세션을 시작하는 방법을 안내합니다.

디버깅 중 로드된 모듈을 종합적으로 보기 위해 DNSpy의 **Modules** 창에 접근하고 모든 모듈을 열어 어셈블리를 정렬하여 더 쉽게 탐색하고 디버깅할 수 있도록 하는 것이 좋습니다.

이 가이드는 WebAssembly 및 .Net 디컴파일의 본질을 요약하여 개발자가 이러한 작업을 쉽게 탐색할 수 있는 경로를 제공합니다.

## **Java 디컴파일러**
Java 바이트코드를 디컴파일하기 위해 다음 도구가 매우 유용할 수 있습니다:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **DLL 디버깅**
### IDA 사용하기
- **Rundll32**는 64비트 및 32비트 버전의 특정 경로에서 로드됩니다.
- **Windbg**는 라이브러리 로드/언로드 시 중단 옵션이 활성화된 디버거로 선택됩니다.
- 실행 매개변수에는 DLL 경로와 함수 이름이 포함됩니다. 이 설정은 각 DLL의 로드 시 실행을 중단합니다.

### x64dbg/x32dbg 사용하기
- IDA와 유사하게 **rundll32**는 DLL 및 함수를 지정하기 위해 명령줄 수정을 통해 로드됩니다.
- DLL 진입 시 중단하도록 설정을 조정하여 원하는 DLL 진입 지점에서 중단점을 설정할 수 있습니다.

### 이미지
- 실행 중지 지점 및 구성은 스크린샷을 통해 설명됩니다.

## **ARM & MIPS**
- 에뮬레이션을 위해 [arm_now](https://github.com/nongiach/arm_now)가 유용한 리소스입니다.

## **Shellcodes**
### 디버깅 기술
- **Blobrunner** 및 **jmp2it**는 메모리에 shellcode를 할당하고 Ida 또는 x64dbg로 디버깅하는 도구입니다.
- Blobrunner [릴리스](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [컴파일된 버전](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter**는 GUI 기반의 shellcode 에뮬레이션 및 검사를 제공하며, 파일로서의 shellcode 처리와 직접 shellcode 처리의 차이를 강조합니다.

### 디오브퓨스케이션 및 분석
- **scdbg**는 shellcode 기능 및 디오브퓨스케이션 기능에 대한 통찰력을 제공합니다.
%%%bash
scdbg.exe -f shellcode # 기본 정보
scdbg.exe -f shellcode -r # 분석 보고서
scdbg.exe -f shellcode -i -r # 인터랙티브 후크
scdbg.exe -f shellcode -d # 디코딩된 shellcode 덤프
scdbg.exe -f shellcode /findsc # 시작 오프셋 찾기
scdbg.exe -f shellcode /foff 0x0000004D # 오프셋에서 실행
%%%

- shellcode를 디스어셈블하기 위한 **CyberChef**: [CyberChef 레시피](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- 모든 명령어를 `mov`로 대체하는 오브퓨스케이터입니다.
- 유용한 리소스에는 [YouTube 설명](https://www.youtube.com/watch?v=2VF_wPkiBJY) 및 [PDF 슬라이드](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)가 포함됩니다.
- **demovfuscator**는 movfuscator의 오브퓨스케이션을 역전시킬 수 있으며, `libcapstone-dev` 및 `libz3-dev`와 같은 종속성이 필요하고 [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)을 설치해야 합니다.

## **Delphi**
- Delphi 바이너리의 경우 [IDR](https://github.com/crypto2011/IDR)를 추천합니다.


# 강좌

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(바이너리 디오브퓨스케이션\)



{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}

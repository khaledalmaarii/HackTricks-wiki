# macOS 번들

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

## 기본 정보

macOS의 번들은 응용 프로그램, 라이브러리 및 기타 필요한 파일을 포함하는 컨테이너로 작동하여 익숙한 `*.app` 파일과 같이 Finder에서 단일 개체로 표시됩니다. 가장 일반적으로 사용되는 번들은 `.app` 번들이지만, `.framework`, `.systemextension`, `.kext`와 같은 다른 유형도 흔하게 사용됩니다.

### 번들의 필수 구성 요소

번들 내에서 특히 `<application>.app/Contents/` 디렉토리 내에는 다양한 중요한 리소스가 저장됩니다:

- **_CodeSignature**: 이 디렉토리에는 응용 프로그램의 무결성을 확인하는 데 필수적인 코드 서명 세부 정보가 저장됩니다. 다음과 같은 명령을 사용하여 코드 서명 정보를 검사할 수 있습니다:
%%%bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
%%%
- **MacOS**: 사용자 상호 작용 시 실행되는 응용 프로그램의 실행 가능한 이진 파일이 포함되어 있습니다.
- **Resources**: 이미지, 문서 및 인터페이스 설명(nib/xib 파일)을 포함한 응용 프로그램의 사용자 인터페이스 구성 요소를 위한 저장소입니다.
- **Info.plist**: 응용 프로그램의 주요 구성 파일로, 시스템이 응용 프로그램을 인식하고 상호 작용하기 위해 필수적입니다.

#### Info.plist의 중요한 키

`Info.plist` 파일은 응용 프로그램 구성을 위한 중요한 기반 요소로, 다음과 같은 키를 포함합니다:

- **CFBundleExecutable**: `Contents/MacOS` 디렉토리에 위치한 주 실행 파일의 이름을 지정합니다.
- **CFBundleIdentifier**: 응용 프로그램에 대한 전역 식별자를 제공하며, macOS에서 응용 프로그램 관리에 널리 사용됩니다.
- **LSMinimumSystemVersion**: 응용 프로그램 실행에 필요한 macOS의 최소 버전을 나타냅니다.

### 번들 탐색

`Safari.app`과 같은 번들의 내용을 탐색하기 위해 다음 명령을 사용할 수 있습니다:
%%%bash
ls -lR /Applications/Safari.app/Contents
%%%

이 탐색을 통해 `_CodeSignature`, `MacOS`, `Resources`와 같은 디렉토리, 그리고 `Info.plist`와 같은 파일이 나타나며, 각각이 응용 프로그램의 보안부터 사용자 인터페이스 및 운영 매개변수 정의에 이르기까지 고유한 목적을 제공합니다.

#### 추가적인 번들 디렉토리

일반적인 디렉토리 이외에도 번들에는 다음과 같은 디렉토리가 포함될 수 있습니다:

- **Frameworks**: 응용 프로그램에서 사용하는 번들된 프레임워크가 포함되어 있습니다.
- **PlugIns**: 응용 프로그램의 기능을 향상시키는 플러그인과 확장 기능을 위한 디렉토리입니다.
- **XPCServices**: 응용 프로그램에서 프로세스 간 통신에 사용되는 XPC 서비스를 보유합니다.

이러한 구조는 번들 내에 필요한 모든 구성 요소가 캡슐화되어 모듈식이고 안전한 응용 프로그램 환경을 제공합니다.

`Info.plist` 키 및 그 의미에 대한 자세한 정보는 Apple 개발자 문서에서 다양한 리소스를 제공합니다: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

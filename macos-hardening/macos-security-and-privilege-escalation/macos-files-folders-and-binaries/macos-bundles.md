# macOS 번들

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}

## 기본 정보

macOS에서 번들은 응용 프로그램, 라이브러리 및 기타 필수 파일을 포함하는 컨테이너로 작용하여 Finder에서 `*.app` 파일과 같이 단일 객체로 나타나게 합니다. 가장 흔히 볼 수 있는 번들은 `.app` 번들이지만, `.framework`, `.systemextension`, `.kext`와 같은 다른 유형도 흔히 사용됩니다.

### 번들의 필수 구성 요소

특히 `<application>.app/Contents/` 디렉토리 내에서 번들 내에는 다음과 같은 중요한 리소스가 포함됩니다:

* **\_CodeSignature**: 응용 프로그램의 무결성을 확인하는 데 중요한 코드 서명 세부 정보를 저장하는 디렉토리입니다. 다음과 같은 명령을 사용하여 코드 서명 정보를 검사할 수 있습니다: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: 사용자 상호 작용 시 실행되는 응용 프로그램의 실행 가능한 이진 파일을 포함합니다.
* **Resources**: 이미지, 문서 및 인터페이스 설명(nib/xib 파일)을 포함하는 응용 프로그램의 사용자 인터페이스 구성 요소를 저장하는 저장소입니다.
* **Info.plist**: 응용 프로그램의 주 구성 파일로, 시스템이 응용 프로그램을 인식하고 상호 작용할 수 있도록 중요합니다.

#### Info.plist의 중요한 키

`Info.plist` 파일은 응용 프로그램 구성을 위한 중추적인 역할을 하며 다음과 같은 키를 포함합니다:

* **CFBundleExecutable**: `Contents/MacOS` 디렉토리에 있는 주 실행 파일의 이름을 지정합니다.
* **CFBundleIdentifier**: 응용 프로그램을 위한 전역 식별자를 제공하며 macOS에서 응용 프로그램 관리에 널리 사용됩니다.
* **LSMinimumSystemVersion**: 응용 프로그램 실행에 필요한 macOS의 최소 버전을 나타냅니다.

### 번들 탐색

`Safari.app`과 같은 번들의 내용을 탐색하려면 다음 명령을 사용할 수 있습니다: `bash ls -lR /Applications/Safari.app/Contents`

이 탐색을 통해 `_CodeSignature`, `MacOS`, `Resources`, `Info.plist`와 같은 디렉토리 및 응용 프로그램을 보호하고 사용자 인터페이스 및 운영 매개변수를 정의하는 파일과 같은 파일이 나타납니다.

#### 추가 번들 디렉토리

일반적인 디렉토리 이외에도 번들에는 다음이 포함될 수 있습니다:

* **Frameworks**: 응용 프로그램에서 사용되는 번들된 프레임워크를 포함합니다. 프레임워크는 추가 리소스가 있는 dylibs와 같습니다.
* **PlugIns**: 응용 프로그램 기능을 향상시키는 플러그인 및 확장 기능을 위한 디렉토리입니다.
* **XPCServices**: 응용 프로그램에서 프로세스 간 통신에 사용되는 XPC 서비스를 보유합니다.

이 구조는 모든 필수 구성 요소가 번들 내에 캡슐화되어 모듈식이고 안전한 응용 프로그램 환경을 용이하게 합니다.

`Info.plist` 키 및 의미에 대한 자세한 정보는 Apple 개발자 문서에서 다양한 리소스를 제공합니다: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}

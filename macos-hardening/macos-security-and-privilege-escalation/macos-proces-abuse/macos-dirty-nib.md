# macOS Dirty NIB

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 여러분의 해킹 기교를 공유하세요.

</details>

**기술에 대한 자세한 내용은 원본 게시물을 확인하세요: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** 여기에는 요약이 있습니다:

NIB 파일은 Apple의 개발 생태계의 일부로, 애플리케이션에서 **UI 요소**와 그들의 상호작용을 정의하기 위해 사용됩니다. 이들은 창과 버튼과 같은 직렬화된 객체를 포함하며, 런타임에 로드됩니다. Apple은 이제 더 포괄적인 UI 흐름 시각화를 위해 스토리보드를 권장하고 있지만, 여전히 NIB 파일이 사용되고 있습니다.

### NIB 파일과 관련된 보안 문제
**NIB 파일은 보안 위험**이 될 수 있습니다. 이들은 **임의의 명령을 실행**할 수 있으며, 앱 내의 NIB 파일을 변경해도 Gatekeeper가 앱을 실행하는 것을 방해하지 않으므로 중대한 위협이 될 수 있습니다.

### Dirty NIB 삽입 과정
#### NIB 파일 생성 및 설정
1. **초기 설정**:
- XCode를 사용하여 새로운 NIB 파일을 생성합니다.
- 인터페이스에 Object를 추가하고, 클래스를 `NSAppleScript`로 설정합니다.
- User Defined Runtime Attributes를 통해 초기 `source` 속성을 구성합니다.

2. **코드 실행 가젯**:
- 설정은 필요할 때 AppleScript를 실행할 수 있도록 합니다.
- `Apple Script` 객체를 활성화하는 버튼을 통합합니다. 특히 `executeAndReturnError:` 선택기를 트리거합니다.

3. **테스트**:
- 테스트 목적으로 간단한 Apple Script:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- XCode 디버거에서 실행하고 버튼을 클릭하여 테스트합니다.

#### 애플리케이션 대상 설정 (예: Pages)
1. **준비**:
- 대상 앱 (예: Pages)을 별도의 디렉토리 (예: `/tmp/`)에 복사합니다.
- Gatekeeper 문제를 우회하고 캐시하기 위해 앱을 시작합니다.

2. **NIB 파일 덮어쓰기**:
- 기존의 NIB 파일 (예: About Panel NIB)을 조작된 DirtyNIB 파일로 대체합니다.

3. **실행**:
- 앱과 상호작용하여 실행을 트리거합니다 (예: `About` 메뉴 항목 선택).

#### 개념 증명: 사용자 데이터 접근
- AppleScript를 수정하여 사용자 동의 없이 사진과 같은 사용자 데이터에 접근하고 추출합니다.

### 코드 샘플: 악성 .xib 파일
- 임의의 코드를 실행하는 [**악성 .xib 파일 샘플**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)에 접근하고 검토합니다.

### 실행 제약 조건 해결
- 실행 제약 조건은 예기치 않은 위치 (예: `/tmp`)에서 앱 실행을 방지합니다.
- 실행 제약 조건에 보호되지 않은 앱을 식별하고 NIB 파일 삽입을 위해 대상으로 지정할 수 있습니다.

### 추가적인 macOS 보호 기능
macOS Sonoma 이후로 앱 번들 내에서의 수정이 제한됩니다. 그러나 이전 방법은 다음과 같습니다:
1. 앱을 다른 위치 (예: `/tmp/`)로 복사합니다.
2. 초기 보호를 우회하기 위해 앱 번들 내의 디렉토리 이름을 변경합니다.
3. Gatekeeper에 등록하기 위해 앱을 실행한 후, 앱 번들을 수정합니다 (예: MainMenu.nib을 Dirty.nib로 대체).
4. 디렉토리 이름을 다시 변경하고 주입된 NIB 파일을 실행하기 위해 앱을 다시 실행합니다.

**참고**: 최근 macOS 업데이트에서는 Gatekeeper 캐싱 이후 앱 번들 내의 파일 수정을 방지하여 이 취약점을 완화시켰습니다.

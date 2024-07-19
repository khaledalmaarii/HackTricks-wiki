# macOS Dirty NIB

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**기술에 대한 자세한 내용은 원본 게시물을 확인하세요: [https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/).** 요약은 다음과 같습니다:

NIB 파일은 Apple의 개발 생태계의 일부로, 애플리케이션에서 **UI 요소**와 그 상호작용을 정의하는 데 사용됩니다. 이들은 창 및 버튼과 같은 직렬화된 객체를 포함하며, 런타임에 로드됩니다. 지속적으로 사용되고 있지만, Apple은 이제 더 포괄적인 UI 흐름 시각화를 위해 Storyboards를 권장합니다.

### NIB 파일의 보안 문제
**NIB 파일은 보안 위험이 될 수 있습니다**. 이들은 **임의의 명령을 실행할 수 있는 잠재력**을 가지고 있으며, 앱 내 NIB 파일의 변경은 Gatekeeper가 앱을 실행하는 것을 방해하지 않아 상당한 위협이 됩니다.

### 더러운 NIB 주입 프로세스
#### NIB 파일 생성 및 설정
1. **초기 설정**:
- XCode를 사용하여 새 NIB 파일을 생성합니다.
- 인터페이스에 객체를 추가하고, 그 클래스는 `NSAppleScript`로 설정합니다.
- 사용자 정의 런타임 속성을 통해 초기 `source` 속성을 구성합니다.

2. **코드 실행 가젯**:
- 이 설정은 필요에 따라 AppleScript를 실행할 수 있게 합니다.
- `Apple Script` 객체를 활성화하는 버튼을 통합하여 `executeAndReturnError:` 선택자를 트리거합니다.

3. **테스트**:
- 테스트 목적으로 간단한 Apple Script:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
- XCode 디버거에서 실행하고 버튼을 클릭하여 테스트합니다.

#### 애플리케이션 타겟팅 (예: Pages)
1. **준비**:
- 타겟 앱(예: Pages)을 별도의 디렉토리(예: `/tmp/`)로 복사합니다.
- Gatekeeper 문제를 피하고 캐시를 위해 앱을 시작합니다.

2. **NIB 파일 덮어쓰기**:
- 기존 NIB 파일(예: About Panel NIB)을 제작한 DirtyNIB 파일로 교체합니다.

3. **실행**:
- 앱과 상호작용하여 실행을 트리거합니다(예: `About` 메뉴 항목 선택).

#### 개념 증명: 사용자 데이터 접근
- 사용자 동의 없이 사진과 같은 사용자 데이터를 접근하고 추출하도록 AppleScript를 수정합니다.

### 코드 샘플: 악성 .xib 파일
- 임의의 코드를 실행하는 [**악성 .xib 파일 샘플**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)을 접근하고 검토합니다.

### 실행 제약 해결
- 실행 제약은 예상치 못한 위치(예: `/tmp`)에서 앱 실행을 방해합니다.
- 실행 제약으로 보호되지 않는 앱을 식별하고 NIB 파일 주입을 위해 타겟팅할 수 있습니다.

### 추가 macOS 보호 조치
macOS Sonoma 이후, 앱 번들 내 수정이 제한됩니다. 그러나 이전 방법은 다음을 포함했습니다:
1. 앱을 다른 위치(예: `/tmp/`)로 복사합니다.
2. 초기 보호를 우회하기 위해 앱 번들 내 디렉토리 이름을 변경합니다.
3. Gatekeeper에 등록하기 위해 앱을 실행한 후, 앱 번들을 수정합니다(예: MainMenu.nib를 Dirty.nib로 교체).
4. 디렉토리 이름을 다시 변경하고 앱을 재실행하여 주입된 NIB 파일을 실행합니다.

**참고**: 최근 macOS 업데이트는 Gatekeeper 캐싱 후 앱 번들 내 파일 수정을 방지하여 이 익스플로잇을 무효화했습니다.


{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

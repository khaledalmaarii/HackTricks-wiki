# macOS Apple Scripts

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## Apple Scripts

이것은 원격 프로세스와 상호 작용하기 위해 사용되는 스크립팅 언어입니다. 다른 프로세스에게 일부 동작을 수행하도록 요청하는 것이 매우 쉽습니다. **악성 소프트웨어**는 다른 프로세스가 내보내는 기능을 악용할 수 있습니다.\
예를 들어, 악성 소프트웨어는 브라우저에서 열린 페이지에 임의의 JS 코드를 **주입**할 수 있습니다. 또는 사용자에게 요청된 허용 권한을 **자동으로 클릭**할 수 있습니다.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
다음은 몇 가지 예시입니다: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
애플스크립트를 사용한 악성 소프트웨어에 대한 자세한 정보는 [**여기**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)에서 찾을 수 있습니다.

애플스크립트는 쉽게 "**컴파일**"될 수 있습니다. 이러한 버전은 `osadecompile`을 사용하여 쉽게 "**디컴파일**"될 수 있습니다.

그러나 이 스크립트는 "읽기 전용"으로도 **내보낼 수 있습니다** (옵션 "내보내기..."를 통해):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
그리고 이 경우에는 `osadecompile`로도 내용을 디컴파일 할 수 없습니다.

그러나 여전히 이러한 종류의 실행 파일을 이해하는 데 사용할 수 있는 몇 가지 도구가 있습니다. [**더 많은 정보를 보려면 이 연구를 읽어보세요**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) 도구와 [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile)를 사용하면 스크립트가 어떻게 작동하는지 이해하는 데 매우 유용할 것입니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

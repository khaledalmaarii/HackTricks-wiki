# 메모리 덤프 분석

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 또는 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 중요한 사이버 보안 행사 중 하나로 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술적인 지식을 촉진하는 미션**을 가지고 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 끓어오르는 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

## 시작하기

pcap 내부에서 **악성 코드**를 **검색**해보세요. [**악성 코드 분석**](../malware-analysis.md)에서 언급된 **도구**를 사용하세요.

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility는 메모리 덤프 분석을 위한 주요 오픈 소스 프레임워크**입니다. 이 Python 도구는 외부 소스 또는 VMware VM의 덤프를 분석하여 덤프의 OS 프로파일을 기반으로 프로세스 및 비밀번호와 같은 데이터를 식별합니다. 플러그인을 사용하여 확장 가능하므로 포렌식 조사에 매우 유연하게 사용할 수 있습니다.

**[여기에서 cheatsheet를 찾아보세요](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**


## 미니 덤프 충돌 보고서

덤프가 작을 경우 (몇 KB 또는 몇 MB) 미니 덤프 충돌 보고서일 가능성이 높습니다.

![](<../../../.gitbook/assets/image (216).png>)

Visual Studio를 설치한 경우이 파일을 열고 프로세스 이름, 아키텍처, 예외 정보 및 실행 중인 모듈과 같은 기본 정보를 바인딩 할 수 있습니다.

![](<../../../.gitbook/assets/image (217).png>)

예외를 로드하고 디컴파일된 명령을 확인할 수도 있습니다.

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

어쨌든, Visual Studio는 덤프의 깊이를 분석하기에는 최적의 도구가 아닙니다.

덤프를 **IDA** 또는 **Radare**를 사용하여 깊이 있는 검사를 수행해야 합니다.



​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 중요한 사이버 보안 행사 중 하나로 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술적인 지식을 촉진하는 미션**을 가지고 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 끓어오르는 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 또는 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

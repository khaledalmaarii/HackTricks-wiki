# 메모리 덤프 분석

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)로부터 **제로**부터 **히어로**가 되는 **AWS 해킹** 배우기</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에 귀사를 광고**하고 싶으신가요? 혹은 **PEASS의 최신 버전에 액세스**하거나 **HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 얻으세요
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 트릭을 공유하고 PR을 제출하여** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 참여**하세요.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 중요한 사이버 보안 이벤트 중 하나이며 **유럽**에서 가장 중요한 이벤트 중 하나입니다. **기술 지식을 촉진하는 미션**을 가지고 있는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들을 위한 뜨거운 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

## 시작

pcap 내부에서 **악성 코드**를 **검색**하기 시작하세요. [**악성 코드 분석**](../malware-analysis.md)에서 언급된 **도구**를 사용하세요.

## [Volatility](volatility-cheatsheet.md)

**Volatility는 메모리 덤프 분석을 위한 주요 오픈 소스 프레임워크**입니다. 이 Python 도구는 외부 소스 또는 VMware VM의 덤프를 분석하여 덤프의 OS 프로필에 따라 프로세스 및 암호와 같은 데이터를 식별합니다. 플러그인으로 확장 가능하여 포렌식 조사에 매우 다재다능합니다.

[**여기에서 치트 시트를 찾을 수 있습니다**](volatility-cheatsheet.md)

## 미니 덤프 충돌 보고서

덤프가 작을 때(몇 KB, 아마도 몇 MB)라면 미니 덤프 충돌 보고서이며 메모리 덤프가 아닙니다.

![](<../../../.gitbook/assets/image (532).png>)

Visual Studio가 설치되어 있다면 이 파일을 열어 프로세스 이름, 아키텍처, 예외 정보 및 실행 중인 모듈과 같은 기본 정보를 바인딩할 수 있습니다.

![](<../../../.gitbook/assets/image (263).png>)

예외를 로드하고 디컴파일된 명령을 볼 수도 있습니다.

![](<../../../.gitbook/assets/image (142).png>)

![](<../../../.gitbook/assets/image (610).png>)

어쨌든, Visual Studio는 덤프의 심도 분석을 수행하기에는 최적의 도구가 아닙니다.

덤프를 **깊이 검사**하기 위해 **IDA** 또는 **Radare**를 사용하여 열어야 합니다.

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 중요한 사이버 보안 이벤트 중 하나이며 **유럽**에서 가장 중요한 이벤트 중 하나입니다. **기술 지식을 촉진하는 미션**을 가지고 있는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들을 위한 뜨거운 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)로부터 **제로**부터 **히어로**가 되는 **AWS 해킹** 배우기</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에 귀사를 광고**하고 싶으신가요? 혹은 **PEASS의 최신 버전에 액세스**하거나 **HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 얻으세요
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 트릭을 공유하고 PR을 제출하여** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 참여**하세요.

</details>

# 메모리 덤프 분석

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성이 높은 사이버 보안 이벤트이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술 지식 증진**을 목표로 하는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들이 모이는 뜨거운 만남의 장소입니다.

{% embed url="https://www.rootedcon.com/" %}

## 시작

pcap 내에서 **악성코드**를 **검색**하기 시작하세요. [**악성코드 분석**](../malware-analysis.md)에서 언급된 **도구**를 사용하세요.

## [볼라틸리티](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**볼라틸리티는 메모리 덤프 분석을 위한 주요 오픈 소스 프레임워크입니다**. 이 Python 도구는 외부 소스 또는 VMware VM에서 덤프를 분석하여 덤프의 OS 프로필에 따라 프로세스 및 비밀번호와 같은 데이터를 식별합니다. 플러그인으로 확장 가능하여 포렌식 조사에 매우 유용합니다.

**[여기에서 치트시트를 찾으세요](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## 미니 덤프 크래시 보고서

덤프가 작을 경우(몇 KB 또는 몇 MB 정도) 이는 아마도 미니 덤프 크래시 보고서일 것이며 메모리 덤프가 아닙니다.

![](<../../../.gitbook/assets/image (216).png>)

Visual Studio가 설치되어 있다면 이 파일을 열어 프로세스 이름, 아키텍처, 예외 정보 및 실행 중인 모듈과 같은 기본 정보를 바인딩할 수 있습니다:

![](<../../../.gitbook/assets/image (217).png>)

예외를 로드하고 디컴파일된 명령어를 볼 수도 있습니다.

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

어쨌든, Visual Studio는 덤프의 깊이 있는 분석을 수행하기 위한 최상의 도구가 아닙니다.

**IDA** 또는 **Radare**를 사용하여 **깊이** 있게 검사해야 합니다.

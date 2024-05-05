# 오피스 파일 분석

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **해킹 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 **가장 고급**한 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

추가 정보는 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)에서 확인하세요. 이것은 간략한 내용입니다:

마이크로소프트는 많은 오피스 문서 형식을 만들었는데, 주요 유형은 **OLE 형식** (예: RTF, DOC, XLS, PPT)과 **Office Open XML (OOXML) 형식** (예: DOCX, XLSX, PPTX)이 있습니다. 이러한 형식에는 매크로가 포함될 수 있어서 피싱 및 악성 코드의 대상이 됩니다. OOXML 파일은 zip 컨테이너로 구조화되어 있어서 압축 해제를 통해 파일 및 폴더 계층 구조 및 XML 파일 내용을 확인할 수 있습니다.

OOXML 파일 구조를 탐색하기 위해 문서를 압축 해제하는 명령어와 출력 구조가 제공됩니다. 이러한 파일에 데이터를 숨기는 기술이 문서화되어 있으며, CTF 도전 과제 내에서 데이터 숨김에 대한 지속적인 혁신을 나타냅니다.

분석을 위해 **oletools** 및 **OfficeDissector**는 OLE 및 OOXML 문서를 조사하기 위한 포괄적인 도구 세트를 제공합니다. 이 도구들은 포함된 매크로를 식별하고 분석하는 데 도움이 되며, 이러한 매크로는 주로 악성 코드 전달을 위한 벡터로 사용되어 일반적으로 추가 악성 페이로드를 다운로드하고 실행합니다. VBA 매크로의 분석은 Microsoft Office를 사용하지 않고 Libre Office를 활용하여 디버깅을 허용하므로 중단점 및 감시 변수로 디버깅할 수 있습니다.

**oletools**의 설치 및 사용법은 간단하며, pip를 통해 설치하고 문서에서 매크로를 추출하는 명령이 제공됩니다. `AutoOpen`, `AutoExec`, 또는 `Document_Open`과 같은 함수에 의해 매크로의 자동 실행이 트리거됩니다.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com) 받기
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)인 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션 발견
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

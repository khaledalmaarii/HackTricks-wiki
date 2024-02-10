# 오피스 파일 분석

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급**한 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}


자세한 정보는 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)를 확인하세요. 이것은 요약입니다:


마이크로소프트는 많은 오피스 문서 형식을 만들었으며, 주요 유형은 **OLE 형식** (예: RTF, DOC, XLS, PPT)과 **Office Open XML (OOXML) 형식** (예: DOCX, XLSX, PPTX)입니다. 이러한 형식은 매크로를 포함할 수 있으므로 피싱 및 악성 소프트웨어의 대상이 됩니다. OOXML 파일은 zip 컨테이너로 구조화되어 있어 압축 해제를 통해 검사하고 파일 및 폴더 계층 구조 및 XML 파일 내용을 확인할 수 있습니다.

OOXML 파일 구조를 탐색하기 위해 문서를 압축 해제하는 명령과 출력 구조가 제공됩니다. 이러한 파일에 데이터를 숨기는 기술은 문제 해결 도전에서 데이터 숨김에 대한 지속적인 혁신을 나타냅니다.

분석을 위해 **oletools**와 **OfficeDissector**는 OLE 및 OOXML 문서를 조사하기 위한 포괄적인 도구 세트를 제공합니다. 이러한 도구는 포함된 매크로를 식별하고 분석하는 데 도움이 됩니다. 매크로는 일반적으로 악성 소프트웨어 전달의 벡터로 사용되며, 일반적으로 추가 악성 페이로드를 다운로드하고 실행합니다. VBA 매크로의 분석은 Microsoft Office를 사용하지 않고 Libre Office를 활용하여 중단점 및 감시 변수로 디버깅할 수 있습니다.

**oletools**의 설치와 사용은 간단하며, pip를 통해 설치하는 명령과 문서에서 매크로를 추출하는 명령이 제공됩니다. `AutoOpen`, `AutoExec`, 또는 `Document_Open`과 같은 함수로 자동으로 매크로를 실행할 수 있습니다.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급**한 커뮤니티 도구로 구동되는 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 PR을 제출**하세요.

</details>

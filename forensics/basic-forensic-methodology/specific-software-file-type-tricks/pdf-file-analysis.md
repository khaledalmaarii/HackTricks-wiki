# PDF 파일 분석

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 여러분의 해킹 기법을 공유하세요.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하여 세계에서 가장 고급스러운 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**할 수 있습니다.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

**자세한 내용은 다음을 참조하세요: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)**

PDF 형식은 복잡성과 데이터를 숨길 수 있는 잠재력으로 알려져 있어 CTF 포렌식 도전 과제의 중점이 됩니다. 이는 일반 텍스트 요소와 이진 객체를 결합할 수 있으며, 압축되거나 암호화될 수 있으며 JavaScript 또는 Flash와 같은 언어로 된 스크립트를 포함할 수 있습니다. PDF 구조를 이해하기 위해 Didier Stevens의 [입문 자료](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)나 텍스트 편집기 또는 Origami와 같은 PDF 전용 편집기와 같은 도구를 사용할 수 있습니다.

PDF의 깊은 탐색 또는 조작을 위해 [qpdf](https://github.com/qpdf/qpdf)와 [Origami](https://github.com/mobmewireless/origami-pdf)와 같은 도구를 사용할 수 있습니다. PDF 내에 숨겨진 데이터는 다음과 같이 숨겨질 수 있습니다:

* 보이지 않는 레이어
* Adobe의 XMP 메타데이터 형식
* 증분 세대
* 배경과 동일한 색상의 텍스트
* 이미지 뒤에 있는 텍스트 또는 이미지와 겹치는 텍스트
* 표시되지 않는 주석

사용자 정의 PDF 분석을 위해 [PeepDF](https://github.com/jesparza/peepdf)와 같은 Python 라이브러리를 사용하여 맞춤형 파싱 스크립트를 작성할 수 있습니다. 또한 PDF의 숨겨진 데이터 저장 가능성은 NSA의 PDF 위험 및 대응책 가이드와 같은 리소스가 여전히 가치 있는 통찰력을 제공합니다. 가이드의 [사본](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)과 Ange Albertini의 [PDF 형식 트릭](https://github.com/corkami/docs/blob/master/PDF/PDF.md) 컬렉션은 이 주제에 대한 추가 독서 자료를 제공할 수 있습니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 **PR을 제출**하여 여러분의 해킹 기법을 공유하세요.

</details>

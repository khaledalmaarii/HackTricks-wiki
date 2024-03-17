# PDF 파일 분석

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 PDF로 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **해킹 요령을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급 커뮤니티 도구**를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

**자세한 내용은 여기를 확인하세요:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDF 형식은 데이터를 숨기는 데 있어 복잡성과 잠재력으로 알려져 있어 CTF 포렌식 도전 과제의 중심이 됩니다. 이는 이진 객체와 함께 평문 요소를 결합하며, 압축되거나 암호화된 이진 객체를 포함할 수 있으며, JavaScript 또는 Flash와 같은 언어로 된 스크립트를 포함할 수 있습니다. PDF 구조를 이해하기 위해 Didier Stevens의 [입문 자료](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)를 참조하거나 Origami와 같은 텍스트 편집기 또는 PDF 전용 편집기와 같은 도구를 사용할 수 있습니다.

PDF의 심층적인 탐색 또는 조작을 위해 [qpdf](https://github.com/qpdf/qpdf) 및 [Origami](https://github.com/mobmewireless/origami-pdf)와 같은 도구를 사용할 수 있습니다. PDF 내의 숨겨진 데이터는 다음 위치에 숨겨질 수 있습니다:

* 보이지 않는 레이어
* Adobe의 XMP 메타데이터 형식
* 증분 세대
* 배경과 동일한 색상의 텍스트
* 이미지 뒤에 있는 텍스트 또는 이미지와 겹치는 텍스트
* 표시되지 않는 주석

사용자 정의 PDF 분석을 위해 [PeepDF](https://github.com/jesparza/peepdf)와 같은 Python 라이브러리를 사용하여 맞춤형 구문 분석 스크립트를 작성할 수 있습니다. 또한 PDF의 숨겨진 데이터 저장 가능성이 매우 크기 때문에 NSA의 PDF 위험 및 대책 가이드와 같은 자원은 원래 위치에서 더 이상 호스팅되지 않지만 가치 있는 통찰을 제공합니다. Ange Albertini의 [가이드 사본](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) 및 [PDF 형식 요령](https://github.com/corkami/docs/blob/master/PDF/PDF.md) 컬렉션은 해당 주제에 대한 추가 독서 자료를 제공할 수 있습니다. 

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 PDF로 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **해킹 요령을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

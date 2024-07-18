# PDF 파일 분석

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=pdf-file-analysis)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 **워크플로우**를 쉽게 구축하고 **자동화**하세요.\
오늘 바로 접근하세요:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=pdf-file-analysis" %}

**자세한 내용은 다음을 확인하세요:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDF 형식은 복잡성과 데이터를 숨길 수 있는 잠재력으로 잘 알려져 있어 CTF 포렌식 챌린지의 중심이 됩니다. PDF는 일반 텍스트 요소와 이진 객체를 결합하며, 이는 압축되거나 암호화될 수 있고 JavaScript 또는 Flash와 같은 언어의 스크립트를 포함할 수 있습니다. PDF 구조를 이해하기 위해 Didier Stevens의 [소개 자료](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)를 참조하거나 텍스트 편집기 또는 Origami와 같은 PDF 전용 편집기를 사용할 수 있습니다.

PDF를 심층적으로 탐색하거나 조작하기 위해 [qpdf](https://github.com/qpdf/qpdf) 및 [Origami](https://github.com/mobmewireless/origami-pdf)와 같은 도구를 사용할 수 있습니다. PDF 내 숨겨진 데이터는 다음에 숨겨져 있을 수 있습니다:

* 보이지 않는 레이어
* Adobe의 XMP 메타데이터 형식
* 점진적 생성
* 배경과 같은 색상의 텍스트
* 이미지 뒤의 텍스트 또는 겹치는 이미지
* 표시되지 않는 주석

맞춤형 PDF 분석을 위해 [PeepDF](https://github.com/jesparza/peepdf)와 같은 Python 라이브러리를 사용하여 맞춤형 파싱 스크립트를 작성할 수 있습니다. 또한 PDF의 숨겨진 데이터 저장 가능성은 매우 방대하여, 원래 위치에서 더 이상 호스팅되지 않지만 PDF 위험 및 대응 조치에 대한 NSA 가이드와 같은 자료는 여전히 귀중한 통찰력을 제공합니다. [가이드의 사본](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%Bútmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)과 Ange Albertini의 [PDF 형식 트릭 모음](https://github.com/corkami/docs/blob/master/PDF/PDF.md)은 이 주제에 대한 추가 읽기를 제공할 수 있습니다.

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}

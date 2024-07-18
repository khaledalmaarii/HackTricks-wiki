# Office file analysis

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

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). This is just a sumary:

Microsoft는 많은 오피스 문서 형식을 만들었으며, 두 가지 주요 유형은 **OLE 형식**(RTF, DOC, XLS, PPT와 같은)과 **Office Open XML (OOXML) 형식**(DOCX, XLSX, PPTX와 같은)입니다. 이러한 형식은 매크로를 포함할 수 있어 피싱 및 악성 소프트웨어의 표적이 됩니다. OOXML 파일은 zip 컨테이너로 구조화되어 있어 압축 해제를 통해 파일 및 폴더 계층과 XML 파일 내용을 확인할 수 있습니다.

OOXML 파일 구조를 탐색하기 위해 문서를 압축 해제하는 명령과 출력 구조가 제공됩니다. 이러한 파일에 데이터를 숨기는 기술이 문서화되어 있으며, CTF 도전 과제 내에서 데이터 은닉에 대한 지속적인 혁신을 나타냅니다.

분석을 위해 **oletools**와 **OfficeDissector**는 OLE 및 OOXML 문서를 검사하기 위한 포괄적인 도구 세트를 제공합니다. 이러한 도구는 종종 악성 소프트웨어 배포의 벡터 역할을 하는 내장 매크로를 식별하고 분석하는 데 도움을 줍니다. VBA 매크로 분석은 Libre Office를 활용하여 Microsoft Office 없이 수행할 수 있으며, 이는 중단점 및 감시 변수를 사용한 디버깅을 허용합니다.

**oletools**의 설치 및 사용은 간단하며, pip를 통해 설치하고 문서에서 매크로를 추출하는 명령이 제공됩니다. 매크로의 자동 실행은 `AutoOpen`, `AutoExec` 또는 `Document_Open`과 같은 기능에 의해 트리거됩니다.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 구동되는 **워크플로우**를 쉽게 구축하고 **자동화**하세요.\
지금 바로 접근하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 **팔로우**하세요.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}

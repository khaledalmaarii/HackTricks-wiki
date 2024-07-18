# ZIPs 트릭

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}

**명령줄 도구**를 사용하여 **zip 파일**을 관리하는 것은 zip 파일의 진단, 복구 및 해독에 필수적입니다. 다음은 몇 가지 주요 유틸리티입니다:

- **`unzip`**: zip 파일이 압축 해제되지 않는 이유를 밝혀줍니다.
- **`zipdetails -v`**: zip 파일 형식 필드의 상세 분석을 제공합니다.
- **`zipinfo`**: zip 파일의 내용을 추출하지 않고 나열합니다.
- **`zip -F input.zip --out output.zip`** 및 **`zip -FF input.zip --out output.zip`**: 손상된 zip 파일을 복구하려고 시도합니다.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip 암호를 무력화하는 브루트 포스 크래킹 도구로, 약 7자 이내의 암호에 효과적입니다.

[Zip 파일 형식 명세](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)는 zip 파일의 구조 및 표준에 대한 포괄적인 세부 정보를 제공합니다.

암호로 보호된 zip 파일은 내부의 파일 이름이나 파일 크기를 **암호화하지 않는다는 점**을 주목해야 합니다. 이는 RAR 또는 7z 파일과 공유되지 않는 보안 결함입니다. 또한, 이전 ZipCrypto 방법으로 암호화된 zip 파일은 압축 파일의 암호가 해독되지 않은 복사본이 있는 경우 **평문 공격**에 취약합니다. 이 공격은 알려진 콘텐츠를 활용하여 zip 파일의 암호를 크래킹하는데 사용되며, 이 취약점은 [HackThis의 기사](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)에서 자세히 설명되어 있으며, [이 학술 논문](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf)에서 더 자세히 설명되어 있습니다. 그러나 **AES-256** 암호화로 보호된 zip 파일은 이 평문 공격에 면역이며, 민감한 데이터에 대해 안전한 암호화 방법을 선택하는 중요성을 보여줍니다.

## 참고 자료
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}

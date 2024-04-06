# ZIP 트릭

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 PDF로 HackTricks를 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 트릭을 공유하세요.

</details>

**ZIP 파일**을 관리하기 위한 **명령 줄 도구**는 ZIP 파일의 진단, 복구 및 크랙에 필수적입니다. 다음은 몇 가지 주요 유틸리티입니다:

- **`unzip`**: ZIP 파일이 압축 해제되지 않을 수 있는 이유를 알려줍니다.
- **`zipdetails -v`**: ZIP 파일 형식 필드에 대한 자세한 분석을 제공합니다.
- **`zipinfo`**: ZIP 파일의 내용을 추출하지 않고 목록으로 표시합니다.
- **`zip -F input.zip --out output.zip`** 및 **`zip -FF input.zip --out output.zip`**: 손상된 ZIP 파일을 복구하려고 시도합니다.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ZIP 비밀번호의 브루트 포스 크랙을 위한 도구로, 약 7자리까지의 비밀번호에 효과적입니다.

[ZIP 파일 형식 사양](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)은 ZIP 파일의 구조와 표준에 대한 포괄적인 세부 정보를 제공합니다.

암호로 보호된 ZIP 파일은 내부의 파일 이름이나 파일 크기를 **암호화하지 않는다는 점**을 꼭 기억해야 합니다. 이는 RAR 또는 7z 파일과는 달리 이 정보를 암호화하지 않는 보안 결함입니다. 또한, 이전의 ZipCrypto 방법으로 암호화된 ZIP 파일은 압축 파일의 암호화되지 않은 복사본이 있는 경우 **평문 공격**에 취약합니다. 이 공격은 알려진 내용을 활용하여 ZIP의 비밀번호를 크랙하는 것으로, [HackThis의 기사](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)에서 자세히 설명되었으며, [이 학술 논문](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf)에서 더 자세히 설명되었습니다. 그러나 **AES-256** 암호화로 보호된 ZIP 파일은 이 평문 공격에 면역이므로, 민감한 데이터에 대해 안전한 암호화 방법을 선택하는 것의 중요성을 보여줍니다.

## 참고 자료
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 PDF로 HackTricks를 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 트릭을 공유하세요.

</details>

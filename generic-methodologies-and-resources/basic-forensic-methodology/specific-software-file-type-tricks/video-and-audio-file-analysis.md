<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

**오디오 및 비디오 파일 조작**은 **CTF 포렌식 도전과제**에서 흔히 사용되며, **스테가노그래피**와 메타데이터 분석을 활용하여 비밀 메시지를 숨기거나 드러내는 데 사용됩니다. **[mediainfo](https://mediaarea.net/en/MediaInfo)**와 **`exiftool`**과 같은 도구는 파일 메타데이터를 검사하고 콘텐츠 유형을 식별하는 데 필수적입니다.

오디오 도전과제의 경우, 텍스트를 오디오에 인코딩하는 데 필수적인 파형 및 스펙트로그램을 보는 데 주로 사용되는 주요 도구인 **[Audacity](http://www.audacityteam.org/)**가 돋보입니다. 자세한 스펙트로그램 분석을 위해 **[Sonic Visualiser](http://www.sonicvisualiser.org/)**를 강력히 추천합니다. **Audacity**는 음성 메시지를 감지하기 위해 트랙을 감속하거나 반전하는 등의 오디오 조작을 허용합니다. 오디오 파일의 변환 및 편집에는 명령 줄 유틸리티인 **[Sox](http://sox.sourceforge.net/)**가 뛰어납니다.

**최하위 비트 (LSB)** 조작은 오디오 및 비디오 스테가노그래피에서 흔히 사용되는 기술로, 미디어 파일의 고정 크기 청크를 이용하여 데이터를 은밀하게 포함시킵니다. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)**는 **DTMF 톤**이나 **모스 부호**로 숨겨진 메시지를 해독하는 데 유용합니다.

비디오 도전과제는 종종 오디오 및 비디오 스트림을 번들로 포함하는 컨테이너 형식을 포함합니다. **[FFmpeg](http://ffmpeg.org/)**는 이러한 형식을 분석하고 조작하는 데 가장 많이 사용되며, 다중화 및 콘텐츠 재생이 가능합니다. 개발자를 위해 **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)**는 Python에서 FFmpeg의 기능을 고급 스크립트 상호작용을 위해 통합합니다.

이러한 도구들의 다양성은 CTF 도전과제에서 요구되는 다양한 분석 및 조작 기술을 활용하여 오디오 및 비디오 파일 내에 숨겨진 데이터를 발견해야 하는 능력을 강조합니다.

## 참고 자료
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

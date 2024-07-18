{% hint style="success" %}
**오디오 및 비디오 파일 조작**은 **CTF 포렌식 도전 과제**에서 핵심 요소로, **스테가노그래피** 및 메타데이터 분석을 활용하여 비밀 메시지를 숨기거나 드러내는 데 사용됩니다. **[mediainfo](https://mediaarea.net/en/MediaInfo)** 및 **`exiftool`**과 같은 도구는 파일 메타데이터를 검사하고 콘텐츠 유형을 식별하는 데 필수적입니다.

오디오 도전 과제의 경우 **[Audacity](http://www.audacityteam.org/)**는 오디오에 인코딩된 텍스트를 발견하는 데 필수적인 파형 및 스펙트로그램 분석을 위한 주요 도구로 두드러집니다. **[Sonic Visualiser](http://www.sonicvisualiser.org/)**는 자세한 스펙트로그램 분석을 위해 강력히 추천됩니다. **Audacity**는 숨겨진 메시지를 감지하기 위해 트랙을 감속하거나 반전하는 등의 오디오 조작을 허용합니다. **[Sox](http://sox.sourceforge.net/)**는 오디오 파일의 변환 및 편집에 뛰어난 명령줄 유틸리티입니다.

**최하위 비트 (LSB)** 조작은 오디오 및 비디오 스테가노그래피에서 흔한 기술로, 미디어 파일의 고정 크기 청크를 이용하여 데이터를 비밀리에 삽입합니다. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)**는 **DTMF 톤** 또는 **모스 부호**로 숨겨진 메시지를 해독하는 데 유용합니다.

비디오 도전 과제는 오디오 및 비디오 스트림을 번들로 제공하는 컨테이너 형식을 자주 포함합니다. **[FFmpeg](http://ffmpeg.org/)**는 이러한 형식을 분석하고 조작하는 데 사용되며, 디멀티플렉싱 및 콘텐츠 재생이 가능합니다. 개발자를 위해 **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)**는 Python으로 FFmpeg의 기능을 통합하여 고급 스크립트 상호작용을 제공합니다.

이러한 도구 집합은 CTF 도전 과제에서 필요한 다양성을 강조하며, 참가자들은 오디오 및 비디오 파일 내에 숨겨진 데이터를 발견하기 위해 다양한 분석 및 조작 기술을 사용해야 합니다.

## 참고 자료
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)
{% endhint %}

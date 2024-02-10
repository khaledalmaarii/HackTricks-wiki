# 스테고 트릭

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정하세요. Intruder는 공격 대상을 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **파일에서 데이터 추출하기**

### **Binwalk**
임베디드된 숨겨진 파일과 데이터를 찾기 위한 이진 파일 검색 도구입니다. `apt`를 통해 설치되며 소스는 [GitHub](https://github.com/ReFirmLabs/binwalk)에서 사용할 수 있습니다.
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**
헤더와 푸터를 기반으로 파일을 복구하여 png 이미지에 유용합니다. [GitHub](https://github.com/korczis/foremost)에서 소스를 사용하여 `apt`를 통해 설치됩니다.
```bash
foremost -i file # Extracts data
```
### **Exiftool**
파일 메타데이터를 확인하는 데 도움이 되는 도구입니다. [여기](https://www.sno.phy.queensu.ca/~phil/exiftool/)에서 사용할 수 있습니다.
```bash
exiftool file # Shows the metadata
```
### **Exiv2**
exiftool과 유사한 메타데이터 뷰어입니다. `apt`를 통해 설치할 수 있으며, [GitHub](https://github.com/Exiv2/exiv2)에서 소스를 찾을 수 있으며, [공식 웹사이트](http://www.exiv2.org/)도 있습니다.
```bash
exiv2 file # Shows the metadata
```
### **파일**
다루고 있는 파일의 유형을 식별합니다.

### **문자열**
파일에서 읽을 수 있는 문자열을 추출하며, 출력을 필터링하기 위해 다양한 인코딩 설정을 사용합니다.
```bash
strings -n 6 file # Extracts strings with a minimum length of 6
strings -n 6 file | head -n 20 # First 20 strings
strings -n 6 file | tail -n 20 # Last 20 strings
strings -e s -n 6 file # 7bit strings
strings -e S -n 6 file # 8bit strings
strings -e l -n 6 file # 16bit strings (little-endian)
strings -e b -n 6 file # 16bit strings (big-endian)
strings -e L -n 6 file # 32bit strings (little-endian)
strings -e B -n 6 file # 32bit strings (big-endian)
```
### **비교 (cmp)**
수정된 파일을 온라인에서 찾은 원본 버전과 비교하는 데 유용합니다.
```bash
cmp original.jpg stego.jpg -b -l
```
## **텍스트에서 숨겨진 데이터 추출하기**

### **공백에 숨겨진 데이터**
보이지 않는 문자들이 비어있는 공백에 숨겨져 있을 수 있습니다. 이 데이터를 추출하기 위해서는 [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)를 방문하세요.



***

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급스러운** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**할 수 있습니다.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

## **이미지에서 데이터 추출하기**

### **GraphicMagick을 사용하여 이미지 세부 정보 식별하기**

[GraphicMagick](https://imagemagick.org/script/download.php)은 이미지 파일 유형을 결정하고 잠재적인 손상을 식별하는 데 사용됩니다. 아래 명령을 실행하여 이미지를 검사하세요:
```bash
./magick identify -verbose stego.jpg
```
손상된 이미지를 복구하려면 메타데이터 주석을 추가하는 것이 도움이 될 수 있습니다:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **데이터 은닉을 위한 Steghide**

Steghide는 `JPEG, BMP, WAV, AU` 파일에 데이터를 숨기는 기능을 제공하며, 암호화된 데이터를 포함하고 추출할 수 있습니다. 설치는 `apt`를 사용하여 간단하게 할 수 있으며, [GitHub에서 소스 코드를 사용할 수 있습니다](https://github.com/StefanoDeVuono/steghide).

**명령어:**
- `steghide info file`은 파일에 숨겨진 데이터가 있는지 확인합니다.
- `steghide extract -sf file [--passphrase password]`은 숨겨진 데이터를 추출하며, 비밀번호는 선택 사항입니다.

웹 기반 추출을 위해서는 [이 웹사이트](https://futureboy.us/stegano/decinput.html)를 방문하십시오.

**Stegcracker를 사용한 무차별 대입 공격:**
- Steghide에서 비밀번호 크래킹을 시도하려면 [stegcracker](https://github.com/Paradoxis/StegCracker.git)를 다음과 같이 사용하십시오:
```bash
stegcracker <file> [<wordlist>]
```
### **PNG 및 BMP 파일에 대한 zsteg**

zsteg는 PNG 및 BMP 파일에서 숨겨진 데이터를 찾는 데 특화되어 있습니다. 설치는 `gem install zsteg`를 통해 수행되며, [GitHub에서 소스](https://github.com/zed-0xff/zsteg)를 확인할 수 있습니다.

**명령어:**
- `zsteg -a 파일`은 파일에 모든 탐지 방법을 적용합니다.
- `zsteg -E 파일`은 데이터 추출을 위한 페이로드를 지정합니다.

### **StegoVeritas 및 Stegsolve**

**stegoVeritas**는 메타데이터를 확인하고 이미지 변환을 수행하며, LSB 무차별 대입 등의 기능을 제공합니다. 모든 옵션을 확인하려면 `stegoveritas.py -h`를 사용하고, 모든 검사를 실행하려면 `stegoveritas.py stego.jpg`를 사용하세요.

**Stegsolve**는 다양한 색상 필터를 적용하여 이미지 내에 숨겨진 텍스트나 메시지를 확인할 수 있습니다. [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)에서 사용할 수 있습니다.

### **FFT를 사용한 숨겨진 콘텐츠 탐지**

Fast Fourier Transform (FFT) 기술을 사용하면 이미지에서 숨겨진 콘텐츠를 확인할 수 있습니다. 유용한 자료는 다음과 같습니다:

- [EPFL 데모](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [GitHub의 FFTStegPic](https://github.com/0xcomposure/FFTStegPic)

### **오디오 및 이미지 파일에 대한 Stegpy**

Stegpy를 사용하면 PNG, BMP, GIF, WebP 및 WAV와 같은 형식의 이미지 및 오디오 파일에 정보를 삽입할 수 있습니다. [GitHub](https://github.com/dhsdshdhk/stegpy)에서 사용할 수 있습니다.

### **PNG 파일 분석을 위한 Pngcheck**

PNG 파일을 분석하거나 그들의 신뢰성을 검증하려면 다음을 사용하세요:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **이미지 분석을 위한 추가 도구**

더 자세히 알아보기 위해 다음을 방문해보세요:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **오디오에서 데이터 추출하기**

**오디오 스테가노그래피**는 소리 파일 내에 정보를 숨기는 독특한 방법을 제공합니다. 다양한 도구를 사용하여 숨겨진 콘텐츠를 삽입하거나 검색할 수 있습니다.

### **Steghide (JPEG, BMP, WAV, AU)**
Steghide는 JPEG, BMP, WAV, AU 파일에 데이터를 숨기기 위해 설계된 다재다능한 도구입니다. 자세한 지침은 [stego tricks documentation](stego-tricks.md#steghide)을 참조하세요.

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**
이 도구는 PNG, BMP, GIF, WebP, WAV 등 다양한 형식과 호환됩니다. 자세한 정보는 [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)을 참조하세요.

### **ffmpeg**
ffmpeg는 오디오 파일의 무결성을 평가하고 상세한 정보를 강조하며 어떠한 불일치도 찾아낼 수 있는 데 필수적입니다.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**
WavSteg은 최하위 비트 전략을 사용하여 WAV 파일 내에 데이터를 숨기고 추출하는 데 능숙합니다. [GitHub](https://github.com/ragibson/Steganography#WavSteg)에서 사용할 수 있습니다. 명령어는 다음과 같습니다:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**
Deepsound는 AES-256을 사용하여 소리 파일 내에 정보를 암호화하고 감지할 수 있게 해줍니다. [공식 페이지](http://jpinsoft.net/deepsound/download.aspx)에서 다운로드할 수 있습니다.

### **Sonic Visualizer**
오디오 파일의 시각적 및 분석적 검사에 귀중한 도구인 Sonic Visualizer는 다른 수단으로는 감지할 수 없는 숨겨진 요소를 드러낼 수 있습니다. 자세한 내용은 [공식 웹사이트](https://www.sonicvisualiser.org/)를 방문하세요.

### **DTMF Tones - Dial Tones**
오디오 파일에서 DTMF 톤을 감지하는 것은 [이 DTMF 감지기](https://unframework.github.io/dtmf-detect/)와 [DialABC](http://dialabc.com/sound/detect/index.html)와 같은 온라인 도구를 통해 가능합니다.

## **기타 기술**

### **Binary Length SQRT - QR Code**
제곱수가 되는 이진 데이터는 QR 코드를 나타낼 수 있습니다. 다음 스니펫을 사용하여 확인할 수 있습니다:
```python
import math
math.sqrt(2500) #50
```
이진 파일을 이미지로 변환하려면 [dcode](https://www.dcode.fr/binary-image)를 확인하세요. QR 코드를 읽으려면 [온라인 바코드 리더](https://online-barcode-reader.inliteresearch.com/)를 사용하세요.

### **브라일 변환**
브라일을 번역하기 위해 [Branah Braille Translator](https://www.branah.com/braille-translator)는 훌륭한 도구입니다.

## **참고 자료**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

<figure><img src="../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 빠르게 수정할 수 있도록 해주는 Intruder는 공격 표면을 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>로부터 AWS 해킹을 처음부터 전문가까지 배워보세요</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

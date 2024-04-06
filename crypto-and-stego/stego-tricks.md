# 스테고 트릭

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **해킹 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **깃허브 저장소에 제출하세요.**

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## **파일에서 데이터 추출하기**

### **Binwalk**

임베디드 숨겨진 파일과 데이터를 찾기 위한 이진 파일 검색 도구입니다. `apt`를 통해 설치되며 소스는 [GitHub](https://github.com/ReFirmLabs/binwalk)에서 사용할 수 있습니다.
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

파일을 헤더와 푸터를 기반으로 복구하여 png 이미지에 유용합니다. [GitHub](https://github.com/korczis/foremost)에서 소스를 사용하여 `apt`를 통해 설치됩니다.
```bash
foremost -i file # Extracts data
```
### **Exiftool**

파일 메타데이터를 볼 수 있도록 도와줍니다. [여기](https://www.sno.phy.queensu.ca/\~phil/exiftool/)에서 사용할 수 있습니다.
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

exiftool과 유사한 메타데이터 뷰어입니다. `apt`를 통해 설치할 수 있으며 [GitHub](https://github.com/Exiv2/exiv2)에서 소스를 찾을 수 있으며 [공식 웹사이트](http://www.exiv2.org/)도 있습니다.
```bash
exiv2 file # Shows the metadata
```
### **파일**

다루고 있는 파일의 유형을 식별합니다.

### **문자열**

다양한 인코딩 설정을 사용하여 파일에서 읽을 수 있는 문자열을 추출하여 출력을 필터링합니다.
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

온라인에서 찾은 원본 버전과 수정된 파일을 비교하는 데 유용합니다.
```bash
cmp original.jpg stego.jpg -b -l
```
## **텍스트에서 숨겨진 데이터 추출하기**

### **공백 안에 숨겨진 데이터**

보이지 않는 문자들이 비어 보이는 공백에 정보를 숨길 수 있습니다. 이 데이터를 추출하려면 [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)을 방문하세요.

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
### **데이터 숨김을 위한 Steghide**

Steghide은 `JPEG, BMP, WAV 및 AU` 파일 내에 데이터를 숨기는 것을 용이하게 해주며, 암호화된 데이터를 포함하고 추출할 수 있습니다. 설치는 `apt`를 사용하여 간단하게 할 수 있으며, [소스 코드는 GitHub에서](https://github.com/StefanoDeVuono/steghide) 사용할 수 있습니다.

**명령어:**

* `steghide info file`는 파일이 숨겨진 데이터를 포함하는지 여부를 나타냅니다.
* `steghide extract -sf file [--passphrase password]`는 숨겨진 데이터를 추출하며, 비밀번호는 선택 사항입니다.

웹 기반 추출을 위해서는 [이 웹사이트](https://futureboy.us/stegano/decinput.html)를 방문하십시오.

**Stegcracker를 사용한 브루트포스 공격:**

* Steghide에서 비밀번호 크래킹을 시도하려면 [stegcracker](https://github.com/Paradoxis/StegCracker.git)를 다음과 같이 사용하십시오:
```bash
stegcracker <file> [<wordlist>]
```
### **PNG 및 BMP 파일용 zsteg**

zsteg은 PNG 및 BMP 파일에서 숨겨진 데이터를 발견하는 데 특화되어 있습니다. 설치는 `gem install zsteg`를 통해 수행되며, [GitHub에서 소스를 확인할 수 있습니다](https://github.com/zed-0xff/zsteg).

**명령어:**

* `zsteg -a 파일`은 파일에 모든 탐지 방법을 적용합니다.
* `zsteg -E 파일`은 데이터 추출을 위한 페이로드를 지정합니다.

### **StegoVeritas 및 Stegsolve**

**stegoVeritas**는 메타데이터를 확인하고 이미지 변환을 수행하며, 다른 기능 중에 LSB 브루트 포싱을 적용합니다. 모든 옵션의 전체 목록을 보려면 `stegoveritas.py -h`를 사용하고, 모든 확인을 실행하려면 `stegoveritas.py stego.jpg`를 사용하세요.

**Stegsolve**는 다양한 색상 필터를 적용하여 이미지 내에 숨겨진 텍스트나 메시지를 드러내는 데 사용됩니다. [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)에서 사용할 수 있습니다.

### **숨겨진 콘텐츠 탐지를 위한 FFT**

Fast Fourier Transform (FFT) 기술을 사용하면 이미지 내에 숨겨진 콘텐츠를 발견할 수 있습니다. 유용한 자료는 다음과 같습니다:

* [EPFL 데모](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [GitHub의 FFTStegPic](https://github.com/0xcomposure/FFTStegPic)

### **오디오 및 이미지 파일용 Stegpy**

Stegpy를 사용하면 PNG, BMP, GIF, WebP, WAV와 같은 형식을 지원하는 이미지 및 오디오 파일에 정보를 삽입할 수 있습니다. [GitHub](https://github.com/dhsdshdhk/stegpy)에서 사용할 수 있습니다.

### **PNG 파일 분석을 위한 Pngcheck**

PNG 파일을 분석하거나 그 신뢰성을 확인하려면 사용하세요:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **이미지 분석을 위한 추가 도구**

더 깊이 탐구하기 위해 다음을 방문해보세요:

* [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
* [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [OpenStego](https://www.openstego.com/)
* [DIIT](https://diit.sourceforge.net/)

## **오디오에서 데이터 추출하기**

**오디오 스테가노그래피**는 소리 파일 내에 정보를 숨기는 독특한 방법을 제공합니다. 다양한 도구가 잠재된 콘텐츠를 삽입하거나 검색하는 데 사용됩니다.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide는 JPEG, BMP, WAV 및 AU 파일에 데이터를 숨기기 위해 설계된 다재다능한 도구입니다. 자세한 지침은 [stego tricks 문서](stego-tricks.md#steghide)를 참조하세요.

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

이 도구는 PNG, BMP, GIF, WebP 및 WAV와 같은 다양한 형식과 호환됩니다. 자세한 정보는 [Stegpy 섹션](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)을 참조하세요.

### **ffmpeg**

ffmpeg는 오디오 파일의 무결성을 평가하고 상세 정보를 강조하며 어떠한 불일치도 파악하는 데 중요합니다.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg은 최소 유의 비트 전략을 사용하여 WAV 파일 내에 데이터를 숨기고 추출하는 데 뛰어납니다. [GitHub](https://github.com/ragibson/Steganography#WavSteg)에서 사용할 수 있습니다. 명령어는 다음과 같습니다:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound는 AES-256을 사용하여 소리 파일 내의 정보를 암호화하고 감지할 수 있습니다. [공식 페이지](http://jpinsoft.net/deepsound/download.aspx)에서 다운로드할 수 있습니다.

### **Sonic Visualizer**

오디오 파일의 시각적 및 분석적 검사에 귀중한 도구 인 Sonic Visualizer는 다른 수단으로는 감지할 수 없는 숨겨진 요소를 드러낼 수 있습니다. 더 많은 정보는 [공식 웹 사이트](https://www.sonicvisualiser.org/)에서 확인할 수 있습니다.

### **DTMF Tones - Dial Tones**

오디오 파일에서 DTMF 톤을 감지하는 것은 [이 DTMF 검출기](https://unframework.github.io/dtmf-detect/) 및 [DialABC](http://dialabc.com/sound/detect/index.html)와 같은 온라인 도구를 통해 달성할 수 있습니다.

## **기타 기술**

### **Binary Length SQRT - QR Code**

제곱근이 정수인 이진 데이터는 QR 코드를 나타낼 수 있습니다. 다음 스니펫을 사용하여 확인하세요:
```python
import math
math.sqrt(2500) #50
```
### **점자 번역**

점자 번역을 위해서는 [Branah Braille Translator](https://www.branah.com/braille-translator)를 사용할 수 있습니다.

## **참고 자료**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 AWS 해킹을 마스터하세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 PDF로 다운로드하려면** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

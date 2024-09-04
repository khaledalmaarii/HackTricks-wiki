# Stego Tricks

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

## **파일에서 데이터 추출하기**

### **Binwalk**

내장된 숨겨진 파일과 데이터를 찾기 위한 이진 파일 검색 도구입니다. `apt`를 통해 설치되며, 소스는 [GitHub](https://github.com/ReFirmLabs/binwalk)에서 확인할 수 있습니다.
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

헤더와 푸터를 기반으로 파일을 복구하며, png 이미지에 유용합니다. [GitHub](https://github.com/korczis/foremost)에서 소스를 통해 `apt`로 설치할 수 있습니다.
```bash
foremost -i file # Extracts data
```
### **Exiftool**

파일 메타데이터를 보기 위해 사용되며, [여기](https://www.sno.phy.queensu.ca/\~phil/exiftool/)에서 확인할 수 있습니다.
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

메타데이터 보기용으로 exiftool과 유사합니다. `apt`를 통해 설치 가능하며, [GitHub](https://github.com/Exiv2/exiv2)에서 소스를 확인할 수 있고, [공식 웹사이트](http://www.exiv2.org/)가 있습니다.
```bash
exiv2 file # Shows the metadata
```
### **파일**

다루고 있는 파일의 유형을 식별합니다.

### **문자열**

출력을 필터링하기 위해 다양한 인코딩 설정을 사용하여 파일에서 읽을 수 있는 문자열을 추출합니다.
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
### **Comparison (cmp)**

온라인에서 찾은 원본 버전과 수정된 파일을 비교하는 데 유용합니다.
```bash
cmp original.jpg stego.jpg -b -l
```
## **텍스트에서 숨겨진 데이터 추출하기**

### **공간에서 숨겨진 데이터**

겉보기에는 비어 있는 공간의 보이지 않는 문자들이 정보를 숨길 수 있습니다. 이 데이터를 추출하려면 [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder) 를 방문하세요.

## **이미지에서 데이터 추출하기**

### **GraphicMagick로 이미지 세부정보 식별하기**

[GraphicMagick](https://imagemagick.org/script/download.php)는 이미지 파일 유형을 결정하고 잠재적인 손상을 식별하는 데 사용됩니다. 이미지를 검사하려면 아래 명령을 실행하세요:
```bash
./magick identify -verbose stego.jpg
```
손상된 이미지를 복구하려고 시도할 때, 메타데이터 주석을 추가하는 것이 도움이 될 수 있습니다:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide를 통한 데이터 은닉**

Steghide는 `JPEG, BMP, WAV, AU` 파일 내에 데이터를 숨기는 기능을 제공하며, 암호화된 데이터를 삽입하고 추출할 수 있습니다. 설치는 `apt`를 사용하여 간단하게 할 수 있으며, [소스 코드는 GitHub에서 확인할 수 있습니다](https://github.com/StefanoDeVuono/steghide).

**명령어:**

* `steghide info file`은 파일에 숨겨진 데이터가 있는지 확인합니다.
* `steghide extract -sf file [--passphrase password]`는 숨겨진 데이터를 추출하며, 비밀번호는 선택 사항입니다.

웹 기반 추출을 원하시면 [이 웹사이트](https://futureboy.us/stegano/decinput.html)를 방문하세요.

**Stegcracker를 이용한 무차별 대입 공격:**

* Steghide의 비밀번호 크래킹을 시도하려면 [stegcracker](https://github.com/Paradoxis/StegCracker.git)를 다음과 같이 사용하세요:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg for PNG and BMP Files**

zsteg는 PNG 및 BMP 파일에서 숨겨진 데이터를 발견하는 데 특화되어 있습니다. 설치는 `gem install zsteg`를 통해 이루어지며, [GitHub 소스](https://github.com/zed-0xff/zsteg)에서 확인할 수 있습니다.

**Commands:**

* `zsteg -a file`는 파일에 모든 탐지 방법을 적용합니다.
* `zsteg -E file`는 데이터 추출을 위한 페이로드를 지정합니다.

### **StegoVeritas and Stegsolve**

**stegoVeritas**는 메타데이터를 확인하고, 이미지 변환을 수행하며, LSB 무차별 대입 공격을 적용하는 등 다양한 기능을 제공합니다. 전체 옵션 목록은 `stegoveritas.py -h`를 사용하고, 모든 검사를 실행하려면 `stegoveritas.py stego.jpg`를 사용하세요.

**Stegsolve**는 이미지를 통해 숨겨진 텍스트나 메시지를 드러내기 위해 다양한 색상 필터를 적용합니다. [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)에서 사용할 수 있습니다.

### **FFT for Hidden Content Detection**

Fast Fourier Transform (FFT) 기술은 이미지에서 숨겨진 콘텐츠를 드러낼 수 있습니다. 유용한 리소스는 다음과 같습니다:

* [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpy는 PNG, BMP, GIF, WebP 및 WAV와 같은 형식을 지원하여 이미지 및 오디오 파일에 정보를 삽입할 수 있습니다. [GitHub](https://github.com/dhsdshdhk/stegpy)에서 사용할 수 있습니다.

### **Pngcheck for PNG File Analysis**

PNG 파일을 분석하거나 그 진위를 확인하려면:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **이미지 분석을 위한 추가 도구**

더 많은 탐색을 원하신다면 다음을 방문해 보세요:

* [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
* [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
* [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
* [OpenStego](https://www.openstego.com/)
* [DIIT](https://diit.sourceforge.net/)

## **오디오에서 데이터 추출하기**

**오디오 스테가노그래피**는 사운드 파일 내에 정보를 숨기는 독특한 방법을 제공합니다. 숨겨진 콘텐츠를 삽입하거나 검색하기 위해 다양한 도구가 사용됩니다.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide는 JPEG, BMP, WAV 및 AU 파일에 데이터를 숨기기 위해 설계된 다목적 도구입니다. 자세한 지침은 [stego tricks documentation](stego-tricks.md#steghide)에서 확인할 수 있습니다.

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

이 도구는 PNG, BMP, GIF, WebP 및 WAV를 포함한 다양한 형식과 호환됩니다. 더 많은 정보는 [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)을 참조하세요.

### **ffmpeg**

ffmpeg는 오디오 파일의 무결성을 평가하는 데 중요하며, 자세한 정보를 강조하고 불일치를 정확히 지적합니다.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg은 가장 덜 중요한 비트 전략을 사용하여 WAV 파일 내에서 데이터를 숨기고 추출하는 데 뛰어납니다. [GitHub](https://github.com/ragibson/Steganography#WavSteg)에서 접근할 수 있습니다. 명령어는 다음과 같습니다:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound는 AES-256을 사용하여 사운드 파일 내의 정보를 암호화하고 감지할 수 있습니다. [공식 페이지](http://jpinsoft.net/deepsound/download.aspx)에서 다운로드할 수 있습니다.

### **Sonic Visualizer**

Sonic Visualizer는 오디오 파일의 시각적 및 분석적 검사를 위한 귀중한 도구로, 다른 방법으로는 감지할 수 없는 숨겨진 요소를 드러낼 수 있습니다. 더 많은 정보는 [공식 웹사이트](https://www.sonicvisualiser.org/)를 방문하세요.

### **DTMF Tones - Dial Tones**

오디오 파일에서 DTMF 톤을 감지하는 것은 [이 DTMF 감지기](https://unframework.github.io/dtmf-detect/)와 [DialABC](http://dialabc.com/sound/detect/index.html)와 같은 온라인 도구를 통해 가능합니다.

## **Other Techniques**

### **Binary Length SQRT - QR Code**

정수로 제곱되는 이진 데이터는 QR 코드를 나타낼 수 있습니다. 확인하려면 이 코드를 사용하세요:
```python
import math
math.sqrt(2500) #50
```
이진수를 이미지로 변환하려면 [dcode](https://www.dcode.fr/binary-image)를 확인하세요. QR 코드를 읽으려면 [이 온라인 바코드 리더](https://online-barcode-reader.inliteresearch.com/)를 사용하세요.

### **점자 번역**

점자를 번역하기 위해 [Branah Braille Translator](https://www.branah.com/braille-translator)는 훌륭한 자원입니다.

## **참고문헌**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}

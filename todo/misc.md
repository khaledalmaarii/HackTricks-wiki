<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>


Ping 응답에서 TTL:
127 = Windows
254 = Cisco
Lo demás,algunlinux

$1$- md5
$2$ 또는 $2a$ - Blowfish
$5$- sha256
$6$- sha512

서비스 뒤에 무엇이 있는지 모르는 경우, HTTP GET 요청을 시도해보세요.

**UDP 스캔**
nc -nv -u -z -w 1 \<IP> 160-16

빈 UDP 패킷이 특정 포트로 전송됩니다. UDP 포트가 열려 있으면 대상 컴퓨터에서 응답이 돌아오지 않습니다. UDP 포트가 닫혀 있으면 대상 컴퓨터에서 ICMP 포트 도달 불가 패킷이 전송됩니다.


UDP 포트 스캔은 종종 신뢰할 수 없으며, 방화벽과 라우터가 ICMP 패킷을 삭제할 수 있습니다.
스캔에서 잘못된 양성 결과가 발생할 수 있으며, 스캔된 컴퓨터의 모든 UDP 포트가 열려 있다고 표시되는 것을 정기적으로 볼 수 있습니다.
o 대부분의 포트 스캐너는 사용 가능한 모든 포트를 스캔하지 않으며, 일반적으로 스캔되는 "흥미로운 포트"의 미리 정의된 목록이 있습니다.

# CTF - 트릭

**Windows**에서 파일을 검색하기 위해 **Winzip**을 사용하세요.
**대체 데이터 스트림**: _dir /r | find ":$DATA"_
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## 암호화

**featherduster**\


**Base64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> "_begin \<mode> \<filename>_"로 시작하고 이상한 문자\
**Xxencoding** --> "_begin \<mode> \<filename>_"로 시작하고 B64\
\
**Vigenere** (빈도 분석) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (문자의 오프셋) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> 공백과 탭을 사용하여 메시지 숨기기

# 문자

%E2%80%AE => RTL 문자 (페이로드를 거꾸로 작성)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기술을 공유하세요.

</details>

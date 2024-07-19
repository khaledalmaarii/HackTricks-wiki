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


핑 응답 TTL:\
127 = Windows\
254 = Cisco\
나머지, 어떤 리눅스

$1$- md5\
$2$ 또는 $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

서비스 뒤에 무엇이 있는지 모른다면, HTTP GET 요청을 시도해 보세요.

**UDP 스캔**\
nc -nv -u -z -w 1 \<IP> 160-16

특정 포트로 빈 UDP 패킷이 전송됩니다. UDP 포트가 열려 있으면, 대상 머신에서 응답이 전송되지 않습니다. UDP 포트가 닫혀 있으면, 대상 머신에서 ICMP 포트 도달 불가 패킷이 전송되어야 합니다.\

UDP 포트 스캔은 종종 신뢰할 수 없으며, 방화벽과 라우터가 ICMP 패킷을 차단할 수 있습니다. 이로 인해 스캔에서 잘못된 긍정 결과가 발생할 수 있으며, 스캔된 머신에서 모든 UDP 포트가 열려 있는 것으로 표시되는 UDP 포트 스캔을 자주 볼 수 있습니다.\
대부분의 포트 스캐너는 사용 가능한 모든 포트를 스캔하지 않으며, 일반적으로 스캔되는 "흥미로운 포트"의 미리 설정된 목록을 가지고 있습니다.

# CTF - 트릭

**Windows**에서 **Winzip**을 사용하여 파일을 검색하세요.\
**대체 데이터 스트림**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\


**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> "_begin \<mode> \<filename>_"로 시작하고 이상한 문자\
**Xxencoding** --> "_begin \<mode> \<filename>_"로 시작하고 B64\
\
**Vigenere** (주파수 분석) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (문자의 오프셋) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> 공백과 탭을 사용하여 메시지 숨기기

# Characters

%E2%80%AE => RTL 문자 (페이로드를 거꾸로 씀)


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

# Proxmark 3

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 트릭을 공유하려면 PR을** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 제출**하세요.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정하세요. Intruder는 공격 대상을 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Proxmark3을 사용한 RFID 시스템 공격

첫 번째로 해야 할 일은 [**Proxmark3**](https://proxmark.com)을 준비하고 [**소프트웨어를 설치하고 종속성을 설치**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**하세요**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### MIFARE Classic 1KB 공격

**16개의 섹터**가 있으며, 각 섹터에는 **4개의 블록**이 있고 각 블록에는 **16B**가 포함되어 있습니다. UID는 섹터 0 블록 0에 있으며 변경할 수 없습니다.\
각 섹터에 액세스하려면 **2개의 키**(**A** 및 **B**)가 필요하며, 이 키는 각 섹터의 **블록 3에 저장**됩니다(섹터 트레일러). 섹터 트레일러에는 또한 2개의 키를 사용하여 각 블록에 대한 **읽기 및 쓰기 권한**을 부여하는 **액세스 비트**가 저장됩니다.\
첫 번째 키를 알고 있다면 읽기 권한을 부여하고, 두 번째 키를 알고 있다면 쓰기 권한을 부여하는 데 2개의 키가 유용합니다(예:).
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
Proxmark3는 민감한 데이터를 찾기 위해 **태그와 리더 간의 통신을 도청**하는 등 다른 작업을 수행할 수 있습니다. 이 카드에서는 **암호화 작업이 약하게 사용**되므로 평문과 암호문을 알고 있다면 사용된 키를 계산할 수 있습니다 (`mfkey64` 도구).

### 원시 명령어

IoT 시스템은 때로는 **브랜드가 없거나 상업적이지 않은 태그**를 사용합니다. 이 경우, Proxmark3를 사용하여 태그에 **사용자 정의 원시 명령어를 보낼 수** 있습니다.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
이 정보를 사용하여 카드에 대한 정보와 통신 방법을 찾아볼 수 있습니다. Proxmark3는 `hf 14a raw -p -b 7 26`와 같은 원시 명령을 보낼 수 있도록 합니다.

### 스크립트

Proxmark3 소프트웨어에는 간단한 작업을 수행하는 데 사용할 수 있는 **자동화 스크립트** 목록이 미리 로드되어 있습니다. 전체 목록을 검색하려면 `script list` 명령을 사용하십시오. 그런 다음 `script run` 명령을 사용하여 스크립트 이름을 입력하십시오:
```
proxmark3> script run mfkeys
```
**태그 판독기를 퍼징(fuzz)하는 스크립트를 만들 수 있습니다**. 유효한 카드의 데이터를 복사하여 무작위로 하나 이상의 랜덤 바이트를 **Lua 스크립트**로 작성하고, 판독기가 어떤 반복에서도 **크래시(crash)**가 발생하는지 확인합니다.

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정할 수 있습니다. Intruder는 공격 표면을 추적하고 예방적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 사용해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm\_campaign=hacktricks&utm\_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 플랜**](https://github.com/sponsors/carlospolop)을 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 트릭을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하세요.

</details>

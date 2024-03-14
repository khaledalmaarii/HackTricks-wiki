# Proxmark 3

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에 귀사를 광고하고 싶으신가요**? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점적인 [**NFT 컬렉션**](https://opensea.io/collection/the-peass-family)
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 받으세요
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요**.
* **해킹 요령을 공유하고 싶으시다면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **로 PR을 제출하세요**.

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Proxmark3을 사용한 RFID 시스템 공격

첫 번째로 해야 할 일은 [**Proxmark3**](https://proxmark.com)을 준비하고 [**소프트웨어를 설치하고 그 의존성을 해결**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)해야 합니다.

### MIFARE Classic 1KB 공격

각각에 **4개의 블록**이 있는 **16개의 섹터**가 있습니다. 각 블록은 **16B**를 포함합니다. UID는 섹터 0 블록 0에 있으며 **변경할 수 없습니다**.\
각 섹터에 액세스하려면 **2개의 키**(**A** 및 **B**)가 필요하며 이는 **각 섹터의 블록 3에 저장**됩니다(섹터 트레일러). 섹터 트레일러에는 또한 **2개의 키를 사용하여 각 블록에 대한 읽기 및 쓰기 권한을 부여하는** **액세스 비트**가 저장됩니다.\
첫 번째 키를 알고 있다면 읽기 권한을 부여하고 두 번째 키를 알고 있다면 쓰기 권한을 부여하는 데 2개의 키가 유용합니다(예:).

여러 공격을 수행할 수 있습니다.
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
Proxmark3는 **도청**과 같은 다른 작업을 수행할 수 있도록 합니다. **태그와 리더 간 통신**을 도청하여 민감한 데이터를 찾아보려고 합니다. 이 카드에서는 **암호화 작업이 약하게 사용**되어 평문과 암호문을 알고 있다면 키를 계산할 수 있습니다 (`mfkey64` 도구).

### 원시 명령어

IoT 시스템은 때로는 **브랜드가 없거나 상업적이지 않은 태그**를 사용합니다. 이 경우 Proxmark3를 사용하여 태그에 **사용자 정의 원시 명령어를 보낼** 수 있습니다.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
이 정보를 사용하여 카드에 대한 정보 및 통신 방법을 검색해 볼 수 있습니다. Proxmark3를 사용하면 `hf 14a raw -p -b 7 26`와 같은 원시 명령을 보낼 수 있습니다.

### 스크립트

Proxmark3 소프트웨어에는 간단한 작업을 수행하는 데 사용할 수 있는 **자동화 스크립트** 목록이 미리로드되어 있습니다. 전체 목록을 검색하려면 `script list` 명령을 사용하십시오. 그런 다음 스크립트 이름 뒤에 `script run` 명령을 사용하십시오.
```
proxmark3> script run mfkeys
```
**유효한 카드**의 데이터를 복사하여 **태그 판독기**를 **퍼징**하는 스크립트를 만들 수 있습니다. 그냥 **Lua 스크립트**를 작성하여 하나 이상의 **랜덤 바이트**를 **랜덤화**하고 **리더가 반복 중에 충돌하는지** 확인하십시오.

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹을 배우세요**!</summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에 귀사를 광고**하고 싶으신가요? 아니면 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 얻으세요
* [**💬**](https://emojipedia.org/speech-balloon/) **디스코드 그룹**에 **가입**하거나 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 트릭을 공유하려면 PR을** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 제출**하세요.

</details>

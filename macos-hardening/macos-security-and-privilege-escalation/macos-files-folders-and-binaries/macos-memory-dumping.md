# macOS 메모리 덤프

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 AWS 해킹을 제로부터 전문가까지 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 기반으로 한 검색 엔진으로, **회사 또는 고객이 **stealer malwares**에 의해 **침해**당했는지를 확인하는 **무료** 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난당한 악성 소프트웨어로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 확인하고 **무료**로 엔진을 시도해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

---

## 메모리 아티팩트

### 스왑 파일

`/private/var/vm/swapfile0`와 같은 스왑 파일은 **물리적 메모리가 가득 찼을 때 캐시로 작동**합니다. 물리적 메모리에 더 이상 공간이 없을 때, 해당 데이터는 스왑 파일로 전송되고 필요할 때 다시 물리적 메모리로 가져옵니다. swapfile0, swapfile1 등과 같은 이름의 여러 스왑 파일이 존재할 수 있습니다.

### 휴면 이미지

`/private/var/vm/sleepimage`에 위치한 파일은 **휴면 모드** 중에 중요합니다. **OS X가 휴면 상태일 때 메모리 데이터가 이 파일에 저장**됩니다. 컴퓨터를 깨우면 시스템이 이 파일에서 메모리 데이터를 검색하여 사용자가 중단한 곳에서 계속할 수 있게 합니다.

현대의 MacOS 시스템에서는 이 파일이 일반적으로 보안상의 이유로 암호화되어 복구가 어려워집니다.

* `sysctl vm.swapusage` 명령을 실행하여 sleepimage에 대한 암호화가 활성화되었는지 확인할 수 있습니다. 이를 통해 파일이 암호화되었는지 확인할 수 있습니다.

### 메모리 압력 로그

MacOS 시스템에서 또 다른 중요한 메모리 관련 파일은 **메모리 압력 로그**입니다. 이 로그는 `/var/log`에 위치하며 시스템의 메모리 사용량 및 압력 이벤트에 대한 자세한 정보를 포함합니다. 이는 메모리 관련 문제를 진단하거나 시스템이 시간이 지남에 따라 메모리를 관리하는 방법을 이해하는 데 유용할 수 있습니다.

## osxpmem을 사용한 메모리 덤프

MacOS 기기에서 메모리를 덤프하려면 [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)를 사용할 수 있습니다.

**참고**: 다음 지침은 Intel 아키텍처를 사용하는 Mac에만 적용됩니다. 이 도구는 현재 보관 중이며 마지막 릴리스는 2017년에 있었습니다. 아래 지침을 사용하여 다운로드한 이진 파일은 Apple Silicon이 2017년에 없었기 때문에 Intel 칩을 대상으로 합니다. arm64 아키텍처용으로 바이너리를 컴파일하는 것이 가능할 수 있지만 직접 시도해봐야 합니다.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
만약 다음 오류를 발견하면: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 다음을 수행하여 해결할 수 있습니다:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**다른 오류**는 "보안 및 개인 정보 보호 --> 일반"에서 **kext 로드를 허용**함으로써 해결될 수 있습니다. 그냥 **허용**하세요.

또한 이 **원라이너**를 사용하여 애플리케이션을 다운로드하고 kext를 로드하고 메모리를 덤프할 수 있습니다:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 기반으로 한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**당했는지 확인할 수 있는 **무료** 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난하는 악성 소프트웨어로 인한 계정 탈취와 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 **무료**로 엔진을 시험해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

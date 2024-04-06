# 기본적인 포렌식 방법론

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하고 싶으신가요? 또는 **PEASS의 최신 버전 또는 HackTricks PDF 다운로드**에 액세스하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>

## 이미지 생성 및 마운트

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md" %}
[image-acquisition-and-mount.md](../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md)
{% endcontent-ref %}

## 악성 코드 분석

이것은 **이미지를 얻은 후에 수행해야 하는 첫 번째 단계는 아닙니다**. 그러나 파일, 파일 시스템 이미지, 메모리 이미지, pcap 등이 있는 경우에도 이 악성 코드 분석 기법을 독립적으로 사용할 수 있으므로 **이러한 작업을 염두에 두는 것이 좋습니다**:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## 이미지 검사

디바이스의 **포렌식 이미지**가 주어진 경우 **파티션, 사용된 파일 시스템**을 분석하고 잠재적으로 **흥미로운 파일**(삭제된 파일 포함)을 복구할 수 있습니다. 다음에서 이를 배워보세요:

{% content-ref url="partitions-file-systems-carving/" %}
[partitions-file-systems-carving](partitions-file-systems-carving/)
{% endcontent-ref %}

사용된 운영 체제 및 플랫폼에 따라 다른 흥미로운 아티팩트를 검색해야 할 수도 있습니다:

{% content-ref url="windows-forensics/" %}
[windows-forensics](windows-forensics/)
{% endcontent-ref %}

{% content-ref url="linux-forensics.md" %}
[linux-forensics.md](linux-forensics.md)
{% endcontent-ref %}

{% content-ref url="docker-forensics.md" %}
[docker-forensics.md](docker-forensics.md)
{% endcontent-ref %}

## 특정 파일 유형 및 소프트웨어의 깊은 검사

매우 **의심스러운 파일**이 있다면, **파일 유형 및 생성한 소프트웨어**에 따라 여러 **기교**가 유용할 수 있습니다.\
다음 페이지를 읽어 몇 가지 흥미로운 기교를 배워보세요:

{% content-ref url="specific-software-file-type-tricks/" %}
[specific-software-file-type-tricks](specific-software-file-type-tricks/)
{% endcontent-ref %}

특히 다음 페이지에 대해 언급하고 싶습니다:

{% content-ref url="specific-software-file-type-tricks/browser-artifacts.md" %}
[browser-artifacts.md](specific-software-file-type-tricks/browser-artifacts.md)
{% endcontent-ref %}

## 메모리 덤프 검사

{% content-ref url="memory-dump-analysis/" %}
[memory-dump-analysis](memory-dump-analysis/)
{% endcontent-ref %}

## Pcap 검사

{% content-ref url="pcap-inspection/" %}
[pcap-inspection](pcap-inspection/)
{% endcontent-ref %}

## **반 포렌식 기법**

반 포렌식 기법의 가능성을 염두에 두세요:

{% content-ref url="anti-forensic-techniques.md" %}
[anti-forensic-techniques.md](anti-forensic-techniques.md)
{% endcontent-ref %}

## 위협 사냥

{% content-ref url="file-integrity-monitoring.md" %}
[file-integrity-monitoring.md](file-integrity-monitoring.md)
{% endcontent-ref %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하고 싶으신가요? 또는 **PEASS의 최신 버전 또는 HackTricks PDF 다운로드**에 액세스하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>

# PsExec/Winexec/ScExec

<details>

<summary><strong>AWS 해킹을 처음부터 전문가까지 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **당신의 해킹 기술을 공유**하세요.

</details>

## 작동 방식

서비스 이진 파일이 SMB를 통해 원격으로 실행되는 방법을 설명하는 아래 단계에 대한 프로세스:

1. **ADMIN$ 공유로 서비스 이진 파일 복사**를 수행합니다.
2. 원격 기계에 **서비스 생성**은 바이너리를 가리킵니다.
3. 서비스가 **원격으로 시작**됩니다.
4. 종료시, 서비스가 **중지되고 바이너리가 삭제**됩니다.

### **PsExec 수동 실행 프로세스**

msfvenom으로 생성되고 Veil을 사용하여 안티바이러스 감지를 회피하기 위해 난독화된 실행 가능한 페이로드인 'met8888.exe'라는 이름의 페이로드가 있다고 가정하면, 다음 단계가 수행됩니다:

* **바이너리 복사**: 실행 파일은 명령 프롬프트에서 ADMIN$ 공유로 복사되지만 숨겨지기 위해 파일 시스템의 어디에나 배치될 수 있습니다.
* **서비스 생성**: Windows `sc` 명령을 사용하여 원격으로 Windows 서비스를 조회, 생성 및 삭제할 수 있는 "meterpreter"라는 서비스가 업로드된 바이너리를 가리키도록 생성됩니다.
* **서비스 시작**: 마지막 단계는 서비스를 시작하는 것으로, 이는 바이너리가 진짜 서비스 바이너리가 아니기 때문에 예상된 응답 코드를 반환하지 못하고 "시간 초과" 오류가 발생할 가능성이 높습니다. 이 오류는 주된 목표인 바이너리 실행에는 영향을 미치지 않습니다.

Metasploit 리스너를 관찰하면 세션이 성공적으로 시작된 것을 확인할 수 있습니다.

[`sc` 명령에 대해 더 알아보기](https://technet.microsoft.com/en-us/library/bb490995.aspx).

자세한 단계는 여기에서 확인하세요: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Windows Sysinternals 바이너리 PsExec.exe를 사용할 수도 있습니다:**

![](<../../.gitbook/assets/image (928).png>)

[**SharpLateral**](https://github.com/mertdas/SharpLateral)를 사용할 수도 있습니다:

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅까지 AWS 해킹 배우기</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 웸하면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
* **해킹 트릭을 공유하고 싶다면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

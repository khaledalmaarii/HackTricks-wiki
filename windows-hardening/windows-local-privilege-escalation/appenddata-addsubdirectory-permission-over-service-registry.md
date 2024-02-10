<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 PDF로 HackTricks를 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**을** 팔로우하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 **PR을 제출하여** 여러분의 해킹 기교를 공유하세요.

</details>


**원본 게시물은** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)입니다.

## 요약

현재 사용자가 쓰기 가능한 두 개의 레지스트리 키를 찾았습니다:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

**regedit GUI**를 사용하여 **RpcEptMapper** 서비스의 권한을 확인하는 것이 제안되었습니다. 특히 **고급 보안 설정** 창의 **유효한 권한** 탭을 사용하여 특정 사용자 또는 그룹에게 부여된 권한을 개별적으로 검사하지 않고도 평가할 수 있습니다.

스크립트의 결과와 일치하는 권한이 부여된 낮은 권한의 사용자에 대한 스크린샷이 제시되었습니다. 이 중 **Create Subkey** 권한이 주목받았습니다. 이 권한은 **AppendData/AddSubdirectory**로도 알려져 있으며, 스크립트의 결과와 일치합니다.

일부 값을 직접 수정할 수 없지만 새로운 하위 키를 생성할 수 있는 능력에 대해 언급되었습니다. 예를 들어 **ImagePath** 값을 변경하려는 시도는 액세스 거부 메시지가 나타났습니다.

그러나 이러한 제한 사항에도 불구하고, **RpcEptMapper** 서비스의 레지스트리 구조 내에 기본적으로 존재하지 않는 **Performance** 하위 키를 활용하여 권한 상승의 가능성이 확인되었습니다. 이를 통해 DLL 등록 및 성능 모니터링이 가능합니다.

**Performance** 하위 키와 성능 모니터링에 대한 문서를 참고하여 개념 증명 DLL을 개발했습니다. **OpenPerfData**, **CollectPerfData**, **ClosePerfData** 함수의 구현을 보여주는 이 DLL은 **rundll32**를 통해 테스트되었으며, 작동이 성공적으로 확인되었습니다.

목표는 **RPC Endpoint Mapper 서비스**가 제작된 Performance DLL을 로드하도록 강제하는 것이었습니다. PowerShell을 통해 성능 데이터와 관련된 WMI 클래스 쿼리를 실행하면 로그 파일이 생성되어 **LOCAL SYSTEM** 컨텍스트에서 임의의 코드를 실행할 수 있으며, 이로써 권한이 상승됩니다.

이 취약점의 지속성과 잠재적인 영향을 강조하며, 이는 사후 공격 전략, 측면 이동 및 백신/EDR 시스템 회피에 중요합니다.

이 취약점은 스크립트를 통해 의도치 않게 공개되었지만, 이를 악용하기 위해서는 오래된 Windows 버전 (예: **Windows 7 / Server 2008 R2**)이어야 하며, 로컬 액세스가 필요합니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 PDF로 HackTricks를 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**을** 팔로우하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 **PR을 제출하여** 여러분의 해킹 기교를 공유하세요.

</details>

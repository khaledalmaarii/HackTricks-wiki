<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## Firmware Integrity

**사용자 정의 펌웨어 및/또는 컴파일된 이진 파일은 무결성 또는 서명 검증 취약점을 이용하여 업로드될 수 있습니다**. 백도어 바인드 쉘 컴파일을 위해 다음 단계를 따를 수 있습니다:

1. 펌웨어를 firmware-mod-kit (FMK)를 사용하여 추출할 수 있습니다.
2. 대상 펌웨어 아키텍처와 엔디안을 식별해야 합니다.
3. Buildroot 또는 다른 적합한 방법을 사용하여 환경에 맞는 크로스 컴파일러를 빌드할 수 있습니다.
4. 크로스 컴파일러를 사용하여 백도어를 빌드할 수 있습니다.
5. 백도어를 추출된 펌웨어의 /usr/bin 디렉토리로 복사할 수 있습니다.
6. 적절한 QEMU 바이너리를 추출된 펌웨어 rootfs로 복사할 수 있습니다.
7. chroot와 QEMU를 사용하여 백도어를 에뮬레이션할 수 있습니다.
8. netcat을 통해 백도어에 액세스할 수 있습니다.
9. 추출된 펌웨어 rootfs에서 QEMU 바이너리를 제거해야 합니다.
10. FMK를 사용하여 수정된 펌웨어를 다시 패키징할 수 있습니다.
11. 백도어가 추가된 펌웨어를 firmware analysis toolkit (FAT)를 사용하여 에뮬레이션하고 netcat을 사용하여 대상 백도어 IP와 포트에 연결하여 테스트할 수 있습니다.

동적 분석, 부트로더 조작 또는 하드웨어 보안 테스트를 통해 이미 루트 쉘이 획득된 경우, 임플란트 또는 리버스 쉘과 같은 사전 컴파일된 악성 이진 파일을 실행할 수 있습니다. Metasploit 프레임워크와 'msfvenom'과 같은 자동화된 페이로드/임플란트 도구를 사용하여 다음 단계를 수행할 수 있습니다:

1. 대상 펌웨어 아키텍처와 엔디안을 식별해야 합니다.
2. Msfvenom을 사용하여 대상 페이로드, 공격자 호스트 IP, 수신 포트 번호, 파일 유형, 아키텍처, 플랫폼 및 출력 파일을 지정할 수 있습니다.
3. 페이로드를 감염된 장치로 전송하고 실행 권한이 있는지 확인해야 합니다.
4. Metasploit을 시작하고 페이로드에 따라 설정을 구성하여 수신 요청을 처리할 준비를 할 수 있습니다.
5. 감염된 장치에서 meterpreter 리버스 쉘을 실행할 수 있습니다.
6. 열리는 meterpreter 세션을 모니터링할 수 있습니다.
7. 사후 공격 활동을 수행할 수 있습니다.

가능한 경우, 시작 스크립트 내의 취약점을 이용하여 장치에 대한 지속적인 액세스를 얻을 수 있습니다. 이러한 취약점은 시작 스크립트가 SD 카드 및 루트 파일 시스템 외부에 데이터를 저장하는 데 사용되는 플래시 볼륨과 같은 신뢰할 수 없는 마운트된 위치에 있는 코드를 참조하거나 [심볼릭 링크](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data)하는 경우에 발생합니다.

## 참고 자료
* 자세한 정보는 [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)를 확인하세요.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>


인터넷에는 LDAP로 구성된 프린터를 기본/약한 로그인 자격 증명으로 두는 것의 위험성을 강조하는 여러 블로그가 있습니다.\
이는 공격자가 프린터를 속여 루즈 LDAP 서버(일반적으로 `nc -vv -l -p 444`이면 충분)에 인증하도록 하고, 프린터 자격 증명을 평문으로 캡처할 수 있기 때문입니다.

또한, 몇몇 프린터는 사용자 이름이 포함된 로그를 포함하거나 도메인 컨트롤러에서 모든 사용자 이름을 다운로드할 수도 있습니다.

이러한 **민감한 정보**와 **보안 부족**으로 인해 프린터는 공격자에게 매우 흥미로운 대상입니다.

이 주제에 대한 일부 블로그:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## 프린터 구성
- **위치**: LDAP 서버 목록은 다음 위치에서 찾을 수 있습니다: `네트워크 > LDAP 설정 > LDAP 설정 구성`.
- **동작**: 인터페이스는 자격 증명을 다시 입력하지 않고도 LDAP 서버 수정을 허용하여 사용자 편의성을 지향하지만 보안 위험을 가지고 있습니다.
- **Exploit**: 이 Exploit은 LDAP 서버 주소를 제어 가능한 기기로 리디렉션하고 "연결 테스트" 기능을 활용하여 자격 증명을 캡처하는 것을 포함합니다.

## 자격 증명 캡처

**더 자세한 단계는 원본 [소스](https://grimhacker.com/2018/03/09/just-a-printer/)를 참조하세요.**

### 방법 1: Netcat 리스너
간단한 Netcat 리스너가 충분할 수 있습니다:
```bash
sudo nc -k -v -l -p 386
```
### 방법 2: Slapd를 사용한 전체 LDAP 서버
더 신뢰할 수 있는 접근 방법은 프린터가 자격 증명 바인딩을 시도하기 전에 널 바인드와 쿼리를 수행하기 때문에 전체 LDAP 서버를 설정하는 것입니다.

1. **LDAP 서버 설정**: 이 가이드는 [이 소스](https://www.server-world.info/en/note?os=Fedora_26&p=openldap)의 단계를 따릅니다.
2. **주요 단계**:
- OpenLDAP 설치.
- 관리자 비밀번호 설정.
- 기본 스키마 가져오기.
- LDAP DB에 도메인 이름 설정.
- LDAP TLS 구성.
3. **LDAP 서비스 실행**: 설정이 완료되면 LDAP 서비스를 다음과 같이 실행할 수 있습니다:
```bash
slapd -d 2
```
## 참고 자료
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

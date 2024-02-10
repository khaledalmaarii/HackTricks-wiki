# macOS 네트워크 서비스 및 프로토콜

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

## 원격 접속 서비스

이러한 서비스는 macOS에서 원격으로 액세스하는 데 사용되는 일반적인 서비스입니다.\
`시스템 환경설정` --> `공유`에서 이러한 서비스를 활성화/비활성화할 수 있습니다.

* **VNC**, "화면 공유"로 알려져 있음 (tcp:5900)
* **SSH**, "원격 로그인"이라고 불림 (tcp:22)
* **Apple 원격 데스크톱** (ARD), 또는 "원격 관리" (tcp:3283, tcp:5900)
* **AppleEvent**, "원격 Apple 이벤트"로 알려져 있음 (tcp:3031)

활성화된 서비스가 있는지 확인하려면 다음을 실행하세요:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### ARD 펜테스팅

Apple Remote Desktop (ARD)는 macOS에 맞춰진 [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing)의 향상된 버전으로, 추가 기능을 제공합니다. ARD의 주목할만한 취약점은 제어 화면 비밀번호의 인증 방법으로, 비밀번호의 처음 8자리만 사용하여 [무차별 대입 공격](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html)과 같은 도구인 Hydra나 [GoRedShell](https://github.com/ahhh/GoRedShell/)을 사용한 공격에 취약합니다. 기본적인 속도 제한이 없기 때문입니다.

취약한 인스턴스는 **nmap**의 `vnc-info` 스크립트를 사용하여 식별할 수 있습니다. `VNC Authentication (2)`를 지원하는 서비스는 특히 8자리 비밀번호의 제한으로 인해 무차별 대입 공격에 취약합니다.

권한 상승, GUI 접근 또는 사용자 모니터링과 같은 다양한 관리 작업을 위해 ARD를 활성화하려면 다음 명령을 사용하세요:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD는 관찰, 공유 제어 및 완전한 제어와 같은 다양한 제어 수준을 제공하며, 사용자 암호 변경 후에도 세션이 지속됩니다. 이는 Unix 명령을 직접 보내고 관리자 사용자의 경우 root로 실행할 수 있도록 해줍니다. 작업 예약 및 원격 스포트라이트 검색은 여러 기기에서 민감한 파일에 대한 원격, 저영향 검색을 용이하게 하는 주목할만한 기능입니다.


## Bonjour 프로토콜

Bonjour은 Apple이 설계한 기술로, **동일한 네트워크 상의 장치가 서로 제공하는 서비스를 감지**할 수 있게 합니다. Rendezvous, Zero Configuration 또는 Zeroconf로도 알려져 있으며, 장치가 TCP/IP 네트워크에 참여하고 **자동으로 IP 주소를 선택**하며 다른 네트워크 장치에 서비스를 브로드캐스트할 수 있게 합니다.

Bonjour이 제공하는 Zero Configuration Networking을 통해 장치는 다음을 수행할 수 있습니다:
* DHCP 서버가 없어도 **자동으로 IP 주소를 얻을 수 있습니다**.
* DNS 서버를 필요로하지 않고 **이름을 주소로 변환**할 수 있습니다.
* 네트워크에서 **사용 가능한 서비스를 발견**할 수 있습니다.

Bonjour을 사용하는 장치는 **169.254/16 범위에서 IP 주소를 할당**하고 네트워크에서의 고유성을 확인합니다. Mac은 이 서브넷에 대한 라우팅 테이블 항목을 유지하며, `netstat -rn | grep 169`를 통해 확인할 수 있습니다.

Bonjour은 DNS에 Multicast DNS (mDNS) 프로토콜을 사용합니다. mDNS는 **포트 5353/UDP**를 통해 작동하며, **표준 DNS 쿼리**를 사용하지만 **멀티캐스트 주소 224.0.0.251**을 대상으로 합니다. 이 접근 방식은 네트워크의 모든 수신 장치가 쿼리를 수신하고 응답할 수 있도록 하여 레코드를 업데이트하는 것을 용이하게 합니다.

네트워크에 참여한 후, 각 장치는 일반적으로 호스트 이름에서 파생되거나 무작위로 생성된 **.local로 끝나는 이름을 자체 선택**합니다.

네트워크 내에서의 서비스 검색은 **DNS Service Discovery (DNS-SD)**에 의해 용이하게 됩니다. DNS SRV 레코드의 형식을 활용하는 DNS-SD는 **DNS PTR 레코드**를 사용하여 여러 서비스의 목록을 가능하게 합니다. 특정 서비스를 찾는 클라이언트는 `<Service>.<Domain>`에 대한 PTR 레코드를 요청하고, 여러 호스트에서 서비스를 사용할 수 있는 경우 `<Instance>.<Service>.<Domain>` 형식으로 된 PTR 레코드 목록을 반환받습니다.


`dns-sd` 유틸리티는 **네트워크 서비스 검색 및 광고**에 사용될 수 있습니다. 다음은 그 사용 예시입니다:

### SSH 서비스 검색

네트워크에서 SSH 서비스를 검색하려면 다음 명령을 사용합니다:
```bash
dns-sd -B _ssh._tcp
```
이 명령은 _ssh._tcp 서비스를 찾아 세부 정보를 타임스탬프, 플래그, 인터페이스, 도메인, 서비스 유형 및 인스턴스 이름과 함께 출력합니다.

### HTTP 서비스 광고하기

HTTP 서비스를 광고하려면 다음을 사용할 수 있습니다:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
이 명령은 포트 80에 "/index.html" 경로를 가진 "Index"라는 HTTP 서비스를 등록합니다.

그런 다음 네트워크에서 HTTP 서비스를 검색하려면:
```bash
dns-sd -B _http._tcp
```
서비스가 시작되면, 해당 서비스는 자신의 존재를 멀티캐스트하여 서브넷의 모든 장치에 알립니다. 이 서비스에 관심 있는 장치들은 요청을 보내지 않고 이러한 알림을 수신하기만 하면 됩니다.

더 사용자 친화적인 인터페이스를 위해, Apple App Store에서 제공되는 **Discovery - DNS-SD Browser** 앱을 사용하면 로컬 네트워크에서 제공되는 서비스를 시각화할 수 있습니다.

또는, `python-zeroconf` 라이브러리를 사용하여 서비스를 탐색하고 발견하기 위해 사용자 정의 스크립트를 작성할 수 있습니다. [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) 스크립트는 `_http._tcp.local.` 서비스를 위한 서비스 브라우저를 생성하고 추가된 또는 제거된 서비스를 출력하는 예제입니다:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Bonjour 비활성화
보안에 대한 우려나 다른 이유로 Bonjour을 비활성화하려면 다음 명령을 사용하여 비활성화할 수 있습니다:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 참고 자료

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

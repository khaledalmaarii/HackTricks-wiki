<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **깃허브 저장소에 제출**하세요.

</details>


## Logstash

Logstash는 **로그를 수집, 변환 및 전송**하기 위해 **파이프라인**이라고 하는 시스템을 통해 사용됩니다. 이러한 파이프라인은 **입력**, **필터**, **출력** 단계로 구성됩니다. Logstash가 침해된 기기에서 작동할 때 흥미로운 측면이 나타납니다.

### 파이프라인 구성

파이프라인은 **/etc/logstash/pipelines.yml** 파일에서 구성되며, 이 파일은 파이프라인 구성의 위치를 나열합니다:
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
이 파일은 파이프라인 구성을 포함하는 **.conf** 파일이 위치한 곳을 나타냅니다. **Elasticsearch 출력 모듈**을 사용할 때, **파이프라인**에는 종종 Logstash가 Elasticsearch에 데이터를 쓰기 위해 필요한 광범위한 권한을 가진 **Elasticsearch 자격 증명**이 포함됩니다. 구성 경로의 와일드카드를 사용하면 Logstash는 지정된 디렉토리에서 일치하는 모든 파이프라인을 실행할 수 있습니다.

### 쓰기 가능한 파이프라인을 통한 권한 상승

권한 상승을 시도하기 위해 먼저 Logstash 서비스가 실행되는 사용자, 일반적으로 **logstash** 사용자를 식별합니다. 다음 중 **하나**의 조건을 충족해야 합니다:

- 파이프라인 **.conf** 파일에 **쓰기 권한**을 가지고 있거나
- **/etc/logstash/pipelines.yml** 파일이 와일드카드를 사용하고 대상 폴더에 쓸 수 있는 경우

또한 다음 중 **하나**의 조건이 충족되어야 합니다:

- Logstash 서비스를 다시 시작할 수 있는 권한이 있는 경우 **또는**
- **/etc/logstash/logstash.yml** 파일에 **config.reload.automatic: true**가 설정되어 있는 경우

구성에서 와일드카드가 제공된 경우, 이와 일치하는 파일을 생성하면 명령 실행이 가능합니다. 예를 들어:
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
여기서 **interval**은 실행 빈도를 초 단위로 결정합니다. 주어진 예제에서 **whoami** 명령은 120초마다 실행되며, 출력은 **/tmp/output.log**로 이동됩니다.

**/etc/logstash/logstash.yml**에 있는 **config.reload.automatic: true**를 사용하면, Logstash는 자동으로 새로운 또는 수정된 파이프라인 구성을 감지하고 적용합니다. 와일드카드가 없는 경우에도 기존 구성에 수정을 가할 수 있지만, 중단을 피하기 위해 주의가 필요합니다.


## 참고 자료

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹 배우기<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

# Python 내부 읽기 가젯

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 기본 정보

[**Python 포맷 문자열**](bypass-python-sandboxes/#python-format-string) 또는 [**클래스 오염**](class-pollution-pythons-prototype-pollution.md)과 같은 다양한 취약점은 **Python 내부 데이터를 읽을 수 있지만 코드를 실행할 수는 없을 수도 있습니다**. 따라서 펜테스터는 이러한 읽기 권한을 최대한 활용하여 **민감한 권한을 획득하고 취약점을 승격**해야 할 것입니다.

### Flask - 비밀 키 읽기

Flask 애플리케이션의 메인 페이지에는 이 **비밀 키가 구성된** **`app`** 전역 객체가 있을 것입니다.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
이 경우에는 [**Python 샌드박스 우회 페이지**](bypass-python-sandboxes/)에서 **전역 객체에 접근**하기 위해 어떤 가젯을 사용하여 이 객체에 액세스할 수 있습니다.

**취약점이 다른 Python 파일에 있는 경우**에는 메인 파일에 접근하기 위해 파일을 탐색하는 가젯이 필요합니다. 이를 통해 Flask 비밀 키를 변경하고 [**이 키를 알고 권한을 상승**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)시킬 수 있습니다.

[이 writeup](https://ctftime.org/writeup/36082)에서 제공하는 다음과 같은 페이로드를 사용할 수 있습니다:

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

이 페이로드를 사용하여 `app.secret_key` (앱에서의 이름은 다를 수 있음)를 변경하여 새로운 권한을 가진 flask 쿠키를 서명할 수 있습니다.

### Werkzeug - machine\_id 및 node uuid

[**이 글에서 제공하는 페이로드를 사용하여**](https://vozec.fr/writeups/tweedle-dum-dee/) **machine\_id**와 **uuid** 노드에 액세스할 수 있으며, 이는 [**Werkzeug pin을 생성하는 데 필요한 주요 비밀**](../../network-services-pentesting/pentesting-web/werkzeug.md)입니다. 디버그 모드가 활성화된 경우 `/console`에서 python 콘솔에 액세스할 수 있습니다.
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
`app.py`의 **서버 로컬 경로**를 얻으려면 웹 페이지에서 **오류를 생성**하여 **경로를 얻을 수 있습니다**.
{% endhint %}

만약 취약점이 다른 파이썬 파일에 있다면, 메인 파이썬 파일에서 객체에 접근하기 위한 이전 Flask 트릭을 확인하세요.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

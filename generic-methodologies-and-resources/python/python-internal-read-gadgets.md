# Python 내부 Read 가젯

{% hint style="success" %}
AWS 해킹 배우고 실습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우고 실습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}

## 기본 정보

[**Python Format Strings**](bypass-python-sandboxes/#python-format-string) 또는 [**Class Pollution**](class-pollution-pythons-prototype-pollution.md)과 같은 다양한 취약점은 **파이썬 내부 데이터를 읽을 수 있지만 코드 실행은 허용하지 않을 수 있습니다**. 따라서, 펜테스터는 이러한 읽기 권한을 최대한 활용하여 **민감한 권한을 획들하고 취약점을 승격**해야 할 것입니다.

### Flask - 시크릿 키 읽기

Flask 애플리케이션의 메인 페이지에는 아마도 **`app`** 글로벌 객체가 있을 것이며, 여기에 **시크릿이 구성**될 것입니다.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
이 경우 [**Python 샌드박스 우회 페이지**](bypass-python-sandboxes/)에서 **전역 객체에 액세스**하기 위해 어떤 가젯을 사용할 수 있습니다.

**취약점이 다른 Python 파일에 있는 경우**, 주 파일에 액세스하기 위해 파일을 탐색하는 가젯이 필요하며 Flask 시크릿 키를 변경하고 [**이 키를 알고 권한 상승**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)할 수 있습니다.

[이 writeup에서](https://ctftime.org/writeup/36082) 이와 유사한 페이로드:

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

이 페이로드를 사용하여 `app.secret_key`를 변경하여 새로운 권한을 부여받은 플라스크 쿠키를 서명할 수 있습니다.

### Werkzeug - machine\_id 및 node uuid

[**이 문서에서 제공하는 페이로드를 사용하면**](https://vozec.fr/writeups/tweedle-dum-dee/) **machine\_id** 및 **uuid** 노드에 액세스할 수 있으며, 이는 [**Werkzeug 핀을 생성하는 데 필요한 주요 비밀**](../../network-services-pentesting/pentesting-web/werkzeug.md)입니다. 이 핀을 사용하여 `/console`에서 파이썬 콘솔에 액세스할 수 있습니다. **디버그 모드가 활성화된 경우:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
**`app.py`**에 대한 **서버 로컬 경로를 얻을 수 있습니다**. 웹 페이지에서 **오류를 발생**시켜 **경로를 얻을 수 있습니다**.
{% endhint %}

만약 취약점이 다른 파이썬 파일에 있다면, 주요 파이썬 파일에서 객체에 액세스하기 위한 이전 Flask 트릭을 확인하세요.

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* 해킹 트릭을 공유하려면 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
{% endhint %}

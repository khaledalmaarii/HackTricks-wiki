{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}


# ECB

(ECB) 전자 코드북 - 각 **일반 텍스트 블록을** **암호문 블록으로 대체**하는 대칭 암호화 방식입니다. 이것은 **가장 간단한** 암호화 방식입니다. 주요 아이디어는 일반 텍스트를 **N 비트 블록**으로 **분할**하고(입력 데이터 블록 크기, 암호화 알고리즘에 따라 다름) 그런 다음 단 하나의 키를 사용하여 각 일반 텍스트 블록을 암호화(복호화)하는 것입니다.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

ECB 사용에는 여러 보안 문제가 있습니다:

* **암호화된 메시지에서 블록을 제거할 수 있음**
* **암호화된 메시지에서 블록을 이동할 수 있음**

# 취약점 탐지

어떤 응용 프로그램에 여러 번 로그인하고 **항상 동일한 쿠키**를 받는다고 상상해보세요. 이것은 응용 프로그램의 쿠키가 **`<사용자명>|<비밀번호>`**인 경우입니다.\
그런 다음 **거의** **동일한 사용자명**을 가진 **동일한 긴 비밀번호**를 가진 두 명의 새 사용자를 생성합니다.\
두 사용자의 정보가 동일한 **8바이트 블록**인 것을 발견했습니다. 그런 다음 이것이 **ECB가 사용 중**이기 때문일 수 있다고 상상해봅니다.

다음 예제와 같이. 이 **2개의 디코딩된 쿠키**가 여러 번 블록 **`\x23U\xE45K\xCB\x21\xC8`**을 가지고 있음을 관찰하세요.
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
이것은 **쿠키의 사용자 이름과 비밀번호에 "a"라는 문자가 여러 번 포함**되어 있기 때문입니다. **다른 블록**은 **적어도 1개의 다른 문자**를 포함한 블록입니다(아마도 구분 기호 "|" 또는 사용자 이름에 필요한 어떤 차이).

이제 공격자는 형식이 `<사용자 이름><구분 기호><비밀번호>`인지 아니면 `<비밀번호><구분 기호><사용자 이름>`인지 발견하기만 하면 됩니다. 이를 위해 그는 **유사하고 긴 사용자 이름과 비밀번호를 가진 여러 사용자 이름을 생성하여 형식과 구분 기호의 길이를 찾을 수 있습니다:**

| 사용자 이름 길이: | 비밀번호 길이: | 사용자 이름+비밀번호 길이: | 디코딩 후 쿠키의 길이: |
| ---------------- | ---------------- | ------------------------- | --------------------------------- |
| 2                | 2                | 4                         | 8                                 |
| 3                | 3                | 6                         | 8                                 |
| 3                | 4                | 7                         | 8                                 |
| 4                | 4                | 8                         | 16                                |
| 7                | 7                | 14                        | 16                                |

# 취약점의 악용

## 전체 블록 제거

쿠키의 형식을 알고 있다면 (`<사용자 이름>|<비밀번호>`), 사용자 이름 `admin`을 피해자로 만들기 위해 `aaaaaaaaadmin`이라는 새 사용자를 생성하고 쿠키를 가져와 디코딩하세요:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
이전에 `a`만 포함된 사용자 이름으로 생성된 패턴 `\x23U\xE45K\xCB\x21\xC8`을 볼 수 있습니다.\
그런 다음, 첫 번째 블록 8B를 제거하면 사용자 이름이 `admin`인 유효한 쿠키를 얻을 수 있습니다:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## 블록 이동

많은 데이터베이스에서 `WHERE username='admin';` 또는 `WHERE username='admin    ';`를 검색하는 것은 동일합니다. _(추가 공백에 유의)_

따라서 사용자 `admin`을 표현하는 또 다른 방법은 다음과 같습니다:

* 다음을 만족하는 사용자 이름을 생성합니다: `len(<username>) + len(<delimiter) % len(block)`. 블록 크기가 `8B`인 경우 `username       `이라는 사용자 이름을 생성할 수 있으며, 구분 기호 `|`와 함께 청크 `<username><delimiter>`는 8B의 2개 블록을 생성합니다.
* 그런 다음, 사용자 이름과 공백을 포함하는 정확한 수의 블록을 채우는 비밀번호를 생성합니다. 예를 들어: `admin   `

이 사용자의 쿠키는 3개의 블록으로 구성됩니다: 처음 2개는 사용자 이름 + 구분 기호의 블록이고, 세 번째는 사용자 이름을 위조하는 비밀번호의 블록입니다: `username       |admin   `

**그런 다음, 첫 번째 블록을 마지막 블록으로 교체하면 사용자 `admin`을 표현하게 됩니다: `admin          |username`**

## 참고 자료

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))

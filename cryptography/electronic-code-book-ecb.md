<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>


# ECB

(ECB) 전자 코드 북 - 각 블록의 평문을 암호문 블록으로 **대체**하는 대칭 암호화 방식입니다. 가장 **간단한** 암호화 방식입니다. 주요 아이디어는 평문을 N 비트 블록(입력 데이터 블록 크기, 암호화 알고리즘에 따라 다름)으로 **분할**한 다음, 유일한 키를 사용하여 각 평문 블록을 암호화(복호화)하는 것입니다.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

ECB 사용은 여러 보안 문제를 야기할 수 있습니다:

* 암호화된 메시지의 **블록이 제거**될 수 있습니다.
* 암호화된 메시지의 **블록이 이동**될 수 있습니다.

# 취약점 탐지

어떤 애플리케이션에 여러 번 로그인하고 항상 **동일한 쿠키**를 받는다고 상상해보세요. 이는 애플리케이션의 쿠키가 **`<사용자명>|<비밀번호>`**인 것입니다.\
그런 다음, **동일한 긴 비밀번호**와 **거의** **동일한** **사용자명**을 가진 새로운 사용자를 생성합니다.\
두 사용자의 정보가 동일한 **8B 블록**이 **동일**함을 발견합니다. 그럼 이것은 아마도 **ECB가 사용되고 있을 수 있다는 것**을 상상해볼 수 있습니다.

다음 예시와 같이, 이 **2개의 디코딩된 쿠키**에는 여러 번 블록 **`\x23U\xE45K\xCB\x21\xC8`**이 포함되어 있음을 관찰하세요.
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
이는 해당 쿠키의 **사용자 이름과 비밀번호에 여러 번 "a" 문자가 포함**되어 있기 때문입니다. **다른 블록**은 적어도 1개의 다른 문자(아마도 구분 기호 "|" 또는 사용자 이름에 필요한 차이)가 포함된 블록입니다.

이제 공격자는 형식이 `<사용자 이름><구분 기호><비밀번호>` 또는 `<비밀번호><구분 기호><사용자 이름>`인지 알아내기만 하면 됩니다. 이를 위해 그는 **유사하고 긴 사용자 이름과 비밀번호를 가진 여러 사용자 이름**을 생성하여 형식과 구분 기호의 길이를 찾을 수 있습니다:

| 사용자 이름 길이 | 비밀번호 길이 | 사용자 이름+비밀번호 길이 | 쿠키의 길이 (디코딩 후): |
| ---------------- | ---------------- | ------------------------- | --------------------------------- |
| 2                | 2                | 4                         | 8                                 |
| 3                | 3                | 6                         | 8                                 |
| 3                | 4                | 7                         | 8                                 |
| 4                | 4                | 8                         | 16                                |
| 7                | 7                | 14                        | 16                                |

# 취약점의 악용

## 전체 블록 제거

쿠키의 형식(`<사용자 이름>|<비밀번호>`)을 알고 있다면, 사용자 이름 `admin`을 가장하려면 `aaaaaaaaadmin`이라는 새 사용자를 생성하고 쿠키를 가져와 디코딩하면 됩니다:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
이전에 'a'만을 포함한 사용자 이름으로 생성된 패턴 `\x23U\xE45K\xCB\x21\xC8`을 볼 수 있습니다.\
그런 다음, 첫 번째 8B 블록을 제거하면 사용자 이름이 `admin`인 유효한 쿠키를 얻을 수 있습니다.
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## 블록 이동

많은 데이터베이스에서 `WHERE username='admin';` 또는 `WHERE username='admin    ';` (추가 공백에 주목)와 같이 검색하는 것은 동일합니다.

따라서, 사용자 `admin`을 표현하는 또 다른 방법은 다음과 같습니다:

* `len(<username>) + len(<delimiter) % len(block)`와 같이 길이가 `8B`인 블록을 사용하여 `username       `이라는 이름의 사용자 이름을 생성할 수 있습니다. 구분자 `|`와 함께 청크 `<username><delimiter>`는 8B의 2개 블록을 생성합니다.
* 그런 다음, 원하는 사용자 이름과 공백이 포함된 블록의 정확한 수를 채우는 비밀번호를 생성합니다. 예를 들어, `admin   `입니다.

이 사용자의 쿠키는 3개의 블록으로 구성됩니다: 첫 번째 2개는 사용자 이름 + 구분자 블록이고 세 번째는 비밀번호 블록입니다 (사용자 이름을 가장한 것입니다): `username       |admin   `

**그런 다음, 첫 번째 블록을 마지막 블록으로 대체하면 사용자 `admin`을 표현하게 됩니다: `admin          |username`**

## 참고 자료

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

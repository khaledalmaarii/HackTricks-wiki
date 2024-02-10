<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왑**](https://peass.creator-spring.com)을 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="크리에이티브 커먼즈 라이선스" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>저작권 © Carlos Polop 2021. (책에 복사된 외부 정보는 원래 저작자에게 속합니다.) Carlos Polop의 <a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a>의 텍스트는 <a href="https://creativecommons.org/licenses/by-nc/4.0/">크리에이티브 커먼즈 저작자표시-비영리 4.0 국제 라이선스</a>에 따라 라이선스가 부여됩니다.

라이선스: 저작자표시-비영리 4.0 국제<br>
사람이 읽을 수 있는 라이선스: https://creativecommons.org/licenses/by-nc/4.0/<br>
전체 법적 약관: https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>
서식: https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# 크리에이티브 커먼즈

# 저작자표시-비영리 4.0 국제

크리에이티브 커먼즈 코퍼레이션("크리에이티브 커먼즈")은 법률 사무소가 아니며 법률 서비스나 법률 상담을 제공하지 않습니다. 크리에이티브 커먼즈의 공개 라이선스 배포는 변호사-의뢰인 또는 기타 관계를 형성하지 않습니다. 크리에이티브 커먼즈는 라이선스와 관련된 정보를 "있는 그대로" 제공합니다. 크리에이티브 커먼즈는 라이선스, 해당 조건에 따라 라이선스된 자료 또는 관련 정보에 대해 어떠한 보증도 제공하지 않습니다. 크리에이티브 커먼즈는 그 사용으로 인한 손해에 대해 최대한의 책임을 부인합니다.

## 크리에이티브 커먼즈 공개 라이선스 사용

크리에이티브 커먼즈 공개 라이선스는 저작자와 기타 권리자가 저작권 및 특정 다른 권리에 따라 제한된 방식으로 원작 및 기타 저작물을 공유하기 위해 사용할 수 있는 표준 약관을 제공합니다. 다음 고려 사항은 정보 제공을 목적으로 하며, 철저하지 않으며, 라이선스의 일부가 아닙니다.

* __라이선서를 위한 고려 사항:__ 공개 라이선스는 저작권 및 특정 다른 권리에 의해 제한되는 방식으로 자료를 사용할 수 있는 권한을 부여할 수 있는 권한을 가진 사람들이 사용하기 위해 고안되었습니다. 라이선스는 철회할 수 없습니다. 라이선서는 적용하기 전에 선택한 라이선스의 조건을 읽고 이해해야 합니다. 라이선서는 자료를 예상대로 공중에서 재사용할 수 있도록 하기 위해 라이선스를 적용하기 전에 필요한 모든 권리를 확보해야 합니다. 라이선서는 라이선스의 적용 대상이 아닌 자료를 명확하게 표시해야 합니다. 이에는 다른 CC-라이선스 자료 또는 저작권 예외 또는 제한을 적용한 자료가 포함됩니다. [라이선서를 위한 추가 고려 사항](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors).

* __일반인을 위한 고려 사항:__ 공개 라이선스 중 하나를 사용함으로써 라이선서는 특정 조건과 조건에 따라 라이선스된 자료를 사용할 권한을 대줍니다. 라이선서의 허가가 필요하지 않은 경우(예: 저작권 예외 또는 제한 때문에) 해당 사용은 라이선스에 의해 규제되지 않습니다. 라이선스는 라이선서가 권한을 부여할 수 있는 저작권 및 특정 다른 권리에 대한 권한만 부여합니다. 라이선스된 자료의 사용은 여전히 다른 이유로 제한될 수 있습니다. 이는 다른 사람이 해당 자료에 저작권 또는 기타 권리를 가지고 있기 때문일 수 있습니다. 라이선서는 모든 변경 사항을 표시하거나 설명할 것을 요청할 수 있습니다. 라이선스에서 요구하지 않지만 합리적인 경우 해당 요청을 존중하는 것이 좋습니다. [일반인을 위한 추가 고려 사항](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees).

# 크리에이티브 커먼즈 저작자표시-비영리 4.0 국제 공개 라이선스

라이선스 권리(아래 정의)를 행사함으로써 여러분은 이 크리에이티브 커먼즈 저작자표시-비영리 4.0 국제 공개 라이선스("공개 라이선스")의 조건
## 섹션 2 - 범위.

a. ___라이선스 부여.___

1. 이 공개 라이선스의 조건에 따라, 라이선서는 여러분에게 전 세계적으로 무료로, 비하위 라이선스 가능한, 배타적이지 않은, 철회할 수 없는 라이선스를 부여합니다. 여러분은 라이선스된 자료에 대한 라이선스 권한을 행사할 수 있습니다.

A. 비상업적 목적으로만 전체 또는 일부 라이선스 자료를 복제하고 공유할 수 있습니다.

B. 비상업적 목적으로 적응된 자료를 생성, 복제 및 공유할 수 있습니다.

2. __예외와 제한사항.__ 명확히 하기 위해, 예외와 제한사항이 여러분의 사용에 적용되는 경우, 이 공개 라이선스는 적용되지 않으며, 여러분은 이의 조건을 준수할 필요가 없습니다.

3. __기간.__ 이 공개 라이선스의 기간은 섹션 6(a)에 명시되어 있습니다.

4. __미디어 및 형식; 기술적 수정 허용.__ 라이선서는 여러분이 알려진 미디어와 형식을 통해 라이선스 권한을 행사하고, 이를 위해 필요한 기술적 수정을 할 수 있도록 허용합니다. 라이선서는 여러분이 라이선스 권한을 행사하기 위해 필요한 기술적 수정, 즉 효과적인 기술적 조치를 우회하기 위한 기술적 수정을 금지하거나 어떠한 권리나 권한을 주장하지 않습니다. 이 공개 라이선스의 목적을 위해, 이 섹션 2(a)(4)에 따라 허용된 수정만으로는 적응된 자료가 생성되지 않습니다.

5. __하류 수령인.__

A. __라이선서로부터의 제안 - 라이선스 자료.__ 라이선스 자료의 모든 수령인은 자동으로 이 공개 라이선스의 조건에 따라 라이선스 권한을 행사할 수 있는 제안을 라이선서로부터 받게 됩니다.

B. __하류 제한 없음.__ 여러분은 라이선스 자료의 수령인이 라이선스 권한을 행사하는 것을 제한하는 추가적인 또는 다른 조건을 부과하거나 효과적인 기술적 조치를 적용해서는 안 됩니다.

6. __지지 표시 없음.__ 이 공개 라이선스에는 라이선서나 다른 사람들이 섹션 3(a)(1)(A)(i)에서 제공된 속성을 받기로 지정된 다른 사람들과 연결되어 있거나, 후원되거나, 공식적인 지위가 부여된다는 것을 주장하거나 시사하는 권한이나 허가를 부여한다는 것을 의미하는 것은 아닙니다.

b. ___기타 권리.___

1. 라이선스자의 도덕적 권리, 예를 들어 무결성 권리는 이 공개 라이선스에 따라 라이선스되지 않으며, 홍보, 개인 정보 보호 및/또는 기타 유사한 인격권도 라이선스되지 않습니다. 그러나 가능한 한 라이선서는 여러분이 라이선스 권한을 행사할 수 있도록 필요한 범위 내에서 해당 권리를 포기하거나 주장하지 않습니다.

2. 특허 및 상표권은 이 공개 라이선스에 따라 라이선스되지 않습니다.

3. 가능한 한 라이선서는 여러분이 비상업적 목적 이외의 용도로 라이선스 자료를 사용함에 따라 여러분으로부터 로열티를 징수하는 권리를 포기합니다. 이에는 자발적이거나 포기 가능한 법적 라이선싱 체계에 따라 징수 단체를 통해 직접적으로 또는 간접적으로 로열티를 징수하는 경우를 포함합니다. 다른 모든 경우에는 라이선서는 비상업적 목적 이외의 용도로 라이선스 자료가 사용될 때를 포함하여 이러한 로열티를 징수하기 위한 어떠한 권리도 명시적으로 보유합니다.

## 섹션 3 - 라이선스 조건.

라이선스 권한의 행사는 명시적으로 다음 조건에 따라야 합니다.

a. ___표시.___

1. 라이선스 자료를 공유할 경우 (수정된 형태로 포함), 다음을 유지해야 합니다:

A. 라이선서로부터 라이선스 자료와 함께 제공된 경우 다음을 유지해야 합니다:

i. 라이선스 자료의 창작자 및 속성을 받기로 지정된 다른 사람들의 식별, 라이선서가 요청한 합리적인 방법으로 (지정된 경우 익명으로) 포함합니다.

ii. 저작권 고지.

iii. 이 공개 라이선스를 참조하는 고지.

iv. 보증의 부인을 참조하는 고지.

v. 합리적으로 실행 가능한 범위 내에서 라이선스 자료로의 URI 또는 하이퍼링크.

B. 라이선스 자료를 수정한 경우 수정한 사실을 나타내고 이전 수정 사항을 표시해야 합니다.

C. 라이선스 자료가 이 공개 라이선스에 따라 라이선스되었음을 나타내고, 이 공개 라이선스의 텍스트 또는 URI 또는 하이퍼링크를 포함해야 합니다.

2. 여러분은 섹션 3(a)(1)의 조건을 여러분이 라이선스 자료를 공유하는 미디어, 수단 및 문맥에 기반하여 합리적인 방법으로 충족시킬 수 있습니다. 예를 들어, 필요한 정보를 포함하는 리소스로의 URI 또는 하이퍼링크를 제공함으로써 조건을 충족시키는 것이 합리적일 수 있습니다.

3. 라이선서가 요청한 경우, 섹션 3(a)(1)(A)에 필요한 정보를 합리적으로 실행 가능한 범위 내에서 제거해야 합니다.

4. 여러분이 생성한 적응된 자료를 공유하는 경우, 적응자의 라이선스는 이 공개 라이선스의 조건을 준수하는 데 수령인을 제한해서는 안 됩니다.

## 섹션 4 - Sui Generis 데이터베이스 권리.

라이선스 권한이 여러분의 라이선스 자료 사용에 적용되는 Sui Generis 데이터베이스 권리를 포함하는 경우:

a. 명확히 하기 위해, 섹션 2(a)(1)은 비상업적 목적으로 데이터베이스의 내용 전체 또는 실질적인 일부를 추출, 재사용, 복제 및 공유할 권리를 여러분에게 부여합니다.

b. 여러분이 Sui Generis 데이터베이스 권리를 가진 데이터베이스에 데이터베이스의 내용 전체 또는 실질적인 일부를 포함하는 경우, 여러분이 Sui Generis 데이터베이스 권리를 가진 데이터베이스
## 섹션 7 - 기타 약관 및 조건.

a. 라이선서는 명시적으로 동의하지 않는 한, 당신이 전달한 추가적이거나 다른 약관 또는 조건에 구속되지 않습니다.

b. 본 공개 라이선스의 약관과 조건과 별도로, 라이선스된 자료에 관한 어떠한 정리, 이해 또는 합의도 여기에 명시되지 않으며 독립적입니다.

## 섹션 8 - 해석.

a. 명확히 하기 위해, 본 공개 라이선스는 본 공개 라이선스에 따른 허가 없이 합법적으로 이루어질 수 있는 라이선스 자료의 사용에 대해 줄이거나 제한하거나 조건을 부과하지 않습니다.

b. 가능한 한, 본 공개 라이선스의 어떤 조항이 시행할 수 없다고 판단되면, 그 조항은 시행 가능하도록 최소한의 범위로 자동으로 개정됩니다. 조항을 개정할 수 없는 경우, 그 조항은 본 공개 라이선스에서 분리되어 남은 약관과 조건의 시행 가능성에 영향을 미치지 않습니다.

c. 라이선서의 명시적인 동의 없이는 본 공개 라이선스의 어떤 조건도 포기되지 않으며, 준수하지 않은 것으로 간주되지 않습니다.

d. 본 공개 라이선스에는 라이선서 또는 당신에게 적용되는 권리와 면제 사항, 특히 어떠한 관할권이나 권한의 법적 절차로부터의 면제에 대한 제한 또는 포기로 해석되지 않습니다.
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

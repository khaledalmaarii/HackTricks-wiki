{% hint style="success" %}
学习和实践AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>版权所有 © Carlos Polop 2021。  除非另有规定（复制到书中的外部信息属于原始作者），Carlos Polop 的 <a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a> 上的文本受 <a href="https://creativecommons.org/licenses/by-nc/4.0/">知识共享署名-非商业性使用 4.0 国际许可协议 (CC BY-NC 4.0)</a> 许可。

许可证：署名-非商业性使用 4.0 国际许可协议（CC BY-NC 4.0）<br>
人类可读许可证：https://creativecommons.org/licenses/by-nc/4.0/<br>
完整法律条款：https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>
格式：https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# 创意共享

# 署名-非商业性使用 4.0 国际

创意共享公司（“创意共享”）不是律师事务所，也不提供法律服务或法律建议。创意共享公共许可的分发不会创建律师-客户或其他关系。创意共享以“原样”提供其许可证和相关信息。创意共享不对其许可证、根据其条款和条件许可的任何材料或任何相关信息提供任何担保。创意共享尽可能地免除因使用而导致的所有责任。

## 使用创意共享公共许可证

创意共享公共许可证提供了一套标准的条款和条件，创作者和其他权利持有人可以使用这些条款和条件来分享原创作品和其他受版权和某些其他权利约束的材料。以下考虑仅供信息目的，不是详尽无遗的，并且不构成我们许可证的一部分。

* __授权者的考虑：__ 我们的公共许可证适用于那些有权向公众授予以其他方式受版权和某些其他权利限制的材料使用许可的人。我们的许可证是不可撤销的。授权者在应用许可证之前应阅读并理解他们选择的许可证的条款和条件。授权者还应在应用我们的许可证之前获得所有必要的权利，以便公众可以按预期重用材料。授权者应清楚标记任何不受许可证约束的材料。这包括其他 CC 许可的材料，或者根据版权例外或限制使用的材料。[更多授权者的考虑](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors)。

* __公众的考虑：__ 通过使用我们的公共许可证之一，授权者授予公众根据指定的条款和条件使用受许可材料的许可。如果由于任何适用的版权例外或限制而不需要授权者的许可，例如由于任何适用的版权例外或限制，那么该使用不受许可证管辖。我们的许可证仅授予授权者有权授予的版权和某些其他权利下的权限。对于其他原因，例如其他人对材料拥有版权或其他权利，对受许可材料的使用仍可能受限制。授权者可以提出特殊要求，例如要求标记或描述所有更改。虽然我们的许可证不要求这样做，但鼓励您在合理的情况下尊重这些要求。[更多公众的考虑](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees)。

# 创意共享署名-非商业性使用 4.0 国际公共许可协议

通过行使许可权（下文定义），您接受并同意受本创意共享署名-非商业性使用 4.0 国际公共许可协议（“公共许可证”）的条款和条件约束。在某种程度上，如果本公共许可证可被解释为合同，您在接受这些条款和条件的同时被授予许可权，并且许可人出于使受许可材料根据这些条款和条件可用而获得的利益，向您授予这些权利。

## 第 1 节 – 定义。

a. __改编材料__ 指根据许可材料衍生或基于许可材料的受版权和类似权利的材料，在这些材料中，许可材料被翻译、改变、排列、转换或以其他方式修改，这些修改需要许可人持有的受版权和类似权利的许可。对于本公共许可证，如果许可材料是音乐作品、表演或声音录制，那么只要许可材料与移动图像同步，就会产生改编材料。

b. __适配者的许可证__ 指您根据本公共许可证的条款和条件，对您对改编材料的贡献中的受版权和类似权利应用的许可证。

c. __版权和类似权利__ 指与版权密切相关的版权和/或类似权利，包括但不限于表演、广播、声音录制和独创性数据库权利，不考虑这些权利如何被标记或分类。对于本公共许可证，第 2(b)(1)-(2) 节中指定的权利不属于版权和类似权利。

d. __有效技术措施__ 指在没有适当授权的情况下，根据 1996 年 12 月 20 日通过的《世界知识产权组织版权条约》第 11 条义务履行法律下，不得规避的措施，以及类似的国际协议。

e. __例外和限制__ 指适用于您对许可材料使用的版权和类似权利的公平使用、公平交易和/或任何其他例外或限制。

f. __许可材料__ 指许可人应用本公共许可证的艺术作品、文学作品、数据库或其他材料。

g. __许可权利__ 指根据本公共许可证的条款和条件授予您的权利，这些权利仅限于适用于您对许可材料使用的所有版权和类似权利，并且许可人有权许可这些权利。

h. __许可人__ 指授予本公共许可证下的权利的个人或实体。

i. __非商业性__ 指不主要用于或针对商业优势或货币补偿。对于本公共许可证，通过数字文件共享或类似方式将许可材料交换为其他受版权和类似权利的材料是非商业性的，只要在交换过程中没有支付货币补偿。

j. __分享__ 指通过任何需要许可权的方式或过程向公众提供材料，例如复制、公开展示、公开表演、分发、传播、传播或进口，并使材料可供公众访问，包括以公众可以在自己选择的时间和地点访问材料的方式。

k. __独创性数据库权利__ 指除版权外的其他权利，源自欧洲议会和理事会于 1996 年 3 月 11 日通过的《数据库法律保护指令》（Directive 96/9/EC），以及在世界其他地方具有本质上等效权利。

l. __您__ 指根据本公共许可证行使许可权利的个人或实体。您具有相应的含义。
## 第2节 - 范围。

a. ___许可授予。___

1. 根据本公共许可证的条款和条件，许可方特此向您授予全球范围内、免费、不可转让、非独占、不可撤销的许可，行使许可材料中的许可权，以便：

A. 仅限非商业目的复制和共享许可材料的全部或部分内容；以及

B. 为仅限非商业目的生产、复制和共享改编材料。

2. __例外和限制。__ 为避免疑义，如果例外和限制适用于您的使用，本公共许可证不适用，您无需遵守其条款和条件。

3. __期限。__ 本公共许可证的期限在第6(a)节中指定。

4. __媒体和格式；允许技术修改。__ 许可方授权您在现在已知或今后创建的所有媒体和格式中行使许可权，并进行必要的技术修改。许可方放弃和/或同意不主张任何权利或权限禁止您进行必要的技术修改以行使许可权，包括规避有效技术措施所需的技术修改。根据本公共许可证的目的，仅仅进行本节2(a)(4)部分授权的修改永远不会产生改编材料。

5. __下游接收方。__

A. __许可方提供 - 许可材料。__ 每个许可材料的接收方自动收到许可方的提供，以便根据本公共许可证的条款和条件行使许可权。

B. __无下游限制。__ 如果这样做限制了任何许可材料的接收方行使许可权，您不得提供或强加任何额外或不同的条款或条件，或应用任何有效技术措施到许可材料上。

6. __无认可。__ 本公共许可证中的任何内容都不构成或不得被解释为许可主张或暗示您与许可方或其他被指定接收署名的人有关联，或得到赞助、认可或官方地位的许可方或其他人。

b. ___其他权利。___

1. 道德权利，如完整性权利，不在本公共许可证下授权，宣传、隐私和/或其他类似人格权利也不在其中；然而，许可方尽可能放弃和/或同意不主张许可方持有的任何此类权利，以允许您行使许可权，但其他情况除外。

2. 专利和商标权不在本公共许可证下授权。

3. 尽可能，许可方放弃从您那里收取行使许可权的版税的权利，无论是直接还是通过任何自愿或可放弃的法定或强制性许可计划下的代收机构。在所有其他情况下，许可方明确保留收取此类版税的权利，包括在许可材料用于非商业目的以外的情况下。

## 第3节 - 许可条件。

您行使许可权明确受以下条件约束。

a. ___归属。___

1. 如果您共享许可材料（包括修改形式），您必须：

A. 保留以下由许可方提供的内容，如果有的话：

i. 许可材料的创作者和任何其他被指定接收署名的人的身份，以许可方要求的任何合理方式（包括如果被指定，使用化名）；

ii. 版权声明；

iii. 指向本公共许可证的通知；

iv. 指向担保声明的通知；

v. 在合理可行的范围内，指向许可材料的URI或超链接；

B. 指示您是否修改了许可材料，并保留任何先前修改的指示；以及

C. 指示许可材料是根据本公共许可证许可的，并包括本公共许可证的文本，或其URI或超链接。

2. 您可以根据您共享许可材料的媒体、方式和上下文以任何合理方式满足第3(a)(1)部分的条件。例如，通过提供指向包含所需信息的资源的URI或超链接来满足条件可能是合理的。

3. 如果许可方要求，您必须在合理可行的范围内删除第3(a)(1)(A)部分要求的任何信息。

4. 如果您共享您制作的改编材料，您应用的适配器许可证不得阻止改编材料的接收方遵守本公共许可证。

## 第4节 - 特殊数据库权利。

如果许可权包括适用于您对许可材料使用的特殊数据库权利：

a. 为避免疑义，第2(a)(1)部分授予您提取、重复使用、复制和仅限非商业目的共享数据库内容全部或实质部分的权利；

b. 如果您在具有特殊数据库权利的数据库中包含全部或实质部分的数据库内容，则您具有特殊数据库权利的数据库（但不包括其各自的内容）属于改编材料；以及

c. 如果您共享数据库内容的全部或实质部分，则您必须遵守第3(a)节中的条件。

为避免疑义，本节4补充而不取代您在许可权包括其他版权和类似权利的情况下根据本公共许可证的义务。

## 第5节 - 担保声明和责任限制。

a. __除非许可方另行承担，尽可能，许可方按原样和按现状提供许可材料，并不就许可材料的任何性质作出任何明示或默示的陈述或担保。这包括但不限于，对所有权、适销性、特定用途适用性、非侵权、潜在缺陷或其他缺陷的不存在、准确性或错误的存在或不存在等方面的担保，无论是明示的、默示的、法定的还是其他的。在不允许全面或部分免责声明的情况下，此免责声明可能不适用于您。__

b. __尽可能，在任何情况下，许可方不会根据任何法律理论（包括但不限于疏忽）或其他方式对您承担任何直接、特殊、间接、附带、惩罚性、示范性或其他损失、成本、费用或损害承担责任，无论许可方是否已被告知此类损失、成本、费用或损害的可能性。在不允许全面或部分责任限制的情况下，此责任限制可能不适用于您。__

c. 上述的担保声明和责任限制应被解释为尽可能接近绝对免责和放弃所有责任。

## 第6节 - 期限和终止。

a. 本公共许可证适用于此处许可的版权和类似权利的期限。但是，如果您未遵守本公共许可证，则您根据本公共许可证的权利将自动终止。

b. 如果根据第6(a)节，您使用许可材料的权利已终止，则它将重新生效：

1. 在违规行为得到纠正的日期自动生效，前提是在您发现违规行为后30天内得到纠正；或

2. 由许可方明确重新生效。

为避免疑义，本节6(b)不影响许可方可能寻求救济您违反本公共许可证的任何权利。

c. 为避免疑义，许可方也可以根据单独的条款或条件提供许可材料，或随时停止分发许可材料；但是，这样做不会终止本公共许可证。

d. 第1、5、6、7和8节在本公共许可证终止后仍然有效。
## 第7节 - 其他条款和条件。

a. 除非明确同意，许可方不受您传达的任何额外或不同的条款或条件的约束。

b. 有关已许可材料的任何安排、理解或协议，若未在此处声明，均与本公共许可证的条款和条件分开且独立。

## 第8节 - 解释。

a. 为避免疑义，本公共许可证不会，也不应被解释为，减少、限制、限制或对在本公共许可证下无需许可即可合法进行的任何已许可材料的使用施加条件。

b. 在可能范围内，如果本公共许可证的任何条款被视为不可执行，则将自动改革至使其可执行的最低程度。如果无法改革该条款，则将其从本公共许可证中剥离，而不影响其余条款和条件的可执行性。

c. 除非许可方明确同意，否则不会放弃本公共许可证的任何条款或条件，也不会同意违反。

d. 本公共许可证中的任何内容均不构成或不得被解释为对许可方或您适用的任何特权和豁免的限制或放弃，包括来自任何司法管辖区或权威的法律程序。
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
{% hint style="success" %}
学习并练习AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

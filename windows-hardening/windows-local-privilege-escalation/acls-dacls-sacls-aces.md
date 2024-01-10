# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习 AWS 黑客攻击，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

其他支持 HackTricks 的方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。**

</details>

## **访问控制列表 (ACL)**

**ACL 是 ACE 的有序列表**，定义了适用于对象及其属性的保护措施。每个 **ACE** 标识一个安全**主体**并指定允许、拒绝或审计该安全主体的一组访问权限。

对象的安全描述符可以包含**两个 ACL**：

1. 一个 **DACL**，用于**识别**被**允许**或**拒绝**访问的**用户**和**组**
2. 一个 **SACL**，控制如何**审计**访问

当用户尝试访问文件时，Windows 系统运行 AccessCheck 并将安全描述符与用户访问令牌进行比较，评估用户是否被授予访问权限以及根据设置的 ACEs 授予何种类型的访问权限。

### **自主访问控制列表 (DACL)**

DACL（通常提到的 ACL）识别分配或拒绝对象访问权限的用户和组。它包含一系列配对的 ACE（帐户 + 访问权限）到可保护对象。

### **系统访问控制列表 (SACL)**

SACL 使得监控对受保护对象的访问成为可能。SACL 中的 ACE 确定**在安全事件日志中记录哪些类型的访问**。使用监控工具，如果恶意用户尝试访问受保护对象，可能会向相关人员发出警报，并且在事件情况下，我们可以使用日志追溯历史步骤。最后，您可以启用日志记录以排查访问问题。

## 系统如何使用 ACLs

每个**登录**系统的**用户持有一个带有该登录会话安全信息的访问令牌**。系统在用户登录时创建访问令牌。**用户代表执行的每个进程都有访问令牌的副本**。令牌标识用户、用户的组和用户的权限。令牌还包含一个登录 SID（安全标识符），用于标识当前的登录会话。

当线程尝试访问可保护对象时，LSASS（本地安全权限）授予或拒绝访问。为此，**LSASS 搜索 SDS 数据流中的 DACL**，寻找适用于线程的 ACE。

**对象 DACL 中的每个 ACE** 指定允许或拒绝安全主体或登录会话的访问权限。如果对象的所有者未在 DACL 中为该对象创建任何 ACE，则系统立即授予访问权限。

如果 LSASS 找到 ACE，它会将每个 ACE 中的受托人 SID 与线程访问令牌中标识的受托人 SID 进行比较。

### ACEs

有**`三`种主要类型的 ACE**，可以应用于 AD 中的所有可保护对象：

| **ACE**                  | **描述**                                                                                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`拒绝访问 ACE`**  | 在 DACL 中使用，表明一个用户或组被明确拒绝访问对象                                                                                   |
| **`允许访问 ACE`** | 在 DACL 中使用，表明一个用户或组被明确允许访问对象                                                                                  |
| **`系统审计 ACE`**   | 在 SACL 中使用，当用户或组尝试访问对象时生成审计日志。它记录是否授予访问权限以及发生了哪种类型的访问 |

每个 ACE 由以下`四`个组成部分构成：

1. 对象（或以图形方式的主体名称）有权访问的用户/组的安全标识符（SID）
2. 表示 ACE 类型的标志（拒绝访问、允许访问或系统审计 ACE）
3. 一组标志，指定子容器/对象是否可以从主要或父对象继承给定的 ACE 条目
4. [访问掩码](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)，这是一个 32 位值，定义了授予对象的权限

系统按顺序检查每个 ACE，直到发生以下事件之一：

* **拒绝访问 ACE 明确拒绝** 线程访问令牌中列出的受托人的任何请求访问权限。
* **一个或多个允许访问 ACE** 明确授予线程访问令牌中列出的受托人所有请求的访问权限。
* 所有 ACE 都已检查，仍然至少有**一个请求的访问**权限**未被明确允许**，在这种情况下，访问被隐式**拒绝**。

### ACEs 的顺序

因为**系统在请求的访问被明确授予或拒绝时停止检查 ACE**，所以 DACL 中 ACE 的顺序很重要。

DACL 中 ACE 的首选顺序称为“规范”顺序。对于 Windows 2000 和 Windows Server 2003，规范顺序如下：

1. 所有**明确的** ACE 都放在任何**继承的** ACE **之前**的一个组中。
2. 在**明确的** ACE 组中，**拒绝访问**的 ACE 放在**允许访问**的 ACE **之前**。
3. 在**继承的**组中，首先是从**子对象的父对象继承的** ACE，**然后**是从**祖父母继承的** ACE，**依此类推**，沿着对象树向上。之后，**拒绝访问**的 ACE 放在**允许访问**的 ACE **之前**。

下图显示了 ACE 的规范顺序：

### ACEs 的规范顺序

![ACE](https://www.ntfs.com/images/screenshots/ACEs.gif)

规范顺序确保发生以下情况：

* 无论是否有明确的允许访问 ACE，都会执行明确的**拒绝访问 ACE**。这意味着对象的所有者可以定义允许一组用户访问的权限，并拒绝该组的一个子集访问。
* 所有**明确的 ACE** 都在任何继承的 ACE **之前**处理。这与自主访问控制的概念一致：对子对象（例如文件）的访问由子对象的所有者自行决定，而不是父对象（例如文件夹）的所有者。子对象的所有者可以直接在子对象上定义权限。结果是修改了继承权限的效果。

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### GUI 示例

这是显示 ACL、DACL 和 ACE 的文件夹的经典安全选项卡：

![](../../.gitbook/assets/classicsectab.jpg)

如果我们点击**高级按钮**，我们将获得更多选项，如继承：

![](../../.gitbook/assets/aceinheritance.jpg)

如果您添加或编辑安全主体：

![](../../.gitbook/assets/editseprincipalpointers1.jpg)

最后我们有审计选项卡中的 SACL：

![](../../.gitbook/assets/audit-tab.jpg)

### 示例：明确拒绝访问一个组

在此示例中，允许访问的组是 Everyone，拒绝访问的组是 Marketing，Marketing 是 Everyone 的一个子集。

您想拒绝 Marketing 组访问 Cost 文件夹。如果 Cost 文件夹的 ACE 按规范顺序排列，则拒绝 Marketing 的 ACE 会在允许 Everyone 的 ACE 之前。

在访问检查期间，操作系统按照它们在对象的 DACL 中出现的顺序逐步处理 ACE，以便先处理拒绝 ACE。结果，Marketing 组的成员被拒绝访问。其他人则被允许访问对象。

### 示例：明确优先于继承

在此示例中，Cost 文件夹有一个可继承的 ACE，拒绝 Marketing 访问（父对象）。换句话说，所有 Marketing 组的成员（或子对象）都通过继承被拒绝访问。

您想允许 Bob 访问，他是 Marketing 主管。作为 Marketing 组的成员，Bob 通过继承被拒绝访问 Cost 文件夹。子对象的所有者（用户 Bob）定义了一个明确的 ACE，允许访问 Cost 文件夹。如果子对象的 ACE 按规范顺序排列，则允许 Bob 访问的明确 ACE 会在任何继承的 ACE 之前，包括拒绝 Marketing 组访问的继承 ACE。

在访问检查期间，操作系统在到达拒绝 Marketing 组访问的 ACE 之前，先到达允许 Bob 访问的 ACE。结果，尽管 Bob 是 Marketing 组的成员，他仍被允许访问对象。Marketing 组的其他成员被拒绝访问。

### 访问控制条目

如前所述，ACL（访问控制列表）是 ACE（访问控制条目）的有序列表。每个 ACE 包含以下内容：

* 用于识别特定用户或组的 SID（安全标识符）。
* 指定访问权限的访问掩码。
* 一组位标志，决定子对象是否可以继承 ACE。
* 指示 ACE 类型的标志。

ACE 本质上是相似的。它们的区别在于它们对继承和对象访问的控制程度。ACE 有两种类型：

* 通用类型，附加到所有可保护对象。
* 特定对象类型，只能出现在 Active Directory 对象的 ACL 中。

### 通用 ACE

通用 ACE 对可以继承它们的子对象类型的控制有限。本质上，它们只能区分容器和非容器。

例如，NTFS 中的 Folder 对象的 DACL 可以包括一个通用 ACE，允许一组用户列出文件夹的内容。因为列出文件夹内容只能在 Container 对象上执行，所以允许操作的 ACE 可以被标记为 CONTAINER_INHERIT_ACE。只有文件夹中的 Container 对象（即其他 Folder 对象）继承 ACE。非容器对象（即 File 对象）不继承父对象的 ACE。

通用 ACE 适用于整个对象。如果通用 ACE 给特定用户读取访问权限，用户可以读取与对象相关的所有信息——数据和属性。对于大多数对象类型来说，这不是一个严重的限制。例如，File 对象有很少的属性，这些属性都用于描述对象的特征，而不是用于存储信息。File 对象中的大部分信息都存储为对象数据；因此，对文件属性进行单独控制的需求不大。

### 特定对象 ACE

特定对象 ACE 对可以继承它们的子对象类型提供更大程度的控制。

例如，OU（组织单位）对象的 ACL 可以有一个特定对象 ACE，仅标记为 User 对象继承。其他类型的对象，如 Computer 对象，将不会继承 ACE。

这种能力是为什么特定对象 ACE 被称为特定对象的原因。它们的继承可以限制为特定类型的子对象。

这两类 ACE 类型控制对象访问的方式也有类似的差异。

特定对象 ACE 可以适用于对象的任何单个属性或该对象的一组属性。这种类型的 ACE 仅用于 Active Directory 对象的 ACL，与其他对象类型不同，Active Directory 对象将大部分信息存储在属性中。通常希望对 Active Directory 对象的每个属性进行独立控制，特定对象 ACE 使这成为可能。

例如，当您为 User 对象定义权限时，您可以使用一个特定对象 ACE 允许 Principal Self（即用户）对 Phone-Home-Primary（homePhone）属性进行写入访问，并且可以使用其他特定对象 ACE 拒绝 Principal Self 访问 Logon-Hours（logonHours）属性和其他设置用户帐户限制的属性。

下表显示了每个 ACE 的布局。

### 访问控制条目布局

| ACE 字段   | 描述                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

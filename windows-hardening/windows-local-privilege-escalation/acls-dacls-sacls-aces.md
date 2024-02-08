# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建和 **自动化工作流**，利用世界上 **最先进** 的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的 **公司广告** 或 **下载 PDF 版本的 HackTricks**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFT**](https://opensea.io/collection/the-peass-family) 收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来 **分享您的黑客技巧**。

</details>

## **访问控制列表（ACL）**

访问控制列表（ACL）由一组有序的访问控制条目（ACE）组成，用于规定对象及其属性的保护措施。实质上，ACL 定义了哪些安全主体（用户或组）对给定对象具有允许或拒绝的操作权限。

有两种类型的 ACL：

- **自主访问控制列表（DACL）：** 指定哪些用户和组对对象具有或不具有访问权限。
- **系统访问控制列表（SACL）：** 管理对对象的访问尝试进行审计。

访问文件的过程涉及系统检查对象的安全描述符与用户的访问令牌，以确定是否应授予访问权限以及根据 ACE 的范围授予的访问权限。

### **关键组件**

- **DACL：** 包含 ACE，为用户和组授予或拒绝对象的访问权限。它实质上是指定访问权限的主要 ACL。

- **SACL：** 用于审计对对象的访问，其中 ACE 定义要在安全事件日志中记录的访问类型。这对于检测未经授权的访问尝试或解决访问问题非常有价值。

### **系统与 ACL 的交互**

每个用户会话都与包含与该会话相关的安全信息的访问令牌相关联，包括用户、组标识和特权。此令牌还包括一个登录 SID，用于唯一标识会话。

本地安全性机构（LSASS）通过检查 DACL 中与试图访问的安全主体匹配的 ACE 来处理对对象的访问请求。如果未找到相关 ACE，则立即授予访问权限。否则，LSASS 将 ACE 与访问令牌中的安全主体 SID 进行比较，以确定访问资格。

### **总结的过程**

- **ACL：** 通过 DACL 定义访问权限，通过 SACL 定义审计规则。
- **访问令牌：** 包含会话的用户、组和特权信息。
- **访问决策：** 通过将 DACL ACE 与访问令牌进行比较来进行；SACL 用于审计。

### ACEs

有 **三种主要类型的访问控制条目（ACE）**：

- **拒绝访问 ACE：** 此 ACE 明确拒绝指定用户或组对对象的访问（在 DACL 中）。
- **允许访问 ACE：** 此 ACE 明确授予指定用户或组对对象的访问权限（在 DACL 中）。
- **系统审计 ACE：** 位于系统访问控制列表（SACL）中，此 ACE 负责在用户或组对对象的访问尝试时生成审计日志。它记录访问是否被允许或拒绝以及访问的性质。

每个 ACE 都有 **四个关键组件**：

1. 用户或组的 **安全标识符（SID）**（或其主体名称在图形表示中）。
2. 用于标识 ACE 类型（拒绝访问、允许访问或系统审计）的 **标志**。
3. 确定子对象是否可以从其父对象继承 ACE 的 **继承标志**。
4. 一个指定对象授予的权限的 **[访问掩码](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)**，一个指定对象授予的权限的 32 位值。

访问决定是通过顺序检查每个 ACE 进行的，直到：

- **拒绝访问 ACE** 明确拒绝访问令牌中的受托人请求的权限。
- **允许访问 ACE** 明确授予访问令牌中的受托人所有请求的权限。
- 在检查所有 ACE 后，如果任何请求的权限 **未被明确允许**，则将隐式 **拒绝** 访问。

### ACE 的顺序

将 **ACE**（规定谁可以访问或不能访问某物的规则）放在称为 **DACL** 的列表中的方式非常重要。这是因为一旦系统根据这些规则给予或拒绝访问权限，它就会停止查看其余内容。

有一种最佳组织这些 ACE 的方法，称为 **“规范顺序”**。这种方法有助于确保一切运行顺畅和公平。以下是适用于 **Windows 2000** 和 **Windows Server 2003** 等系统的方法：

- 首先，将所有专门为此项制定的规则放在其他规则之前，例如来自父文件夹等地方的规则。
- 在这些特定规则中，将明确拒绝（拒绝）的规则放在允许（允许）的规则之前。
- 对于来自其他地方的规则，从最接近的来源开始，然后再往回走。同样，将 **“不”** 放在 **“是”** 之前。

这种设置有两个重要作用：

* 确保如果有一个特定的 **“不”**，它将被尊重，无论其他 **“是”** 规则如何。
* 在任何来自父文件夹或更远处的规则生效之前，让文件或文件夹的所有者有 **最终决定权**。

通过这种方式，文件或文件夹的所有者可以非常精确地确定谁可以访问，确保正确的人可以进入，错误的人则不能。

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

因此，这种 **“规范顺序”** 主要是为了确保访问规则清晰且运行良好，首先放置特定规则，并以智能方式组织一切。


<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建和 **自动化工作流**，利用世界上 **最先进** 的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### GUI 示例

**[此处的示例](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)**

这是一个文件夹的经典安全选项卡，显示了 ACL、DACL 和 ACE：

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

如果单击 **高级** 按钮，将会看到更多选项，如继承：

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

如果添加或编辑安全主体：

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

最后，我们在审计选项卡中有 SACL：

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### 以简化方式解释访问控制

在管理对资源（如文件夹）的访问时，我们使用称为访问控制列表（ACL）和访问控制条目（ACE）的列表和规则。这些规则定义了谁可以或不能访问某些数据。

#### 拒绝特定组的访问

假设您有一个名为 Cost 的文件夹，您希望所有人都可以访问它，除了市场团队。通过正确设置规则，我们可以确保在允许其他人访问之前，明确拒绝市场团队的访问。这是通过将拒绝市场团队访问的规则放在允许所有人访问的规则之前来实现的。

#### 允许被拒绝组的特定成员访问

假设市场总监 Bob 需要访问 Cost 文件夹，尽管通常市场团队不应该访问。我们可以为 Bob 添加一个特定规则（ACE），授予他访问权限，并将其放在拒绝市场团队访问的规则之前。这样，尽管对他的团队有一般限制，Bob 仍然可以访问。

#### 理解访问控制条目

ACE 是 ACL 中的个别规则。它们标识用户或组，指定允许或拒绝的访问权限，并确定这些规则如何应用于子项（继承）。有两种主要类型的 ACE：

- **通用 ACE：** 这些广泛适用，影响所有类型的对象或仅区分容器（如文件夹）和非容器（如文件）。例如，允许用户查看文件夹内容但不允许访问其中的文件的规则。

- **特定对象 ACE：** 这些提供更精确的控制，允许为特定类型的对象或甚至对象内的个别属性设置规则。例如，在用户目录中，规则可能允许用户更新其电话号码但不允许更新登录时间。

每个 ACE 包含重要信息，如规则适用于谁（使用安全标识符或 SID）、规则允许或拒绝什么（使用访问掩码）以及如何被其他对象继承。

#### ACE 类型之间的关键区别

- **通用 ACE：** 适用于简单的访问控制场景，其中相同规则适用于对象的所有方面或容器内的所有对象。

- **特定对象 ACE：** 用于更复杂的场景，特别是在像 Active Directory 这样的环境中，您可能需要以不同方式控制对对象特定属性的访问。

总而言之，ACL 和 ACE 有助于定义精确的访问控制，确保只有正确的个人或组可以访问敏感信息或资源，并且可以将访问权限调整到个别属性或对象类型的级别。

### 访问控制条目布局

| ACE 字段   | 描述                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 类型        | 指示 ACE 类型的标志。Windows 2000 和 Windows Server 2003 支持六种 ACE 类型：附加到所有可保护对象的三种通用 ACE 类型。可能出现在 Active Directory 对象中的三种特定对象 ACE 类型。                                                                                                                                                                                                                                                            |
| 标志       | 一组位标志，用于控制继承和审计。                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| 大小        | 为 ACE 分配的内存字节数。                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 访问掩码 | 32 位值，其位对应于对象的访问权限。位可以设置为开启或关闭，但设置的含义取决于 ACE 类型。例如，如果对应于读取权限的位被打开，并且 ACE 类型为拒绝，则 ACE 拒绝读取对象权限。如果相同位被设置为开启但 ACE 类型为允许，则 ACE 授予读取对象权限。访问掩码的更多详细信息在下一个表中。 |
| SID         | 标识由此 ACE 控制或监视访问的用户或组。                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### 访问掩码布局

| 位（范围） | 含义                            | 描述/示例                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | 特定对象访问权限      | 读取数据、执行、追加数据           |
| 16 - 22     | 标准访问权限             | 删除、写入 ACL、写入所有者            |
| 23          | 可访问安全 ACL            |                                           |
| 24 - 27     | 保留                           |                                           |
| 28          | 通用 ALL（读取、写入、执行） | 以下所有内容                          |
| 29          | 通用执行                    | 执行程序所需的所有内容 |
| 30          | 通用写入                      | 写入文件所需的所有内容   |
| 31          | 通用读取                       | 读取文件所需的所有内容       |

## 参考资料

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/_ntfsacl_ht.htm](https://www.coopware.in2.info/_

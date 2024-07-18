# Outros Truques da Web

{% hint style="success" %}
Aprenda e pratique Hacking na AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking na GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

### Cabeçalho do Host

Muitas vezes, o back-end confia no **cabeçalho do Host** para realizar algumas ações. Por exemplo, ele pode usar seu valor como o **domínio para enviar um reset de senha**. Portanto, quando você recebe um e-mail com um link para redefinir sua senha, o domínio sendo usado é aquele que você colocou no cabeçalho do Host. Então, você pode solicitar o reset de senha de outros usuários e alterar o domínio para um controlado por você para roubar seus códigos de reset de senha. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Observe que é possível que você nem precise esperar o usuário clicar no link de redefinição de senha para obter o token, pois talvez até mesmo **filtros de spam ou outros dispositivos/bots intermediários cliquem nele para analisá-lo**.
{% endhint %}

### Booleanos de Sessão

Às vezes, quando você completa alguma verificação corretamente, o back-end **apenas adicionará um booleano com o valor "True" a um atributo de segurança de sua sessão**. Em seguida, um endpoint diferente saberá se você passou com sucesso por aquela verificação.\
No entanto, se você **passar na verificação** e sua sessão for concedida com o valor "True" no atributo de segurança, você pode tentar **acessar outros recursos** que **dependem do mesmo atributo** mas que você **não deveria ter permissão** para acessar. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funcionalidade de Registro

Tente se registrar como um usuário que já existe. Tente também usar caracteres equivalentes (pontos, muitos espaços e Unicode).

### Tomada de Conta de E-mails

Registre um e-mail, antes de confirmá-lo, altere o e-mail. Então, se o novo e-mail de confirmação for enviado para o primeiro e-mail registrado, você pode assumir o controle de qualquer e-mail. Ou se você puder habilitar o segundo e-mail confirmando o primeiro, você também pode assumir o controle de qualquer conta.

### Acesso ao servicedesk interno de empresas que usam atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Método TRACE

Os desenvolvedores podem esquecer de desativar várias opções de depuração no ambiente de produção. Por exemplo, o método `TRACE` do HTTP é projetado para fins de diagnóstico. Se habilitado, o servidor web responderá a solicitações que usam o método `TRACE` ecoando na resposta a solicitação exata que foi recebida. Esse comportamento geralmente é inofensivo, mas ocasionalmente leva à divulgação de informações, como o nome de cabeçalhos de autenticação internos que podem ser anexados a solicitações por proxies reversos.![Imagem para postagem](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Imagem para postagem](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


{% hint style="success" %}
Aprenda e pratique Hacking na AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking na GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

# Sub-GHz RF

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Portas de Garagem

Os abridores de portas de garagem normalmente operam em frequências na faixa de 300-190 MHz, sendo as frequências mais comuns 300 MHz, 310 MHz, 315 MHz e 390 MHz. Essa faixa de frequência é comumente usada para abridores de portas de garagem porque é menos congestionada do que outras bandas de frequência e é menos provável que sofra interferência de outros dispositivos.

## Portas de Carro

A maioria dos controles remotos de carro opera em **315 MHz ou 433 MHz**. Essas são ambas frequências de rádio, e são usadas em uma variedade de aplicações diferentes. A principal diferença entre as duas frequências é que 433 MHz tem um alcance maior do que 315 MHz. Isso significa que 433 MHz é melhor para aplicações que requerem um alcance maior, como entrada sem chave.\
Na Europa, 433.92MHz é comumente usado e nos EUA e Japão é 315MHz.

## **Ataque de Força Bruta**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

Se em vez de enviar cada código 5 vezes (enviado assim para garantir que o receptor o receba) você enviar apenas uma vez, o tempo é reduzido para 6 minutos:

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

e se você **remover o período de espera de 2 ms** entre os sinais, você pode **reduzir o tempo para 3 minutos.**

Além disso, usando a Sequência de De Bruijn (uma maneira de reduzir o número de bits necessários para enviar todos os números binários potenciais para força bruta) esse **tempo é reduzido para apenas 8 segundos**:

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

Um exemplo desse ataque foi implementado em [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Requerer **um preâmbulo evitará a otimização da Sequência de De Bruijn** e **códigos rolantes impedirão esse ataque** (supondo que o código seja longo o suficiente para não ser passível de força bruta).

## Ataque Sub-GHz

Para atacar esses sinais com Flipper Zero, verifique:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Proteção por Códigos Rolantes

Os abridores automáticos de portas de garagem normalmente usam um controle remoto sem fio para abrir e fechar a porta da garagem. O controle remoto **envia um sinal de frequência de rádio (RF)** para o abridor de porta da garagem, que ativa o motor para abrir ou fechar a porta.

É possível que alguém use um dispositivo conhecido como code grabber para interceptar o sinal RF e gravá-lo para uso posterior. Isso é conhecido como um **ataque de repetição**. Para prevenir esse tipo de ataque, muitos abridores de portas de garagem modernos usam um método de criptografia mais seguro conhecido como sistema de **código rolante**.

O **sinal RF é tipicamente transmitido usando um código rolante**, o que significa que o código muda a cada uso. Isso torna **difícil** para alguém **interceptar** o sinal e **usá-lo** para obter acesso **não autorizado** à garagem.

Em um sistema de código rolante, o controle remoto e o abridor de porta da garagem têm um **algoritmo compartilhado** que **gera um novo código** toda vez que o remoto é usado. O abridor de porta da garagem só responderá ao **código correto**, tornando muito mais difícil para alguém obter acesso não autorizado à garagem apenas capturando um código.

### **Ataque de Link Ausente**

Basicamente, você escuta o botão e **captura o sinal enquanto o remoto está fora do alcance** do dispositivo (digamos, o carro ou a garagem). Você então se move para o dispositivo e **usa o código capturado para abri-lo**.

### Ataque de Jamming de Link Completo

Um atacante poderia **interferir no sinal perto do veículo ou receptor** para que o **receptor não consiga realmente ‘ouvir’ o código**, e uma vez que isso esteja acontecendo, você pode simplesmente **capturar e reproduzir** o código quando você parar de interferir.

A vítima em algum momento usará as **chaves para trancar o carro**, mas então o ataque terá **gravado códigos de "fechar a porta" suficientes** que, esperançosamente, poderiam ser reenviados para abrir a porta (uma **mudança de frequência pode ser necessária** já que há carros que usam os mesmos códigos para abrir e fechar, mas escutam ambos os comandos em diferentes frequências).

{% hint style="warning" %}
**A interferência funciona**, mas é perceptível, pois se a **pessoa trancando o carro simplesmente testar as portas** para garantir que estão trancadas, ela notaria que o carro está destrancado. Além disso, se ela estivesse ciente de tais ataques, poderia até ouvir o fato de que as portas nunca fizeram o **som** de trancar ou as **luzes** do carro nunca piscaram quando pressionaram o botão de ‘trancar’.
{% endhint %}

### **Ataque de Captura de Código (também conhecido como ‘RollJam’)**

Esta é uma técnica de **interferência mais furtiva**. O atacante irá interferir no sinal, então quando a vítima tentar trancar a porta, não funcionará, mas o atacante irá **gravar esse código**. Então, a vítima irá **tentar trancar o carro novamente** pressionando o botão e o carro irá **gravar esse segundo código**.\
Instantaneamente após isso, o **atacante pode enviar o primeiro código** e o **carro irá trancar** (a vítima pensará que a segunda pressão o fechou). Então, o atacante poderá **enviar o segundo código roubado para abrir** o carro (supondo que um **código de "fechar o carro" também possa ser usado para abri-lo**). Uma mudança de frequência pode ser necessária (já que há carros que usam os mesmos códigos para abrir e fechar, mas escutam ambos os comandos em diferentes frequências).

O atacante pode **interferir no receptor do carro e não no seu receptor** porque se o receptor do carro estiver ouvindo, por exemplo, uma largura de banda de 1MHz, o atacante não irá **interferir** na frequência exata usada pelo remoto, mas **em uma próxima nesse espectro**, enquanto o **receptor do atacante estará ouvindo em uma faixa menor** onde ele pode ouvir o sinal remoto **sem o sinal de interferência**.

{% hint style="warning" %}
Outras implementações vistas nas especificações mostram que o **código rolante é uma parte** do código total enviado. Ou seja, o código enviado é uma **chave de 24 bits** onde os primeiros **12 são o código rolante**, os **8 segundos são o comando** (como trancar ou destrancar) e os últimos 4 são o **checksum**. Veículos que implementam esse tipo também são naturalmente suscetíveis, pois o atacante precisa apenas substituir o segmento do código rolante para poder **usar qualquer código rolante em ambas as frequências**.
{% endhint %}

{% hint style="danger" %}
Note que se a vítima enviar um terceiro código enquanto o atacante está enviando o primeiro, o primeiro e o segundo código serão invalidados.
{% endhint %}

### Ataque de Jamming com Alarme Soando

Testando contra um sistema de código rolante de mercado instalado em um carro, **enviar o mesmo código duas vezes** imediatamente **ativou o alarme** e o imobilizador, proporcionando uma única oportunidade de **negação de serviço**. Ironicamente, o meio de **desativar o alarme** e o imobilizador era **pressionar** o **remoto**, proporcionando ao atacante a capacidade de **realizar continuamente um ataque DoS**. Ou misturar esse ataque com o **anterior para obter mais códigos**, já que a vítima gostaria de parar o ataque o mais rápido possível.

## Referências

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

# Sub-GHz RF

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Portões de Garagem

Os abridores de portões de garagem normalmente operam em frequências na faixa de 300-190 MHz, sendo as frequências mais comuns 300 MHz, 310 MHz, 315 MHz e 390 MHz. Essa faixa de frequência é comumente usada para abridores de portões de garagem porque é menos congestionada do que outras bandas de frequência e tem menos probabilidade de sofrer interferência de outros dispositivos.

## Portas de Carros

A maioria dos controles remotos de chaves de carro opera em **315 MHz ou 433 MHz**. Ambas são frequências de rádio e são usadas em uma variedade de aplicações diferentes. A principal diferença entre as duas frequências é que 433 MHz tem um alcance maior do que 315 MHz. Isso significa que 433 MHz é melhor para aplicações que exigem um alcance maior, como entrada sem chave remota.\
Na Europa, 433,92 MHz é comumente usado e nos EUA e Japão é o 315 MHz.

## **Ataque de Força Bruta**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

Se, em vez de enviar cada código 5 vezes (enviado assim para garantir que o receptor o receba), enviar apenas uma vez, o tempo é reduzido para 6 minutos:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

e se você **remover o período de espera de 2 ms** entre os sinais, pode **reduzir o tempo para 3 minutos.**

Além disso, usando a Sequência de De Bruijn (uma maneira de reduzir o número de bits necessários para enviar todos os números binários potenciais para força bruta), esse **tempo é reduzido para apenas 8 segundos**:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Exemplo deste ataque foi implementado em [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Exigir **um preâmbulo evitará a otimização da Sequência de De Bruijn** e **códigos rolantes impedirão este ataque** (supondo que o código seja longo o suficiente para não ser forçado).

## Ataque Sub-GHz

Para atacar esses sinais com Flipper Zero, confira:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Proteção de Códigos Rolantes

Abridores automáticos de portões de garagem normalmente usam um controle remoto sem fio para abrir e fechar o portão da garagem. O controle remoto **envia um sinal de frequência de rádio (RF)** para o abridor de portão da garagem, que ativa o motor para abrir ou fechar o portão.

É possível que alguém use um dispositivo conhecido como capturador de código para interceptar o sinal de RF e gravá-lo para uso posterior. Isso é conhecido como **ataque de replay**. Para prevenir esse tipo de ataque, muitos abridores de portões de garagem modernos usam um método de criptografia mais seguro conhecido como sistema de **código rolante**.

O **sinal de RF é tipicamente transmitido usando um código rolante**, o que significa que o código muda a cada uso. Isso torna **difícil** para alguém **interceptar** o sinal e **usá-lo** para ganhar acesso **não autorizado** à garagem.

Em um sistema de código rolante, o controle remoto e o abridor de portão da garagem têm um **algoritmo compartilhado** que **gera um novo código** toda vez que o controle é usado. O abridor de portão da garagem só responderá ao **código correto**, tornando muito mais difícil para alguém ganhar acesso não autorizado à garagem apenas capturando um código.

### **Ataque de Link Ausente**

Basicamente, você escuta o botão e **captura o sinal enquanto o controle remoto está fora do alcance** do dispositivo (digamos, o carro ou a garagem). Você então se move para o dispositivo e **usa o código capturado para abri-lo**.

### Ataque de Jamming de Link Completo

Um atacante poderia **bloquear o sinal perto do veículo ou receptor** para que o **receptor não possa realmente 'ouvir' o código**, e uma vez que isso esteja acontecendo, você pode simplesmente **capturar e reproduzir** o código quando tiver parado de bloquear.

A vítima em algum momento usará as **chaves para trancar o carro**, mas então o ataque terá **gravado códigos suficientes de 'fechar porta'** que, esperançosamente, poderiam ser reenviados para abrir a porta (uma **mudança de frequência pode ser necessária** já que há carros que usam os mesmos códigos para abrir e fechar, mas ouvem ambos os comandos em frequências diferentes).

{% hint style="warning" %}
**Jamming funciona**, mas é perceptível, pois se a **pessoa trancando o carro simplesmente testar as portas** para garantir que estão trancadas, notaria o carro destrancado. Além disso, se estivessem cientes de tais ataques, poderiam até ouvir o fato de que as portas nunca fizeram o som de **trava** ou as **luzes** do carro nunca piscaram quando pressionaram o botão de 'trancar'.
{% endhint %}

### **Ataque de Captura de Código (também conhecido como 'RollJam')**

Esta é uma técnica de Jamming mais **discreta**. O atacante bloqueará o sinal, então quando a vítima tentar trancar a porta, não funcionará, mas o atacante **gravará este código**. Então, a vítima tentará **trancar o carro novamente** pressionando o botão e o carro **gravará este segundo código**.\
Imediatamente após isso, o **atacante pode enviar o primeiro código** e o **carro trancará** (a vítima pensará que a segunda pressionada fechou). Então, o atacante poderá **enviar o segundo código roubado para abrir** o carro (supondo que um **código de 'fechar carro'** também possa ser usado para abri-lo). Uma mudança de frequência pode ser necessária (já que há carros que usam os mesmos códigos para abrir e fechar, mas ouvem ambos os comandos em frequências diferentes).

O atacante pode **bloquear o receptor do carro e não o seu próprio receptor** porque se o receptor do carro estiver ouvindo, por exemplo, uma banda larga de 1MHz, o atacante não **bloqueará** a frequência exata usada pelo controle remoto, mas **uma próxima nesse espectro** enquanto o **receptor do atacante estará ouvindo em uma faixa menor** onde ele pode ouvir o sinal do controle remoto **sem o sinal de bloqueio**.

{% hint style="warning" %}
Outras implementações vistas nas especificações mostram que o **código rolante é uma parte** do código total enviado. Ou seja, o código enviado é uma **chave de 24 bits** onde os primeiros **12 são o código rolante**, os **8 seguintes são o comando** (como trancar ou destrancar) e os últimos 4 são o **checksum**. Veículos que implementam esse tipo também são naturalmente suscetíveis, pois o atacante apenas precisa substituir o segmento do código rolante para poder **usar qualquer código rolante em ambas as frequências**.
{% endhint %}

{% hint style="danger" %}
Observe que se a vítima enviar um terceiro código enquanto o atacante estiver enviando o primeiro, o primeiro e o segundo código serão invalidados.
{% endhint %}

### Ataque de Jamming com Alarme Sonoro

Testando contra um sistema de código rolante pós-venda instalado em um carro, **enviar o mesmo código duas vezes** imediatamente **ativou o alarme** e o imobilizador, proporcionando uma oportunidade única de **negação de serviço**. Ironicamente, o meio de **desativar o alarme** e o imobilizador era **pressionar** o **controle remoto**, proporcionando a um atacante a capacidade de **realizar continuamente o ataque de DoS**. Ou misture este ataque com o **anterior para obter mais códigos** já que a vítima gostaria de parar o ataque o mais rápido possível.

## Referências

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

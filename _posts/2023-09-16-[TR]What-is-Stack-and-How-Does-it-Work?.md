---
title: What is stack and how does it work?[TR]
published: true
---


`Stack` verileri belli bir yapıda tutan veri yapısıdır. Veri yapısı olarak özellikle "Last-In, First-Out" (LIFO) ilkesine dayanan bir yapıdır. Bu, en son eklenen verinin en önce çıkarılacağı anlamına gelir. Bu sayede verilere sadece bir uçtan erişim sağlanır.

Stack'in `push`, `pop` ve `peek` olmak üzere 3 temel işlemi bulunuyor. `Push` stack’e eleman koyar. `Pop` stackten en son eklenen elemanı çeker. `Peek` de en üstteki elemanı gösterir. 

Eğer kafanızda neden bu yapı kullanılıyor şeklinde soru işareti oluştuysa tarayıcılardaki geri butonunu düşünebilirsiniz. Bir önceki sayfaya gitmek istenildiğinde geri butonuna bastığımızda son eklenen veri yani son gezindiğimiz sayfa getiriliyor. Stack kullanımı için güzel bir örnek.

Stack tasarımı dizi üzerinde veya bağlı liste ile yapılabilir. Bu yazıda dizi üzerinde bir stack yapısı örneği gösteriyor olacağım.

### [](#header-3)Pratik

![Stack Overflow](/assets/stack.png)

Yukarıdaki resmi inceleyelim. `3 boyutlu` bir dizi olduğunu görüyoruz. Başta bu dizi eleman içermiyor. Diziye `push` ile sırasıyla `7` `13` `17` elemanları ekleniyor ve dizi doluyor. Eleman çıkarmak istediğimizde ise `pop` işlemi ile aynı şekilde son eklenen elemanı çıkarabiliriz. 

Burada dikkat çekmek istediğim bir diğer nokta, eğer diziye tamamen dolu olduğu halde eleman eklemeye devam edersek bu eklenen eleman diziden taşacak ve sonraki stack değerinin üzerine yazılıp stack overflow olarak isimlendirilen açık meydana gelecektir. Bu açığa ait örnekleri sonraki yazılarda ele alacağım. 




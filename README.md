Сделать программу - консольное приложение, используя языки: С/C++, Rust, Python, Go, Node.JS. Код должен быть оформлен в
отдельный репозитарий на GitHub c инструкцией в README.md как собрать и запустить код в консоли под Ubuntu 18.04. К
заданию должен быть приложен скриншот или текст вывода одного или нескольких прогонов программы(!). Программа эмулирует
работу автомобильного брелока, открывающего машину, с использованием ЭЦП в условиях, когда канал связи полностью
доступен любому прослушивающему (в том числе и в течение большого времени и попыток), также атакующий может повторить
прослушанные данные. 

_______________________________________________________________________________________________________________________

Инструкция по запуску.

1) Установка библиотеки crypto++. 
   пропишите следующие команды:
    1) sudo apt-get update
    2) sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils
2) Запуск программы. 
   пропишите следующие команды:
   1) mkdir build
   2) cd build
   3) cmake ..
   4) make
   5) ./async_crypt_dz5_
# SqrtLocker
一个防机惨的软件/Prevent malicious offline operation of software on your computer by others

Author: [$\color{black}{\textsf{Sqrt404}}$](https://github.com/Sqrt404)

## 使用方式

`F2`:  快速锁定
`LeftControl+LeftShift+Z`: 显示/隐藏窗口


## 原理
 - 通过键盘钩子、冻结 `winlogon.exe` 以禁用大部分快捷键（包括 `Control + Alt + Delete`）

 - 使用thread库来维护控制窗口隐藏/显示、锁定后保护电脑的线程

 - 为了防止机惨者在锁定后触发软件运行错误，输入时使用了 `getch()` 输入

 - 密码使用SHA256加密后在本地储存


## 编译

编译器：MinGW 14.2.0

编译指令：
```
g++ SqrtLocker.cpp -o SqrtLocker.exe -std=c++17 -static
```

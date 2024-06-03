[![Github All Releases](https://img.shields.io/github/downloads/extremeblackliu/NCMAutoDumper/total.svg)]() 

# NCMAutoDumper

在下载ncm之后自动转储临时目录的mp3并移动到音乐下载目录。

# 为什么
我知道一直从以前到现在，都有不少能够将ncm转换mp3的网站，程序等等。但是他们要么麻烦，要么不够自动化等等...

总之不能解决我在使用这些工具时候的痛点，于是我开始编写自己的。

### 优势
- 0 性能开销
- 完全自动化
- 兼容批量下载

# 使用步骤
0. 从 Release 中下载`version.dll`
1. 将`version.dll`移动至网易云音乐的安装目录
2. 重新启动网易云音乐

# 从源码开始使用
0. 克隆本库并编译
1. 将编译后的二进制文件重命名为`version.dll`
2. 将`version.dll`移动至网易云音乐的安装目录

### 编译要求
- 至少 C++ 17
- MSVC v143 (Visual Studio 2022)
- Windows SDK

# 说明
这个可能能用很久，真的很久...非常耐操，不需要更新。

哪天坏了再开issue告诉我。

## 兼容性
- [√] 可以和 BetterNCM 一起使用。

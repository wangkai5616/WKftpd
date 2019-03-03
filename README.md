# WKftpd
FTP 是File Transfer Protocol（文件传输协议）的英文简称，而中文简称为“文传协议”。用于Internet上的控制文件的双向传输。同时，它也是一个应用程序（Application）。基于不同的操作系统有不同的FTP应用程序，而所有这些应用程序都遵守同一种协议以传输文件。在FTP的使用当中，用户经常遇到两个概念："下载"（Download）和"上传"（Upload）。"下载"文件就是从远程主机拷贝文件至自己的计算机上；"上传"文件就是将文件从自己的计算机中拷贝至远程主机上。用Internet语言来说，用户可通过客户机程序向（从）远程主机上传（下载）文件。

在TCP/IP协议族的应用层，其传输层使用的是TCP协议，它是基于客户服务器模式工作的。

主要实现的功能：
1.FTP的两种工作模式
2.下载文件和上传文件
3.限制上传或下载文件的速度
4.最大连接数与每ip连接数的限制
5.ftp的空闲断开
6.通过紧急模式关闭数据传输

# Go_DllLoader

A Go program that calls a Windows DLL, copies itself and the DLL to a specified directory, and adds itself to startup for automatic invocation.

For example, we have a `KernelService.dll`, and it implements a function named `EasyRun` .  
This project demonstrates using Go programming language to build a program which will call `EasyRun` .  

Function `EasyRun` has different results. Return 1 meaning exit, and the program should terminate. Return 2 meaning reload the library.  
In this case `KernelService.dll` has downloaded a new version named `KernelService.new`. So the program will load new library!

I develop this program for another project [SimpleRemoter](https://github.com/yuanyuanxiang/SimpleRemoter) .  

## Changelog

[2025/01/23]

Allow running only one program at the same time. However this change causes Windows Defender report virus!

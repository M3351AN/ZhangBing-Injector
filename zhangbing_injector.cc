// 渟雲. Released to public domain
// 感谢张兵大神的WHQL驱动，让我们可以愉快地进行DLL注入实验！
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")
#pragma warning(push)
#pragma warning(disable : 4005)  // macro redefinition
#include <ntstatus.h>
#pragma warning(pop)
#include <tlhelp32.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "./zhangbing_driver.h"

#pragma comment(lib, "user32.lib")

#define DRIVER_SYMBOLIC_LINK L"\\\\.\\mLnUcWtv9IaZf8LBiMXD"
#define IOCTL_INJECT_DLL 2236420
#define VERIFICATION_CODE 721140700  // magic number lmfao

#pragma pack(push, 1)
struct DriverInjectionData {
  DWORD process_id;
  DWORD unknown1;
  DWORD data_size;
  DWORD unknown2;
  PVOID data_buffer;
  DWORD verify_code;
};
#pragma pack(pop)

std::string cachedDriverName = "";

std::wstring GetDriverNameW() {
  srand((unsigned int)GetTickCount());
  if (cachedDriverName.empty()) {
    // Create a random name
    char buffer[100]{};
    static const char alphanum[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int len = rand() % 20 + 10;
    for (int i = 0; i < len; ++i)
      buffer[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    cachedDriverName = buffer;
  }

  std::wstring name(cachedDriverName.begin(), cachedDriverName.end());
  return name;
}

std::wstring GetFullTempPath() {
  wchar_t temp_directory[MAX_PATH + 1] = {0};
  const uint32_t get_temp_path_ret =
      GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
  if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
    return L"";
  }
  if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
    temp_directory[wcslen(temp_directory) - 1] = 0x0;

  return std::wstring(temp_directory);
}

std::wstring GetDriverPath() {
  std::wstring temp = GetFullTempPath();
  if (temp.empty()) {
    return L"";
  }
  return temp + L"\\" + GetDriverNameW();
}

bool CreateFileFromMemory(const std::wstring& desired_file_path,
                          const char* address, size_t size) {
  std::ofstream file_ofstream(desired_file_path.c_str(),
                              std::ios_base::out | std::ios_base::binary);

  if (!file_ofstream.write(address, size)) {
    file_ofstream.close();
    return false;
  }

  file_ofstream.close();
  return true;
}

extern "C" NTSTATUS RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable,
                                       BOOLEAN Client, BOOLEAN* WasEnabled);

NTSTATUS AcquireDebugPrivilege() {
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  if (ntdll == NULL) {
    return STATUS_UNSUCCESSFUL;
  }

  ULONG SE_DEBUG_PRIVILEGE = 20UL;
  BOOLEAN SeDebugWasEnabled;
  NTSTATUS Status =
      RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &SeDebugWasEnabled);

  return Status;
}

extern "C" NTSTATUS NtLoadDriver(PUNICODE_STRING DriverServiceName);
NTSTATUS RegisterAndStart(const std::wstring& driver_path,
                          const std::wstring& serviceName) {
  const static DWORD ServiceTypeKernel = 1;
  const std::wstring servicesPath =
      L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
  const std::wstring nPath = L"\\??\\" + driver_path;

  HKEY dservice;
  LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(),
                                 &dservice);  // Returns Ok if already exists
  if (status != ERROR_SUCCESS) {
    return STATUS_REGISTRY_IO_FAILED;
  }

  status =
      RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ,
                      nPath.c_str(), (DWORD)(nPath.size() * sizeof(wchar_t)));
  if (status != ERROR_SUCCESS) {
    RegCloseKey(dservice);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
    return STATUS_REGISTRY_IO_FAILED;
  }

  status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD,
                           &ServiceTypeKernel, sizeof(DWORD));
  if (status != ERROR_SUCCESS) {
    RegCloseKey(dservice);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
    return STATUS_REGISTRY_IO_FAILED;
  }

  RegCloseKey(dservice);

  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  if (ntdll == NULL) {
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
    return STATUS_UNSUCCESSFUL;
  }

  // auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll,
  // "RtlAdjustPrivilege"); auto NtLoadDriver =
  // (nt::NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");

  ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
  BOOLEAN SeLoadDriverWasEnabled;
  NTSTATUS ntStatus = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE,
                                         &SeLoadDriverWasEnabled);
  if (!NT_SUCCESS(ntStatus)) {
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
    return ntStatus;
  }

  std::wstring wdriver_reg_path =
      L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" +
      serviceName;
  UNICODE_STRING serviceStr;
  RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

  ntStatus = NtLoadDriver(&serviceStr);

  if (!NT_SUCCESS(ntStatus)) {
    // Remove the service
    status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
    if (status != ERROR_SUCCESS) {
    }
  }

  return ntStatus;
}
extern "C" NTSTATUS NtUnloadDriver(PUNICODE_STRING DriverServiceName);
NTSTATUS StopAndRemove(const std::wstring& serviceName) {
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  if (ntdll == NULL) return STATUS_UNSUCCESSFUL;

  std::wstring wdriver_reg_path =
      L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" +
      serviceName;
  UNICODE_STRING serviceStr;
  RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

  HKEY driver_service;
  std::wstring servicesPath =
      L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
  LSTATUS status =
      RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
  if (status != ERROR_SUCCESS) {
    if (status == ERROR_FILE_NOT_FOUND) {
      return STATUS_SUCCESS;  // already removed
    }
    return STATUS_REGISTRY_IO_FAILED;
  }
  RegCloseKey(driver_service);

  NTSTATUS st = NtUnloadDriver(&serviceStr);
  if (st != ERROR_SUCCESS) {
    status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
    return st;  // lets consider unload fail as error because can cause problems
                // with anti cheats later
  }

  status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
  if (status != ERROR_SUCCESS) {
    return STATUS_REGISTRY_IO_FAILED;
  }
  return st;
}

NTSTATUS Unload() {
  auto status = StopAndRemove(GetDriverNameW());
  if (!NT_SUCCESS(status)) return status;

  std::wstring driver_path = GetDriverPath();

  // Destroy disk information before unlink from disk to prevent any recover of
  // the file
  std::ofstream file_ofstream(driver_path.c_str(),
                              std::ios_base::out | std::ios_base::binary);
  if (!file_ofstream.is_open()) {
    return STATUS_DELETE_PENDING;
  }

  int newFileLen = sizeof(rawdata::kRxdriverRawData) +
                   (((long long)rand() * (long long)rand()) % 2000000 + 1000);
  BYTE* randomData = new BYTE[newFileLen];
  for (size_t i = 0; i < newFileLen; i++) {
    randomData[i] = (BYTE)(rand() % 255);
  }
  file_ofstream.write(reinterpret_cast<char*>(randomData), newFileLen);
  file_ofstream.close();
  delete[] randomData;

  // unlink the file
  if (_wremove(driver_path.c_str()) != 0) return STATUS_DELETE_PENDING;

  return STATUS_SUCCESS;
}

bool ReadDllFile(const std::wstring& dll_path, std::vector<BYTE>& dll_buffer,
                 DWORD& dll_size) {
  HANDLE file_handle =
      CreateFileW(dll_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file_handle == INVALID_HANDLE_VALUE) {
    return false;
  }

  dll_size = GetFileSize(file_handle, NULL);
  dll_buffer.resize(dll_size);

  DWORD bytes_read;
  BOOL result =
      ReadFile(file_handle, dll_buffer.data(), dll_size, &bytes_read, NULL);

  CloseHandle(file_handle);
  return result && (bytes_read == dll_size);
}

DWORD FindProcessId(const std::wstring& process_name) {
  DWORD pid = 0;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  if (snapshot != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &process_entry)) {
      std::wstring process_name_with_exe = process_name + L".exe";

      do {
        bool is_match =
            (_wcsicmp(process_entry.szExeFile, process_name.c_str()) == 0) ||
            (_wcsicmp(process_entry.szExeFile, process_name_with_exe.c_str()) ==
             0);

        if (is_match) {
          pid = process_entry.th32ProcessID;
          break;
        }
      } while (Process32NextW(snapshot, &process_entry));
    }
    CloseHandle(snapshot);
  }

  return pid;
}

int main() {
  std::cout << "Zhang Bing WHQL Signed Super Trash Injector\n\n";

  std::wstring dll_path;
  std::wstring process_name;
  LPWSTR* szArgList;
  int nArgs;
  szArgList = CommandLineToArgvW(GetCommandLineW(), &nArgs);
  if (szArgList == nullptr) {
    std::wcout << L"Error: Failed to parse command line\n";
    std::wcout.flush();
    system("pause");
    return 1;
  }

  if (nArgs >= 2) {
    dll_path = szArgList[1];
    std::wcout << L"DLL path: " << dll_path << L"\n";
    std::wcout.flush();
  }
  if (nArgs >= 3) {
    process_name = szArgList[2];
    std::wcout << L"Process name: " << process_name
               << L"\n";
    std::wcout.flush();
  }
  LocalFree(szArgList);
  if (dll_path.empty()) {
    std::wcout << L"Please enter DLL path: ";
    std::wcin >> dll_path;
  }
  if (process_name.empty()) {
    std::wcout << L"Please enter process name: ";
    std::wcin >> process_name;
  }

  std::cout << "Loading Dr.Zhang driver\n";
  std::wstring driver_path = GetDriverPath();
  if (driver_path.empty()) {
    std::cout << "Can't find TEMP folder\n";
    system("pause");
    return 1;
  }

  _wremove(driver_path.c_str());
  if (!CreateFileFromMemory(
          driver_path, reinterpret_cast<const char*>(rawdata::kRxdriverRawData),
          sizeof(rawdata::kRxdriverRawData))) {
    std::cout << "Failed to create bingbing driver file\n";
    system("pause");
    return 1;
  }

  auto status = AcquireDebugPrivilege();
  if (!NT_SUCCESS(status)) {
    std::cout << "Failed to acquire SeDebugPrivilege\n";
    _wremove(driver_path.c_str());
    system("pause");
    return status;
  }

  status = RegisterAndStart(driver_path, GetDriverNameW());
  if (!NT_SUCCESS(status)) {
    std::cout
        << "Failed to register and start service for Zhang Bing's driver\n";
    _wremove(driver_path.c_str());
    system("pause");
    return status;
  }

  DWORD target_pid = FindProcessId(process_name);
  if (target_pid == 0) {
    std::wcout << L"Error: Process " << process_name << L" not found.\n";
    Unload();
    system("pause");
    return 1;
  }
  std::cout << "Found process PID: " << target_pid << "\n";

  std::vector<BYTE> dll_data;
  DWORD dll_size = 0;

  if (!ReadDllFile(dll_path, dll_data, dll_size)) {
    std::wcout << L"Error: Cannot read " << dll_path << L".\n";
    Unload();
    system("pause");
    return 1;
  }

  std::cout << "DLL size: " << dll_size << " bytes\n";

  HANDLE driver_handle =
      CreateFileW(DRIVER_SYMBOLIC_LINK, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                  OPEN_EXISTING, 0, NULL);

  if (driver_handle == INVALID_HANDLE_VALUE) {
    std::cout << "Error: Cannot open driver (error " << GetLastError() << ")\n";
    Unload();
    system("pause");
    return 1;
  }

  std::cout << "Driver handle: " << driver_handle << "\n";

  DriverInjectionData injection_data = {0};
  injection_data.process_id = target_pid;
  injection_data.data_size = dll_size;
  injection_data.data_buffer = dll_data.data();
  injection_data.verify_code = VERIFICATION_CODE;

  std::cout << "\nSending to driver:\n";
  std::cout << "  Structure size: " << sizeof(injection_data) << " bytes\n";
  std::cout << "  ProcessId: " << injection_data.process_id << "\n";
  std::cout << "  DataSize: " << injection_data.data_size << "\n";
  std::cout << "  DataBuffer: " << injection_data.data_buffer << "\n";
  std::cout << "  VerifyCode: " << injection_data.verify_code << "\n";

  DWORD bytes_returned = 0;
  BOOL success =
      DeviceIoControl(driver_handle, IOCTL_INJECT_DLL, &injection_data,
                      sizeof(injection_data), NULL, 0, &bytes_returned, NULL);

  if (success) {
    std::cout << "\nIOCTL sent successfully!\n";
    std::cout << "Bytes returned: " << bytes_returned << "\n";
    Sleep(3000);
  } else {
    std::cout << "\nError: DeviceIoControl failed (error " << GetLastError()
              << ")\n";
  }

  CloseHandle(driver_handle);
  Unload();
  system("pause");
  return 0;
}

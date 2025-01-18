#include <windows.h>
#include <tlHelp32.h>
#include <string>
#include <thread>
#include <conio.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <cstdlib>
#include <regex>
#include <array>
#include <set>
#include <map>
#include <mutex>

#define KeyDown(VK_NONAME) ((GetAsyncKeyState(VK_NONAME) & 0x8000) ? 1 : 0)

void Stop_Im() {
	while (1) {
		int num = 0;
		for (int i = 0x60; i <= 0x69; i++) {
			if (KeyDown(i)) {
				num++;
			}
		}
		if (num >= 5) {
			exit(0);
		}
		Sleep(100);
	}
}

class SHA256 {
	public:
	    SHA256() { reset(); }
	
	    void update(const uint8_t* data, size_t length) {
	        for (size_t i = 0; i < length; ++i) {
	            data_[datalen_++] = data[i];
	            if (datalen_ == 64) {
	                transform();
	                bitlen_ += 512;
	                datalen_ = 0;
	            }
	        }
	    }
	
	    void update(const std::string& data) {
	        update(reinterpret_cast<const uint8_t*>(data.c_str()), data.size());
	    }
	
	    std::string final() {
	        uint8_t hash[32];
	        pad();
	        revert(hash);
	        std::stringstream ss;
	        for (int i = 0; i < 32; ++i) {
	            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	        }
	        return ss.str();
	    }
	
	private:
	    uint8_t data_[64];
	    uint32_t datalen_;
	    uint64_t bitlen_;
	    uint32_t state_[8];
	
	    static constexpr std::array<uint32_t, 64> k_ = {
	        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	    };
	
	    static uint32_t rotr(uint32_t x, uint32_t n) {
	        return (x >> n) | (x << (32 - n));
	    }
	
	    static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
	        return (e & f) ^ (~e & g);
	    }
	
	    static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
	        return (a & b) ^ (a & c) ^ (b & c);
	    }
	
	    static uint32_t sig0(uint32_t x) {
	        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
	    }
	
	    static uint32_t sig1(uint32_t x) {
	        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
	    }
	
	    void transform() {
	        uint32_t maj, xorA, ch, xorE, sum, newA, newE, m[64];
	        uint32_t state[8];
	
	        for (int i = 0, j = 0; i < 16; ++i, j += 4)
	            m[i] = (data_[j] << 24) | (data_[j + 1] << 16) | (data_[j + 2] << 8) | (data_[j + 3]);
	        for (int k = 16; k < 64; ++k)
	            m[k] = sig1(m[k - 2]) + m[k - 7] + sig0(m[k - 15]) + m[k - 16];
	
	        for (int i = 0; i < 8; ++i)
	            state[i] = state_[i];
	
	        for (int i = 0; i < 64; ++i) {
	            maj = majority(state[0], state[1], state[2]);
	            xorA = rotr(state[0], 2) ^ rotr(state[0], 13) ^ rotr(state[0], 22);
	
	            ch = choose(state[4], state[5], state[6]);
	
	            xorE = rotr(state[4], 6) ^ rotr(state[4], 11) ^ rotr(state[4], 25);
	
	            sum = m[i] + k_[i] + state[7] + ch + xorE;
	            newA = xorA + maj + sum;
	            newE = state[3] + sum;
	
	            state[7] = state[6];
	            state[6] = state[5];
	            state[5] = state[4];
	            state[4] = newE;
	            state[3] = state[2];
	            state[2] = state[1];
	            state[1] = state[0];
	            state[0] = newA;
	        }
	
	        for (int i = 0; i < 8; ++i)
	            state_[i] += state[i];
	    }
	
	    void pad() {
	        uint64_t i = datalen_;
	
	        if (datalen_ < 56) {
	            data_[i++] = 0x80;
	            while (i < 56)
	                data_[i++] = 0x00;
	        } else {
	            data_[i++] = 0x80;
	            while (i < 64)
	                data_[i++] = 0x00;
	            transform();
	            memset(data_, 0, 56);
	        }
	
	        bitlen_ += datalen_ * 8;
	        data_[63] = bitlen_;
	        data_[62] = bitlen_ >> 8;
	        data_[61] = bitlen_ >> 16;
	        data_[60] = bitlen_ >> 24;
	        data_[59] = bitlen_ >> 32;
	        data_[58] = bitlen_ >> 40;
	        data_[57] = bitlen_ >> 48;
	        data_[56] = bitlen_ >> 56;
	        transform();
	    }
	
	    void revert(uint8_t* hash) {
	        for (int i = 0; i < 4; ++i) {
	            for (int j = 0; j < 8; ++j) {
	                hash[i + (j * 4)] = (state_[j] >> (24 - i * 8)) & 0x000000ff;
	            }
	        }
	    }
	
	    void reset() {
	        datalen_ = 0;
	        bitlen_ = 0;
	        state_[0] = 0x6a09e667;
	        state_[1] = 0xbb67ae85;
	        state_[2] = 0x3c6ef372;
	        state_[3] = 0xa54ff53a;
	        state_[4] = 0x510e527f;
	        state_[5] = 0x9b05688c;
	        state_[6] = 0x1f83d9ab;
	        state_[7] = 0x5be0cd19;
	    }
};

std::string sha256(std::string str) {
    SHA256 sha;
    sha.update(str);
    return sha.final();
}

HWND Window = GetConsoleWindow();
bool HideWindow = false, Stop = false, can = true;
int line = 1;

void Show() 
{
    while (!Stop) {
    	
    	if (KeyDown(VK_LCONTROL) && KeyDown(VK_LSHIFT) && (KeyDown('z') || KeyDown('Z')) && can) {
    		
    		HideWindow = !HideWindow;
    		if (HideWindow) {
    			for (int i = 255; i >= 0; i -= 10) {
					SetLayeredWindowAttributes(Window, 0, std::max(0, i), LWA_ALPHA);
					Sleep(1); 
				}
				SetLayeredWindowAttributes(Window, 0, 0, LWA_ALPHA);
				ShowWindow(Window, SW_HIDE); 
			} else {
				ShowWindow(Window, SW_SHOW); 
				for (int i = 0; i <= 255; i += 10) {
					SetLayeredWindowAttributes(Window, 0, std::min(255, i), LWA_ALPHA);
					Sleep(1); 
				}
				SetLayeredWindowAttributes(Window, 0, 255, LWA_ALPHA);
			}
    		while (KeyDown(VK_LCONTROL) && KeyDown(VK_LSHIFT) && (KeyDown('z') || KeyDown('Z')));
		}
	}
}

namespace Hook_common {

    int globlePid = 0;
    HHOOK keyHook = NULL;
    HHOOK mouseHook = NULL;

    LRESULT CALLBACK keyProc(int nCode, WPARAM wParam, LPARAM lParam) {
        KBDLLHOOKSTRUCT * pkbhs = (KBDLLHOOKSTRUCT * ) lParam;
        if (pkbhs -> vkCode == VK_ESCAPE && GetAsyncKeyState(VK_CONTROL) & 0x8000 && GetAsyncKeyState(VK_SHIFT) & 0x8000) {
            return 1;
        } else if (pkbhs -> vkCode == VK_ESCAPE && GetAsyncKeyState(VK_CONTROL) & 0x8000) {
            return 1;
        } else if (pkbhs -> vkCode == VK_TAB && pkbhs -> flags & LLKHF_ALTDOWN) {
            return 1;
        } else if (pkbhs -> vkCode == VK_ESCAPE && pkbhs -> flags & LLKHF_ALTDOWN) {
            return 1;
        } else if (pkbhs -> vkCode == VK_LWIN || pkbhs -> vkCode == VK_RWIN) {
            return 1;
        } else if (pkbhs -> vkCode == VK_F4 && pkbhs -> flags & LLKHF_ALTDOWN) {
            return 1;
        }

        return CallNextHookEx(keyHook, nCode, wParam, lParam);
    }

    LRESULT CALLBACK mouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
        return 1;
    }

    void unHook() {
    	UnhookWindowsHookEx(keyHook);
    }

    void setHook() {
        keyHook = SetWindowsHookEx(WH_KEYBOARD_LL, keyProc, GetModuleHandle(NULL), 0);
    }
    
    char * ConvertLPWSTRToLPSTR(LPWSTR lpwszStrIn) {
        LPSTR pszOut = NULL;
        if (lpwszStrIn != NULL) {
            int nInputStrLen = wcslen(lpwszStrIn);

            int nOutputStrLen = WideCharToMultiByte(CP_ACP, 0, lpwszStrIn, nInputStrLen, NULL, 0, 0, 0) + 2;
            pszOut = new char[nOutputStrLen];

            if (pszOut) {
                memset(pszOut, 0x00, nOutputStrLen);
                WideCharToMultiByte(CP_ACP, 0, lpwszStrIn, nInputStrLen, pszOut, nOutputStrLen, 0, 0);
            }
        }
        return pszOut;
    }

    wchar_t * charToWchar_t(const char * c) {
        const size_t cSize = strlen(c) + 1;
        wchar_t * wc = new wchar_t[cSize];
        mbstowcs(wc, c, cSize);
        return wc;
    }

}

namespace Hook {
	
	#define SE_DEBUG_PRIVILEGE 20

	typedef LONG(__stdcall *RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
	typedef LONG(__stdcall *SuspendOrResumeProcess)(HANDLE hProcess);
	
	DWORD GetWinlogonPid() {
		HANDLE snap;
		PROCESSENTRY32 pEntry;
		BOOL rtn;
	
		snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pEntry.dwSize = sizeof(pEntry);
		rtn = Process32First(snap, &pEntry);
		while (rtn) {
			if (!strcmp(pEntry.szExeFile, "winlogon.exe")) {
				CloseHandle(snap);
				return pEntry.th32ProcessID;
			}
			memset(pEntry.szExeFile, 0, 260);
			rtn = Process32Next(snap, &pEntry);
		}
	
		CloseHandle(snap);
		return 0;
	}
	
	bool LockCtrlAltDel() {
		HMODULE hMod = LoadLibrary("ntdll");
		if (hMod == 0) return false;
		RtlAdjustPrivilege lpfnRtlAdjustPrivilege = (RtlAdjustPrivilege)GetProcAddress(hMod, "RtlAdjustPrivilege");
		if (lpfnRtlAdjustPrivilege == 0) return false;
		SuspendOrResumeProcess lpfnNtSuspendProcess = (SuspendOrResumeProcess)GetProcAddress(hMod, "NtSuspendProcess");
		if (lpfnNtSuspendProcess == 0) return false;
		SuspendOrResumeProcess lpfnNtResumeProcess = (SuspendOrResumeProcess)GetProcAddress(hMod, "NtResumeProcess");
		if (lpfnNtResumeProcess == 0) return false;
		DWORD pid = GetWinlogonPid();
		if (pid == 0) return false;
		BOOLEAN dummy = 0;
		lpfnRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, true, false, &dummy);
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
		if (hProcess == 0) return false;
		lpfnNtSuspendProcess(hProcess);
		CloseHandle(hProcess);
		return true;
	} 
	
	bool UnlockCtrlAltDel() {
		HMODULE hMod = LoadLibrary("ntdll");
		if (hMod == 0) return false;
		RtlAdjustPrivilege lpfnRtlAdjustPrivilege = (RtlAdjustPrivilege)GetProcAddress(hMod, "RtlAdjustPrivilege");
		if (lpfnRtlAdjustPrivilege == 0) return false;
		SuspendOrResumeProcess lpfnNtSuspendProcess = (SuspendOrResumeProcess)GetProcAddress(hMod, "NtSuspendProcess");
		if (lpfnNtSuspendProcess == 0) return false;
		SuspendOrResumeProcess lpfnNtResumeProcess = (SuspendOrResumeProcess)GetProcAddress(hMod, "NtResumeProcess");
		if (lpfnNtResumeProcess == 0) return false;
		DWORD pid = GetWinlogonPid();
		if (pid == 0) return false;
		BOOLEAN dummy = 0;
		lpfnRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, true, false, &dummy);
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
		if (hProcess == 0) return false;
		lpfnNtResumeProcess(hProcess);
		CloseHandle(hProcess);
		return true;
	}
}

void FullScreen(HWND hwnd) {
    int cx = GetSystemMetrics(SM_CXSCREEN);
    int cy = GetSystemMetrics(SM_CYSCREEN);
    LONG l_WinStyle = GetWindowLong(hwnd, GWL_STYLE);
    SetWindowLong(hwnd, GWL_STYLE, (l_WinStyle | WS_POPUP | WS_MAXIMIZE) & compl WS_CAPTION & compl WS_THICKFRAME & compl WS_BORDER);
    SetWindowPos(hwnd, HWND_TOP, 0, 0, cx, cy, 0);
}

void TopWindow(HWND hwnd) {
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

void RestoreWindow(HWND hwnd) {
    LONG l_WinStyle = GetWindowLong(hwnd, GWL_STYLE);
    SetWindowLong(hwnd, GWL_STYLE, (l_WinStyle & ~WS_POPUP & ~WS_MAXIMIZE) | WS_CAPTION | WS_THICKFRAME | WS_BORDER);
    SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_FRAMECHANGED);
}

void UnTopWindow(HWND hwnd) {
    SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

bool flag = false;

void ControlWindow(HWND hwnd) {
	while (1) {
		if (flag) {
			can = false;
			SetLayeredWindowAttributes(Window, 0, 255, LWA_ALPHA);
			ShowWindow(Window, SW_SHOW); 
			Hook::LockCtrlAltDel();
			Hook_common::setHook();
			while (flag) {
				SetForegroundWindow(hwnd);
				TopWindow(hwnd);
				FullScreen(hwnd);
				SetCursorPos(0, 0);
			}
			TopWindow(hwnd);
			FullScreen(hwnd);
			RestoreWindow(hwnd);
		    UnTopWindow(hwnd);
		    system("mode con: cols=60 lines=7");
			Hook::UnlockCtrlAltDel();
			Hook_common::unHook();
			can = true;
			if (HideWindow) {
    			for (int i = 255; i >= 0; i -= 10) {
					SetLayeredWindowAttributes(Window, 0, std::max(0, i), LWA_ALPHA);
					Sleep(1); 
				}
				SetLayeredWindowAttributes(Window, 0, 0, LWA_ALPHA);
				ShowWindow(Window, SW_HIDE); 
			} else {
				ShowWindow(Window, SW_SHOW); 
				for (int i = 0; i <= 255; i += 10) {
					SetLayeredWindowAttributes(Window, 0, std::min(255, i), LWA_ALPHA);
					Sleep(1); 
				}
				SetLayeredWindowAttributes(Window, 0, 255, LWA_ALPHA);
			}
		}
	}
}

std::string password;

bool IsAlreadyRunning() {
    HANDLE hMutex = CreateMutex(NULL, FALSE, "Global\\ScreenLocker");
    DWORD dwWaitResult = WaitForSingleObject(hMutex, 0);
    if (dwWaitResult == WAIT_OBJECT_0) {
        CloseHandle(hMutex);
        return false;
    } else if (dwWaitResult == WAIT_ABANDONED) {
        CloseHandle(hMutex);
        return true;
    } else if (dwWaitResult == WAIT_TIMEOUT) {
        CloseHandle(hMutex);
        return true;
    }
    CloseHandle(hMutex);
    return true;
}

bool CheckPassword() {
	if(password.size() < 10 || password.size() > 30) return true;
	for (int i = 0; i < password.size(); i++) {
		char tmp = password[i];
		if (!((tmp >= 'a' && tmp <= 'z') || (tmp >= 'A' && tmp <= 'Z') || (tmp >= '0' && tmp <= '9'))) {
			return true;
		}
	}
	return false;
}

int main() {
	Hook::UnlockCtrlAltDel();
	HANDLE hMutex = CreateMutex(NULL, FALSE, "Global\\SqrtLocker");
    DWORD dwWaitResult = WaitForSingleObject(hMutex, 0);
    if(IsAlreadyRunning()) return 1;
	system("mode con: cols=60 lines=7");
    Window = GetForegroundWindow();
	std::thread cm(ControlWindow, Window);
	std::thread sh(Show);
//	std::thread st(Stop_Im);
	cm.detach(); sh.detach();
//	st.detach();
	std::ifstream inp("password");
	inp >> password;
	inp.close();
	if (password == "") {
		back:system("cls");
		std::cout << "请设置密码（设置完毕后请按空格确定密码是否正确）：\n";
		password = ""; 
		bool fl = false;
		back1:;
		while(1) {
			char tmp = getch();
			if (tmp == 8) {
				if (password.size() > 0) {
					std::cout << "\b \b";
					password = password.substr(0, password.size() - 1);
				}
			} else if (tmp == 13) {
				if (password.size() > 0) {
					std::cout << "\n";
					fl = true;
					break; 
				}
			} else if ((tmp >= 'a' && tmp <= 'z') || (tmp >= 'A' && tmp <= 'Z') || (tmp >= '0' && tmp <= '9')) {
				password += char(tmp);
				std::cout << "*";
			} else if (tmp == ' ') {
				break;
			}
		}
		if (!fl) {
			system("cls");
			std::cout << "请设置密码（设置完毕后请按空格确定密码是否正确）：\n" << password;
			while (KeyDown(' '));
			system("cls");
			std::cout << "请设置密码（设置完毕后请按空格确定密码是否正确）：\n";
			for (int i = 0; i < password.size(); i++) std::cout << "*"; 
			goto back1;
		}
		if (CheckPassword()) goto back;
		std::ofstream outp("password");
		outp << sha256(password);
		outp.close();
		password = sha256(password);
	}
	system("cls");
	std::cout << "SqrtLocker v1.0\nAuthor:Sqrt404\nhttps://github.com/Sqrt404/SqrtLocker\n\n使用方法：[F2] 快速锁定\n[LeftControl+LeftShift+Z] 显示/隐藏窗口\n\n按下任意键继续";
	getch(); 
	HWND hwnd = GetForegroundWindow();
	SetWindowLong(Window, GWL_EXSTYLE, GetWindowLong(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
	HideWindow = true;
	for (int i = 255; i >= 0; i -= 10) {
		SetLayeredWindowAttributes(Window, 0, std::max(0, i), LWA_ALPHA);
		Sleep(1); 
	}
	SetLayeredWindowAttributes(Window, 0, 0, LWA_ALPHA);
	ShowWindow(Window, SW_HIDE); 
	system("cls");
	while (1) {
		system("cls"); 
		std::cout << "SqrtLocker v1.0\nAuthor:Sqrt404\nhttps://github.com/Sqrt404/SqrtLocker";
		while (!KeyDown(VK_F2));
		flag = true;
		while (1) {
			system("cls");
			std::string s = "";
			std::cout << "  password: ";
			while(s.size() <= 20) {
				char tmp = getch();
				if (tmp == 8) {
					if (s.size() > 0) {
						std::cout << "\b \b";
						s = s.substr(0, s.size() - 1);
					}
				} else if (tmp == 13) {
					if (s.size() > 0) {
						std::cout << "\n";
						break; 
					}
				} else if ((tmp >= 'a' && tmp <= 'z') || (tmp >= 'A' && tmp <= 'Z') || (tmp >= '0' && tmp <= '9')) {
					s += char(tmp);
					std::cout << "*";
				}
			}
			if(sha256(s) == password) break;
		}
		flag = false;
		Hook::UnlockCtrlAltDel();
		LockWorkStation();
	}
	CloseHandle(hMutex);
	return 0;
}

#include"SimpleHook.h"
#define ZYCORE_STATIC_DEFINE
#define ZYDIS_STATIC_DEFINE
#include<inttypes.h>
#include"../Zydis64/Zydis/Zydis.h"
#ifndef _WIN64
#pragma comment(lib, "../Share/Hook/Zydis.lib")
#pragma comment(lib, "../Share/Hook/Zycore.lib")
#else
#pragma comment(lib, "../Share/Hook/Zydis64.lib")
#pragma comment(lib, "../Share/Hook/Zycore64.lib")
#endif
#include<vector>
#include<tlhelp32.h>

ZydisDecoder zDecoder;
ZydisFormatter zFormatter;

// hook internal
class FunctionHook {
private:
	void *Memory;
	ULONG_PTR MemorySize;
	ULONG_PTR HookAddress;
	bool bHooked;
#ifndef _WIN64
#define JMP_OPCODE_SIZE_SHORT 2
#define JMP_OPCODE_SIZE_LONG 5
#define HOT_PATCH_SIZE 5
#else
//#define JMP_OPCODE_SIZE 14
#define JMP_OPCODE_SIZE_SHORT 6
#define JMP_OPCODE_SIZE_LONG 14
#define HOT_PATCH_SIZE 8
#endif

	void operator=(const FunctionHook&) {}
	FunctionHook(const FunctionHook&) {}

	static void Redirection(ULONG_PTR &dwEIP) {
#ifndef _WIN64
		if (memcmp((void *)dwEIP, "\xFF\x25", 2) == 0) {
			dwEIP = *(DWORD *)(*(DWORD *)(dwEIP + 0x02));
			return Redirection(dwEIP);
		}
		if (memcmp((void *)dwEIP, "\x55\x8B\xEC\x5D\xFF\x25", 6) == 0) {
			dwEIP = *(DWORD *)(*(DWORD *)(dwEIP + 0x06));
			return Redirection(dwEIP);
		}
		if (memcmp((void *)dwEIP, "\x8B\xFF\x55\x8B\xEC\x5D\xFF\x25", 8) == 0) {
			dwEIP = *(DWORD *)(*(DWORD *)(dwEIP + 0x08));
			return Redirection(dwEIP);
		}
		if (memcmp((void *)dwEIP, "\x8B\xFF\x55\x8B\xEC\x5D\xE9", 7) == 0) {
			dwEIP = (dwEIP + 0x06) + *(signed long int *)(dwEIP + 0x07) + 0x05;
			return Redirection(dwEIP);
		}
		if (memcmp((void *)dwEIP, "\xEB", 1) == 0) {
			dwEIP += *(char *)(dwEIP + 0x01) + 0x02;
			return Redirection(dwEIP);
		}
		if (memcmp((void *)dwEIP, "\xE9", 1) == 0) {
			dwEIP += *(signed long int *)(dwEIP + 0x01) + 0x05;
			return Redirection(dwEIP);
		}
#else
		// GetProcAddress
		if (memcmp((void *)dwEIP, "\x4C\x8B\x04\x24\x48\xFF\x25", 7) == 0) {
			dwEIP = *(ULONG_PTR *)(dwEIP + 0x04 + *(signed long int *)(dwEIP + 0x03 + 0x04) + 0x07);
			return Redirection(dwEIP);
		}
		if (memcmp((void *)dwEIP, "\x48\xFF\x25", 3) == 0) {
			dwEIP = *(ULONG_PTR *)(dwEIP + *(signed long int *)(dwEIP + 0x03) + 0x07);
			return Redirection(dwEIP);
		}
		if (memcmp((void *)dwEIP, "\xFF\x25", 2) == 0) {
			dwEIP = *(ULONG_PTR *)(dwEIP + *(signed long int *)(dwEIP + 0x02) + 0x06);
			return Redirection(dwEIP);
		}
		if (memcmp((void *)dwEIP, "\xE9", 1) == 0) {
			dwEIP += *(signed long int *)(dwEIP + 0x01) + 0x05;
			return Redirection(dwEIP);
		}
#endif
	}

	static bool DecodeInit() {
#ifndef _WIN64
		ZydisDecoderInit(&::zDecoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#else
		ZydisDecoderInit(&::zDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#endif
		ZydisFormatterInit(&zFormatter, ZYDIS_FORMATTER_STYLE_INTEL);
		return true;
	}

	static ULONG_PTR Decode(ULONG_PTR uStartAddress, bool bHotPatch) {
		static bool bDecode = false;

		if (!bDecode) {
			bDecode = DecodeInit();
		}

		ZydisDecodedInstruction zInst;
		ULONG_PTR uEIP = uStartAddress;
		Redirection(uEIP);

		ULONG_PTR uLength = 0;
		while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&::zDecoder, (void *)uEIP, 100, &zInst))) {
			if (ZYDIS_MNEMONIC_JB <= zInst.mnemonic && zInst.mnemonic <= ZYDIS_MNEMONIC_JZ) {
				return uLength;
			}
			if (zInst.mnemonic == ZYDIS_MNEMONIC_CALL) {
				return uLength;
			}
			uEIP += zInst.length;
			uLength += zInst.length;
			if (bHotPatch) {
				if (uLength >= JMP_OPCODE_SIZE_SHORT) {
					return uLength;
				}
			}
			else {
				if (uLength >= JMP_OPCODE_SIZE_LONG) {
					return uLength;
				}
			}
		}

		return 0;
	}

	static bool HotPatch(ULONG_PTR uHookAddress, ULONG_PTR &uHotPatch) {
#ifndef _WIN64
		ULONG_PTR uFreeSpace = *(ULONG_PTR *)(uHookAddress - 0x05);
		for (ULONG_PTR i = 0; i < 5; i++) {
			BYTE bFreeSpace = *(BYTE *)(uHookAddress - 0x05 + i);
			if (bFreeSpace != 0x90 && bFreeSpace != 0xCC) {
				return false;
			}
		}
		return true;
#else
		ULONG_PTR uFreeSpace = *(ULONG_PTR *)(uHookAddress - 0x08);

		switch (uFreeSpace) {
		case 0xCCCCCCCCCCCCCCCC:
		case 0x9090909090909090:
		case 0x0000000000841F0F:
		{
			uHotPatch = uHookAddress - 0x08;
			return true;
		}
		default:
		{
			break;
		}
		}

		// 5 bytes long jmp
		for (ULONG_PTR i = 0x05; i <= 0x2000; i++) {
			if (*(ULONG_PTR *)(uHookAddress + i) == 0xCCCCCCCCCCCCCCCC) {
				if (*(BYTE *)(uHookAddress + i - 1) == 0xC3) {
					uHotPatch = uHookAddress + i;
					return true;
				}
			}
		}
		/*
		// 2 bytes short jmp
		for (ULONG_PTR i = (-0x80 + 0x02); i <= (0x7F + 0x02); i++) {
			if (*(ULONG_PTR *)(uHookAddress + i) == 0xCCCCCCCCCCCCCCCC) {
				if (*(BYTE *)(uHookAddress + i - 1) == 0xC3) {
					uHotPatch = uHookAddress + i;
					return true;
				}
			}
		}
		*/
		return 0;
#endif
	}

public:
	FunctionHook(void *HookFunction, void *FunctionPointer, ULONG_PTR Address, ULONG_PTR OverWrite) {
		bHooked = false;
		Memory = NULL;
		MemorySize = OverWrite;
		HookAddress = Address;
		// real api finder
		Redirection(HookAddress);
		bool bHotPatch = false;
		ULONG_PTR uFreeSpace = 0;
		if (MemorySize == 0) {
			bHotPatch = HotPatch(HookAddress, uFreeSpace);
			MemorySize = Decode(HookAddress, bHotPatch);
		}

		if (bHotPatch) {
			if (MemorySize < JMP_OPCODE_SIZE_SHORT) {
				return;
			}
		}
		else {
			if (MemorySize < JMP_OPCODE_SIZE_LONG) {
				return;
			}
		}

		Memory = VirtualAlloc(NULL, MemorySize + JMP_OPCODE_SIZE_LONG, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!Memory) {
			return;
		}

		void *vpAddress = (void *)(HookAddress);
		SIZE_T vpSize = MemorySize;
		ULONG_PTR uJMP_CODE_SIZE = JMP_OPCODE_SIZE_LONG;

		if (bHotPatch) {
			vpAddress = (void *)(HookAddress - HOT_PATCH_SIZE);
			vpSize += HOT_PATCH_SIZE;
			uJMP_CODE_SIZE = JMP_OPCODE_SIZE_SHORT;
		}

		DWORD old;
		if (!VirtualProtect(vpAddress, vpSize, PAGE_EXECUTE_READWRITE, &old)) {
			return;
		}

		DWORD old2;
		if (uFreeSpace && !VirtualProtect((void *)uFreeSpace, 8, PAGE_EXECUTE_READWRITE, &old2)) {
			return;
		}

		*(ULONG_PTR *)FunctionPointer = (ULONG_PTR)Memory;
		memcpy_s(Memory, MemorySize, (void *)HookAddress, MemorySize);
#ifndef _WIN64
		((BYTE *)(Memory))[MemorySize] = 0xE9;
		*(DWORD *)&((BYTE *)(Memory))[MemorySize + 1] = (HookAddress + MemorySize) - (ULONG_PTR)&((BYTE *)(Memory))[MemorySize] - 0x05;

		if (bHotPatch) {
			*(BYTE *)(HookAddress - 0x05) = 0xE9;
			*(DWORD *)(HookAddress - 0x05 + 0x01) = (ULONG_PTR)HookFunction - (HookAddress - 0x05) - 0x05;
			*(WORD *)HookAddress = 0xF9EB;
		}
		else {
			*(BYTE *)HookAddress = 0xE9;
			*(DWORD *)(HookAddress + 0x01) = (ULONG_PTR)HookFunction - HookAddress - 0x05;
		}
#else
		*(WORD *)((ULONG_PTR)Memory + MemorySize) = 0x25FF;
		*(DWORD *)((ULONG_PTR)Memory + MemorySize + 0x02) = 0;
		*(ULONG_PTR *)((ULONG_PTR)Memory + MemorySize + 0x06) = HookAddress + MemorySize;

		if (bHotPatch && uFreeSpace) {
			*(ULONG_PTR *)(uFreeSpace) = (ULONG_PTR)HookFunction;
			*(WORD *)HookAddress = 0x25FF;
			*(DWORD *)(HookAddress + 0x02) = (DWORD)(uFreeSpace - HookAddress - 0x06);
		}
		else {
			*(WORD *)HookAddress = 0x25FF;
			*(DWORD *)(HookAddress + 0x02) = 0;
			*(ULONG_PTR *)(HookAddress + 0x06) = (ULONG_PTR)HookFunction;
		}
#endif

		for (ULONG_PTR i = uJMP_CODE_SIZE; i < MemorySize; i++) {
			*(BYTE *)(HookAddress + i) = 0x90;
		}

		if (VirtualProtect(vpAddress, vpSize, old, &old)) {
			bHooked = true;
		}
		if (uFreeSpace && !VirtualProtect((void *)uFreeSpace, 8, old2, &old2)) {
			return;
		}
		return;
	}

	~FunctionHook() {
		if (Memory) {
			DWORD old;
			if (VirtualProtect((void *)HookAddress, MemorySize, PAGE_EXECUTE_READWRITE, &old)) {
				memcpy_s((void *)HookAddress, MemorySize, (void *)Memory, MemorySize);
				VirtualFree(Memory, 0, MEM_RELEASE);
				Memory = NULL;
			}
		}
	}

	static ULONG_PTR Decode(ULONG_PTR uStartAddress) {
		return Decode(uStartAddress, false);
	}

	static ULONG_PTR Decode(ULONG_PTR uStartAddress, std::vector<BYTE> &vCodeSize, ULONG_PTR uMinimumSize) {
		static bool bDecode = false;

		if (!bDecode) {
			bDecode = DecodeInit();
		}

		ZydisDecodedInstruction zInst;
		ULONG_PTR uEIP = uStartAddress;
		Redirection(uEIP);

		ULONG_PTR uLength = 0;
		while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&::zDecoder, (void *)uEIP, 100, &zInst))) {
			if (ZYDIS_MNEMONIC_JB <= zInst.mnemonic && zInst.mnemonic <= ZYDIS_MNEMONIC_JZ) {
				return 0;
			}
			if (zInst.mnemonic == ZYDIS_MNEMONIC_CALL) {
				return 0;
			}
			uEIP += zInst.length;
			uLength += zInst.length;

			vCodeSize.push_back(zInst.length);

			if (uLength >= uMinimumSize) {
				return uLength;
			}
		}

		return 0;
	}

	bool IsHooked() {
		return bHooked;
	}

	// Inline Hook
	FunctionHook(void *HookFunction, ULONG_PTR Address, DWORD dwStackValue) {
		bHooked = false;
		Memory = NULL;
		MemorySize = 0;
		HookAddress = Address;
		Redirection(HookAddress);
		MemorySize = Decode(HookAddress);

		if (MemorySize < JMP_OPCODE_SIZE_LONG) {
			return;
		}

#pragma pack(push, 1)
		typedef struct {
			BYTE b1[4]; // mov rcx,[rsp+StackValue]
			DWORD dwStackValue;
			BYTE b2[4]; // sub rsp,20
			BYTE b3[2]; // mov rax,HookFunction
			ULONG_PTR uHookFunction;
			BYTE b4[2]; // call rax
			BYTE b5[4]; // add rsp,20
		} CallHookFunc;
#pragma pack(pop)

		// x64 hook
		BYTE bPushRegisters[] = { 0x9C,0x50,0x51,0x52,0x53,0x55,0x56,0x57,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57 }; // レジスタを保存
		BYTE bPopRegisters[] = { 0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,0x5F,0x5E,0x5D,0x5B,0x5A,0x59,0x58,0x9D }; // レジスタを復元
		BYTE bCallHookFunction[] = { 0x48,0x8B,0x8C,0x24,0xAA,0xAA,0xAA,0xAA,0x48,0x83,0xEC,0x20,0x48,0xB8,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xFF,0xD0,0x48,0x83,0xC4,0x20 }; // 呼び出し
		CallHookFunc *chf = (CallHookFunc *)&bCallHookFunction[0];

		chf->dwStackValue = dwStackValue;
		chf->uHookFunction = (ULONG_PTR)HookFunction;

		Memory = VirtualAlloc(NULL, sizeof(bPushRegisters) + sizeof(bCallHookFunction) + sizeof(bPopRegisters) + MemorySize + JMP_OPCODE_SIZE_LONG, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!Memory) {
			return;
		}

		void *vpAddress = (void *)(HookAddress);
		SIZE_T vpSize = MemorySize;
		ULONG_PTR uJMP_CODE_SIZE = JMP_OPCODE_SIZE_LONG;

		DWORD old;
		if (!VirtualProtect(vpAddress, vpSize, PAGE_EXECUTE_READWRITE, &old)) {
			return;
		}
		memcpy_s((void *)((ULONG_PTR)Memory), sizeof(bPushRegisters), bPushRegisters, sizeof(bPushRegisters));
		memcpy_s((void *)((ULONG_PTR)Memory + sizeof(bPushRegisters)), sizeof(bCallHookFunction), bCallHookFunction, sizeof(bCallHookFunction));
		memcpy_s((void *)((ULONG_PTR)Memory + sizeof(bPushRegisters) + sizeof(bCallHookFunction)), sizeof(bPopRegisters), bPopRegisters, sizeof(bPopRegisters));
		memcpy_s((void *)((ULONG_PTR)Memory + sizeof(bPushRegisters) + sizeof(bCallHookFunction) + sizeof(bPopRegisters)), MemorySize, (void *)HookAddress, MemorySize);

		*(WORD *)((ULONG_PTR)Memory + sizeof(bPushRegisters) + sizeof(bCallHookFunction) + sizeof(bPopRegisters) + MemorySize) = 0x25FF;
		*(DWORD *)((ULONG_PTR)Memory + sizeof(bPushRegisters) + sizeof(bCallHookFunction) + sizeof(bPopRegisters) + MemorySize + 0x02) = 0;
		*(ULONG_PTR *)((ULONG_PTR)Memory + sizeof(bPushRegisters) + sizeof(bCallHookFunction) + sizeof(bPopRegisters) + MemorySize + 0x06) = HookAddress + MemorySize;

		*(WORD *)HookAddress = 0x25FF;
		*(DWORD *)(HookAddress + 0x02) = 0;
		*(ULONG_PTR *)(HookAddress + 0x06) = (ULONG_PTR)Memory;

		for (ULONG_PTR i = uJMP_CODE_SIZE; i < MemorySize; i++) {
			*(BYTE *)(HookAddress + i) = 0x90;
		}

		if (VirtualProtect(vpAddress, vpSize, old, &old)) {
			bHooked = true;
		}

		return;
	}
};


// for macro
namespace SimpleHook {
	std::vector<FunctionHook*> HookList;
	bool Hook(void *HookFunction, void *FunctionPointer, ULONG_PTR Address, ULONG_PTR OverWrite) {
		HookList.push_back(new FunctionHook(HookFunction, FunctionPointer, Address, OverWrite));
		return HookList.back()->IsHooked();
	}

	bool InlineHook(void *HookFunction, ULONG_PTR Address, DWORD dwStackValue) {
		HookList.push_back(new FunctionHook(HookFunction, Address, dwStackValue));
		return HookList.back()->IsHooked();
	}

	bool UnHook() {
		for (size_t i = 0; i < HookList.size(); i++) {
			delete HookList[i];
		}
		HookList.clear();
		return true;
	}
	
	bool Analyze(ULONG_PTR uAddress, std::vector<BYTE> &vCodeSize, ULONG_PTR uMinimumSize) {
		if (!FunctionHook::Decode(uAddress, vCodeSize, uMinimumSize)) {
			return false;
		}

		return true;
	}

	// test
	std::vector<MEMORY_BASIC_INFORMATION> section_list;

	bool InitSectionInformation() {
		DWORD pid = GetCurrentProcessId();

		if (!pid) {
			return false;
		}

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

		if (hSnapshot == INVALID_HANDLE_VALUE) {
			return false;
		}

		MODULEENTRY32W me;
		memset(&me, 0, sizeof(me));
		me.dwSize = sizeof(me);
		if (!Module32FirstW(hSnapshot, &me)) {
			return false;
		}

		std::vector<MODULEENTRY32W> module_list;
		do {
			module_list.push_back(me);
		} while (Module32NextW(hSnapshot, &me));

		CloseHandle(hSnapshot);

		// first module may be exe
		if (module_list.size() < 0) {
			return false;
		}

		MEMORY_BASIC_INFORMATION mbi;
		memset(&mbi, 0, sizeof(mbi));

		ULONG_PTR section_base = (ULONG_PTR)module_list[0].modBaseAddr;

		while (section_base < ((ULONG_PTR)module_list[0].modBaseAddr + module_list[0].modBaseSize) && (VirtualQuery((void *)section_base, &mbi, sizeof(mbi)) == sizeof(mbi))) {
			section_list.push_back(mbi);
			section_base += mbi.RegionSize;
		}

		if (!section_list.size()) {
			return false;
		}

		return true;
	}

	int IsCallerEXE(void *vReturnAddress) {
		// init
		if (section_list.size() == 0) {
			InitSectionInformation();
		}

		// check addresss
		for (size_t i = 0; i < section_list.size(); i++) {
			if ((ULONG_PTR)section_list[i].BaseAddress <= (ULONG_PTR)vReturnAddress && (ULONG_PTR)vReturnAddress <= ((ULONG_PTR)section_list[i].BaseAddress + section_list[i].RegionSize)) {
				return (int)i;
			}
		}

		return 0;
	}
}
#ifndef __ROSEMARY_H__
#define __ROSEMARY_H__

class Code {
private:
	bool init;
	std::vector<unsigned char> code;

	bool CreateCode(std::wstring wCode);

public:
	Code(std::wstring wCode);
	bool Write(ULONG_PTR uAddress);
};


class AobScan {
private:
	bool init;
	std::vector<unsigned char> array_of_bytes;
	std::vector<unsigned char> mask;

	bool CreateAob(std::wstring wAob);

public:
	AobScan(std::wstring wAob);
#ifndef _WIN64
	bool Compare(unsigned long int uAddress);
#else
	bool Compare(unsigned __int64 uAddress);
#endif
	size_t size();
};


class Rosemary {
private:
	bool init;
	std::vector<MEMORY_BASIC_INFORMATION> section_list;
	std::vector<MEMORY_BASIC_INFORMATION> data_section_list;
	bool GetSections(std::wstring wModuleName, bool bExe = false);

public:
	Rosemary();
	Rosemary(std::wstring wModuleName);
	~Rosemary();
	ULONG_PTR Scan(std::wstring wAob, int res = 0);
	ULONG_PTR Scan(std::wstring wAobList[], size_t size, size_t &index, bool(*Scanner)(ULONG_PTR) = NULL);
	ULONG_PTR Scan(std::wstring wAob, bool (*Scanner)(ULONG_PTR));
	bool Patch(std::wstring wAob, std::wstring wCode);
	bool Patch(ULONG_PTR uAddress, std::wstring wCode);
	bool Backup(std::vector<MEMORY_BASIC_INFORMATION> &vSection, std::vector<void*> &vBackup);
	bool JMP(ULONG_PTR uPrev, ULONG_PTR uNext, ULONG_PTR uNop = 0);
	bool Hook(ULONG_PTR uAddress, void *HookFunction, ULONG_PTR uNop = 0);
	bool GetSectionList(std::vector<MEMORY_BASIC_INFORMATION> &vSection);
	// test
	ULONG_PTR StringPatch(std::string search_string, std::string replace_string);
};

// require hook library
#define AOBHook(func) \
{\
	size_t index = -1;\
	ULONG_PTR scan_result = r.Scan(AOB_##func, _countof(AOB_##func), index);\
	DEBUG(L""#func" = " + QWORDtoString(scan_result) + L", Aob = " + std::to_wstring(index)); \
	if (-1 != index) {\
		SHookFunction(func, scan_result);\
	}\
}

#define AOBHookWithResult(func) \
{\
	size_t index = -1;\
	u##func = r.Scan(AOB_##func, _countof(AOB_##func), index);\
	DEBUG(L""#func" = " + QWORDtoString(u##func) + L", Aob = " + std::to_wstring(index)); \
	if (-1 != index) {\
		SHookFunction(func, u##func);\
	}\
}

#define AOBPatch(func, patch) \
{\
	size_t index = -1;\
	ULONG_PTR scan_result = r.Scan(AOB_##func, _countof(AOB_##func), index);\
	DEBUG(L""#func" = " + QWORDtoString(scan_result) + L", Aob = " + std::to_wstring(index)); \
	if(-1 != index) {\
		r.Patch(scan_result, patch);\
	}\
}

#define AOBPatch_ADD(func, add, patch) \
{\
	size_t index = -1;\
	ULONG_PTR scan_result = r.Scan(AOB_##func, _countof(AOB_##func), index);\
	DEBUG(L""#func" = " + QWORDtoString(scan_result) + L", Aob = " + std::to_wstring(index)); \
	if(-1 != index) {\
		r.Patch(scan_result + add, patch);\
	}\
}

#endif
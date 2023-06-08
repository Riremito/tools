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

#endif
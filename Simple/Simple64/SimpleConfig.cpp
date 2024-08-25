#include"Simple.h"

Config::Config(std::wstring wFileName) {
	SetConfigFile(wFileName, GetModuleHandleW(NULL));
}

Config::Config(std::wstring wFileName, HMODULE hDll) {
	SetConfigFile(wFileName, hDll);
}

bool Config::SetConfigFile(std::wstring wFileName, HMODULE hModule) {
	WCHAR wcDir[MAX_PATH] = { 0 };

	if (!GetModuleFileNameW(hModule, wcDir, _countof(wcDir))) {
		return false;
	}

	std::wstring dir = wcDir;
	size_t pos = dir.rfind(L"\\");

	if (pos == std::wstring::npos) {
		return false;
	}

	dir = dir.substr(0, pos + 1);

	config_file_name = dir + wFileName;
	return true;
}

bool Config::Read(std::wstring wSection, std::wstring wKey, std::wstring &wValue) {
	WCHAR wcValue[MAX_PATH * 2];
	memset(wcValue, 0, sizeof(wcValue));

	if (GetPrivateProfileStringW(wSection.c_str(), wKey.c_str(), NULL, wcValue, _countof(wcValue), config_file_name.c_str()) <= 0) {
		Update(wSection.c_str(), wKey.c_str(), L"");
		return false;
	}

	wValue = wcValue;
	return true;
}

bool Config::Update(std::wstring wSection, std::wstring wKey, std::wstring wValue) {
	if (!WritePrivateProfileStringW(wSection.c_str(), wKey.c_str(), wValue.c_str(), config_file_name.c_str())) {
		return false;
	}

	return true;
}

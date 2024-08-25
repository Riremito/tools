#ifndef __SIMPLECONFIG_H__
#define __SIMPLECONFIG_H__

class Config {
private:
	std::wstring config_file_name;
	bool SetConfigFile(std::wstring wFileName, HMODULE hModule);
public:
	// EXEのディレクトリを参照
	Config(std::wstring wFileName);
	// DLLのディレクトリを参照
	Config(std::wstring wFileName, HMODULE hDll);
	// 設定の読み取り
	bool Read(std::wstring wSection, std::wstring wKey, std::wstring &wValue);
	// 設定の更新
	bool Update(std::wstring wSection, std::wstring wKey, std::wstring wValue);
};

#endif
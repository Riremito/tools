#include"Simple.h"

PipeClient::PipeClient(std::wstring wPipeName) {
	pipe_name = L"\\\\.\\pipe\\" + wPipeName;
	client_pipe = INVALID_HANDLE_VALUE;
}

PipeClient::~PipeClient() {
	if (client_pipe != INVALID_HANDLE_VALUE) {
		CloseHandle(client_pipe);
	}
}

bool PipeClient::Run() {
	client_pipe = CreateFileW(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (client_pipe == INVALID_HANDLE_VALUE) {
		return false;
	}

	return true;
}

bool PipeClient::Send(BYTE *bData, ULONG_PTR uLength) {
	if (client_pipe == INVALID_HANDLE_VALUE) {
		return false;
	}

	union {
		BYTE *b;
		PipeMessage *pm;
	};

	ULONG_PTR pm_length = sizeof(PipeMessage) - 1 + uLength;

	b = new BYTE[pm_length];

	if (!b) {
		return false;
	}

	pm->magic = PIPE_MESSAGE_MAGIC;
	pm->length = (DWORD)uLength;
	memcpy_s(pm->data, uLength, bData, uLength);

	DWORD wb = 0;
	BOOL ret = WriteFile(client_pipe, pm, (DWORD)pm_length, &wb, NULL);
	FlushFileBuffers(client_pipe);

	delete[] b;
	return ret;
}

bool PipeClient::Recv(std::vector<BYTE> &vData) {
	if (client_pipe == INVALID_HANDLE_VALUE) {
		return false;
	}

	PipeMessage header;
	memset(&header, 0, sizeof(header));
	DWORD pm_length = sizeof(PipeMessage) - 1;

	DWORD rb = 0;
	if (!ReadFile(client_pipe, &header, pm_length, &rb, NULL)) {
		return false;
	}
	FlushFileBuffers(client_pipe);

	if (header.magic != PIPE_MESSAGE_MAGIC) {
		return false;
	}

	vData.resize(header.length);
	if (!ReadFile(client_pipe, &vData[0], (DWORD)header.length, &rb, NULL)) {
		return false;
	}
	FlushFileBuffers(client_pipe);

	return true;
}

bool PipeClient::Send(std::wstring wText) {
	return Send((BYTE *)wText.c_str(), (wText.length() + 1) * sizeof(wchar_t));
}

bool PipeClient::Recv(std::wstring &wText) {
	std::vector<BYTE> data;
	if (!Recv(data)) {
		return false;
	}

	wText = (wchar_t *)&data[0];

	return true;
}
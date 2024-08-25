#include"Simple.h"

PipeServerThread::PipeServerThread(HANDLE hPipe, bool(*function)(PipeServerThread&)) {
	server_pipe = hPipe;
	communicate = function;
}

PipeServerThread::~PipeServerThread() {
	if (server_pipe != INVALID_HANDLE_VALUE) {
		DisconnectNamedPipe(server_pipe);
		CloseHandle(server_pipe);
	}
}

bool PipeServerThread::Run() {
	if (communicate) {
		communicate(*this);
	}
	return true;
}

bool PipeServerThread::Send(BYTE *bData, ULONG_PTR uLength) {
	if (server_pipe == INVALID_HANDLE_VALUE) {
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
	BOOL ret = WriteFile(server_pipe, pm, (DWORD)pm_length, &wb, NULL);
	FlushFileBuffers(server_pipe);
	delete[] b;
	return ret;
}

bool PipeServerThread::Recv(std::vector<BYTE> &vData) {
	if (server_pipe == INVALID_HANDLE_VALUE) {
		return false;
	}

	PipeMessage header;
	memset(&header, 0, sizeof(header));
	DWORD pm_length = sizeof(PipeMessage) - 1;

	DWORD rb = 0;
	if (!ReadFile(server_pipe, &header, pm_length, &rb, NULL)) {
		return false;
	}
	FlushFileBuffers(server_pipe);

	if (header.magic != PIPE_MESSAGE_MAGIC) {
		return false;
	}

	vData.resize(header.length);
	if (!ReadFile(server_pipe, &vData[0], (DWORD)header.length, &rb, NULL)) {
		return false;
	}
	FlushFileBuffers(server_pipe);
	return true;
}

bool PipeServerThread::Send(std::wstring wText) {
	return Send((BYTE *)wText.c_str(), (wText.length() + 1) * sizeof(wchar_t));
}

bool PipeServerThread::Recv(std::wstring &wText) {
	std::vector<BYTE> data;
	if (!Recv(data)) {
		return false;
	}

	wText = (wchar_t *)&data[0];

	return true;
}
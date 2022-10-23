#include"Simple.h"

bool(*PipeServer::communicate)(PipeServerThread&) = NULL;

PipeServer::PipeServer(std::wstring wPipeName) {
	pipe_name = L"\\\\.\\pipe\\" + wPipeName;
}

PipeServer::~PipeServer() {

}

bool PipeServer::Run() {
	HANDLE server_pipe = CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 1, 0, 0, NULL);

	if (server_pipe == INVALID_HANDLE_VALUE) {
		return false;
	}

	if (!ConnectNamedPipe(server_pipe, NULL)) {
		return false;
	}

	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Communicate, (void *)server_pipe, NULL, NULL);
	if (!hThread) {
		return false;
	}

	CloseHandle(hThread);
	return Run();
}

bool PipeServer::SetCommunicate(bool (*function)(PipeServerThread&)) {
	communicate = function;
	return true;
}

bool PipeServer::Communicate(HANDLE server_pipe) {
	PipeServerThread psh(server_pipe, communicate);
	psh.Run();
	return true;
}
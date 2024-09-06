#ifndef __SIMPLEPIPE_H__
#define __SIMPLEPIPE_H__

#define PIPE_MESSAGE_MAGIC 0xA11CE

#pragma pack(push, 1)
typedef struct {
	DWORD magic;
	DWORD length;
	BYTE data[1];
} PipeMessage;
#pragma pack(pop)


class PipeServerThread {
private:
	HANDLE server_pipe;
	bool (*communicate)(PipeServerThread&);

public:
	PipeServerThread(HANDLE hPipe, bool (*function)(PipeServerThread&));
	~PipeServerThread();

	bool Run();
	bool Send(BYTE *bData, ULONG_PTR uLength);
	bool Recv(std::vector<BYTE> &vData);
	bool Send(std::wstring wText);
	bool Recv(std::wstring &wText);
};

class PipeServer {
private:
	std::wstring pipe_name;
	static bool (*communicate)(PipeServerThread&);

	static bool Communicate(HANDLE server_pipe);

public:
	PipeServer(std::wstring wPipeName);
	~PipeServer();

	bool SetCommunicate(bool (*function)(PipeServerThread&));
	bool Run();
};

class PipeClient {
private:
	std::wstring pipe_name;
	HANDLE client_pipe;

public:
	PipeClient(std::wstring wPipeName);
	~PipeClient();

	bool Run();
	bool Send(BYTE *bData, ULONG_PTR uLength);
	bool Recv(std::vector<BYTE> &vData);
	bool Send(std::wstring wText);
	bool Recv(std::wstring &wText);
};
#endif
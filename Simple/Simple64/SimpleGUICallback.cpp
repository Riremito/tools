#include"Simple.h"

// public
bool Alice::SetOnCreate(bool (*function)(Alice&)) {
	on_create = function;
	return true;
}

bool Alice::SetOnCommand(bool (*function)(Alice&, int)) {
	on_command = function;
	return true;
}

bool Alice::SetOnNotify(bool (*function)(Alice&, int)) {
	on_notify = function;
	return true;
}

bool Alice::SetCallback(decltype(DefWindowProcW) *function , CallbackType ct) {
	manual_callback = function;
	callback_type = ct;
	return true;
}


Alice::CallbackType Alice::GetCallbackType() {
	return callback_type;
}

LRESULT CALLBACK Alice::Callback(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
	if (!manual_callback) {
		return 0;
	}

	return manual_callback(hWnd, Msg, wParam, lParam);
}

// private
bool Alice::OnCreate(Alice &a) {
	if (!on_create) {
		return false;
	}

	return on_create(a);
}

bool Alice::OnCommand(Alice &a, int nIDDlgItem) {
	if (!on_command) {
		return false;
	}

	return on_command(a, nIDDlgItem);
}

bool Alice::OnNotify(Alice &a, int nIDDlgItem) {
	if (!on_notify) {
		return false;
	}

	return on_notify(a, nIDDlgItem);
}


HWND Alice::GetMainHWND() {
	return main_hwnd;
}
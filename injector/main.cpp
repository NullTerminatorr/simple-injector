#include "injector.h"

int main() {
	inject(L"notepad.exe", L"payload.dll");
	return getchar();
}

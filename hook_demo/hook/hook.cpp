#include <windows.h>

#include "../hookdll/hookdll.h"

int main() {
	hookdll_install();
	Sleep(5000);
	hookdll_uninstall();
}

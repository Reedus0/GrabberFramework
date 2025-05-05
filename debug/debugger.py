import typing
import py3dbg


class Debugger():

    __dbg: py3dbg.pydbg
    __callbacks: dict[tuple[str, str], typing.Callable]

    def __loadDllBreak(self, _: py3dbg.pydbg) -> int:
        for library, function in self.__callbacks:
            address = self.__dbg.func_resolve_debuggee(library.encode(), function.encode())
            if (address):
                self.__dbg.bp_set(address, handler=self.__callbacks[(library, function)])

        return py3dbg.defines.DBG_EXCEPTION_HANDLED

    def __init__(self, path: str) -> None:
        self.__callbacks = dict()
        self.__dbg = py3dbg.pydbg()

        self.__dbg.set_callback(
            py3dbg.defines.LOAD_DLL_DEBUG_EVENT, self.__loadDllBreak)

        self.__dbg.load(path.encode(), show_window=False)

    def addBreakpoint(self, library: str, function: str, callback: typing.Callable) -> None:
        self.__callbacks[(library, function)] = callback

    def run(self) -> None:
        while (self.__dbg.debugger_active):
            self.__dbg.debug_event_iteration()

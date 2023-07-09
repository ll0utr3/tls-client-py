from sys import platform
from platform import machine
import ctypes
import os

m = machine()

if platform == 'darwin':
    file_ext = '-arm64.dylib' if m == "arm64" else '-x86.dylib'
elif platform in ('win32', 'cygwin'):
    file_ext = '-64.dll' if 8 == ctypes.sizeof(ctypes.c_voidp) else '-32.dll'
else:
    if m == "aarch64":
        file_ext = '-arm64.so'
    elif m == "x86_64":
        file_ext = '-amd64.so'
    else:
        file_ext = '-x86.so'

root_dir = os.path.abspath(os.path.dirname(__file__))
library = ctypes.cdll.LoadLibrary(f'{root_dir}/dependencies/tls-client{file_ext}')

# extract the exposed request function from the shared package
request = library.request
request.argtypes = [ctypes.c_char_p]
request.restype = ctypes.c_char_p

freeMemory = library.freeMemory
freeMemory.argtypes = [ctypes.c_char_p]
freeMemory.restype = ctypes.c_char_p

destroySession = library.destroySession
destroySession.argtypes = [ctypes.c_char_p]
destroySession.restype = ctypes.c_char_p

destroyAll = library.destroyAll
destroyAll.argtypes = []
destroyAll.restype = ctypes.c_char_p

addCookiesToSession = library.addCookiesToSession
addCookiesToSession.argtypes = [ctypes.c_char_p]
addCookiesToSession.restype = ctypes.c_char_p
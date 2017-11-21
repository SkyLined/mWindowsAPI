import platform;

def fsGetPythonISA():
  return {
    "32bit": "x86",
    "64bit": "x64",
  }[platform.architecture()[0]];

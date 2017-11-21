import platform;

gsPythonISA = None;
def fsGetPythonISA():
  global gsPythonISA;
  if gsPythonISA is None:
    gsPythonISA = {
      "32bit": "x86",
      "64bit": "x64",
    }[platform.architecture()[0]];
  return gsPythonISA;
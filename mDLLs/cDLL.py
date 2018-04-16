import ctypes, threading;

class cDLL(object):
  def __init__(oSelf, sDLLFilePath):
    oSelf.__sDLLFilePath = sDLLFilePath;
    oSelf.__oWinDLL = None;
  
  def fLoad(oSelf):
    if oSelf.__oWinDLL is None:
      oSelf.__oWinDLL = ctypes.WinDLL(oSelf.__sDLLFilePath);
  
  def fDefineFunction(oSelf, xReturnType, sFunctionName, *axArgumenTypes, **dxOptions):
    def fxInitialFunctionWrapper(*axArguments, **dxArguments):
      # This code is used as a wrapper for functions in this DLL until they are first called. At that point, this code
      # makes sure the DLL gets loaded and replaces itself as the wrapper with a simpler wrapper that does not make
      # sure the DLL is loaded but simply calls the function. This simpler wrapper is also used to make the actual
      # first call to the function.
      # This complexity is needed so we can have cDLL instances without having to load the DLLs in the Python process.
      # We want this so we can offer functionality in many different DLLs without having to load them if the user does
      # not use them. This way, DLLs are loaded transparently the first time a function needs to be called in them, and
      # subsequent calls do not check if the DLL needs to be loaded any more, making those faster
      oSelf.fLoad();
      ffxFunctionConstructor = ctypes.WINFUNCTYPE(xReturnType, *axArgumenTypes);
      fxBasicFunctionWrapper = ffxFunctionConstructor(
        (sFunctionName, oSelf.__oWinDLL),
        tuple([(1, "p%d" % u, 0) for u in xrange(len(axArgumenTypes))])
      );
      if "bSingleThreaded" in dxOptions:
        # This function cannot be called concurrently from multiple threads: wrap it in a function that holds a lock
        # while a call is in progress. This allows only a single thread to call it at the same time.
        oCallLock = threading.Lock();
        def fxSingleThreadedFunctionWrapper(*axArguments, **dxArguments):
          oCallLock.acquire();
          try:
            return fxBasicFunctionWrapper(*axArguments, **dxArguments);
          finally:
            oCallLock.release();
        fxFunctionWrapper = fxSingleThreadedFunctionWrapper;
      else:
        fxFunctionWrapper = fxBasicFunctionWrapper;
      setattr(oSelf, sFunctionName, fxFunctionWrapper);
      return fxFunctionWrapper(*axArguments, **dxArguments);
    setattr(oSelf, sFunctionName, fxInitialFunctionWrapper);
    

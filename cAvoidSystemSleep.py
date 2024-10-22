from mWindowsSDK.mKernel32 import oKernel32DLL;
from mWindowsSDK import (
  POWER_REQUEST_CONTEXT_SIMPLE_STRING,
  POWER_REQUEST_CONTEXT_VERSION,
  PowerRequestDisplayRequired,
  PowerRequestSystemRequired,
  LPWSTR,
  REASON_CONTEXT
);

from .fbIsValidHandle import fbIsValidHandle;
from .fsHexNumber import fsHexNumber;
from .fThrowLastError import fThrowLastError;

class cAvoidSystemSleep(object):
  def __init__(oSelf, sReason, bKeepDisplayOn = False):
    oSelf.__sReason = sReason;
    oSelf.__bKeepDisplayOn = bKeepDisplayOn;
    oSelf.__bEnabled = False;
  
  def fEnable(oSelf):
    assert not oSelf.__bEnabled, \
        "Already enabled";
    opReason = LPWSTR(oSelf.__sReason);
    oReasonContext = REASON_CONTEXT(
      Version = POWER_REQUEST_CONTEXT_VERSION,
      Flags = POWER_REQUEST_CONTEXT_SIMPLE_STRING,
      SimpleReasonString = opReason,
    );
    poReasonContext = oReasonContext.foCreatePointer();
    oSelf.__hPowerRequest = oKernel32DLL.PowerCreateRequest(
      poReasonContext,
    );
    if not fbIsValidHandle(oSelf.__hPowerRequest):
      fThrowLastError("kernel32.PowerCreateRequest(%s) == %s" % ( \
        repr(poReasonContext),
        fsHexNumber(oSelf.__hPowerRequest.fuGetValue()),
      ));
    if not oKernel32DLL.PowerSetRequest(
      oSelf.__hPowerRequest,
      PowerRequestSystemRequired,
    ):
      fThrowLastError("kernel32.PowerSetRequest(%s, %s (PowerRequestSystemRequired)) == FALSE" %
        fsHexNumber(oSelf.__hPowerRequest.fuGetValue()),
        fsHexNumber(PowerRequestDisplayRequired),
      );
    if oSelf.__bKeepDisplayOn and not oKernel32DLL.PowerSetRequest(
      oSelf.__hPowerRequest,
      PowerRequestDisplayRequired,
    ):
      fThrowLastError("kernel32.PowerSetRequest(%s, %s (PowerRequestDisplayRequired)) == FALSE" %\
        fsHexNumber(oSelf.__hPowerRequest.fuGetValue()),
        fsHexNumber(PowerRequestDisplayRequired),
      );
    oSelf.__bEnabled = True;
  
  def fDisable(oSelf):
    assert oSelf.__bEnabled, \
        "Not enabled";
    bExceptionThrown = False;
    try:
      try:
        if not oKernel32DLL.PowerClearRequest(
          oSelf.__hPowerRequest,
          PowerRequestSystemRequired,
        ):
          bExceptionThrown = True;
          fThrowLastError("kernel32.PowerClearRequest(%s, %s (PowerRequestSystemRequired)) == FALSE" %
            fsHexNumber(oSelf.__hPowerRequest.fuGetValue()),
            fsHexNumber(PowerRequestSystemRequired),
          );
      finally:
        if oSelf.__bKeepDisplayOn and not oKernel32DLL.PowerClearRequest(
          oSelf.__hPowerRequest,
          PowerRequestDisplayRequired,
        ) and not bExceptionThrown:
          bExceptionThrown = True;
          fThrowLastError("kernel32.PowerClearRequest(%s, s (PowerRequestSystemRequired)) == FALSE" %
            fsHexNumber(oSelf.__hPowerRequest.fuGetValue()),
            fsHexNumber(PowerRequestSystemRequired),
          );
    finally:
      if not oKernel32DLL.CloseHandle(oSelf.__hPowerRequest) and not bExceptionThrown:
        fThrowLastError("kernel32.CloseHandle(%s) == FALSE" %
          fsHexNumber(oSelf.__hPowerRequest.fuGetValue())
        );
    del oSelf.__hPowerRequest;
    oSelf.__bEnabled = False;
  
  def __del__(oSelf):
    assert not oSelf.__bEnabled, \
        "A cAvoidSystemSleep instance (sReason=%s) was enabled but not disabled!" % repr(oSelf.__sReason);
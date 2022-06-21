from mWindowsSDK.mKernel32 import oKernel32DLL;
from mWindowsSDK import \
  POWER_REQUEST_CONTEXT_SIMPLE_STRING, \
  POWER_REQUEST_CONTEXT_VERSION, \
  PowerRequestDisplayRequired, \
  PowerRequestSystemRequired, \
  PWSTR, \
  REASON_CONTEXT;

from .fbIsValidHandle import fbIsValidHandle;
from .fThrowLastError import fThrowLastError;

class cAvoidSystemSleep(object):
  def __init__(oSelf, sReason, bKeepDisplayOn = False):
    oSelf.__bKeepDisplayOn = bKeepDisplayOn;
    oReasonContext = REASON_CONTEXT(
      Version = POWER_REQUEST_CONTEXT_VERSION,
      Flags = POWER_REQUEST_CONTEXT_SIMPLE_STRING,
      SimpleReasonString = PWSTR(sReason)
    );
    poReasonContext = oReasonContext.foCreatePointer();
    oSelf.__hPowerRequest = oKernel32DLL.PowerCreateRequest(
      poReasonContext,
    );
    if not fbIsValidHandle(oSelf.__hPowerRequest):
      fThrowLastError("PowerCreateRequest(%s) == 0x%X" % (repr(poReasonContext), oSelf.__hPowerRequest));
    oSelf.__bEnabled = False;
  def fEnable(oSelf):
    assert not oSelf.__bEnabled, \
        "Already enabled";
    if not oKernel32DLL.PowerSetRequest(
      oSelf.__hPowerRequest,
      PowerRequestSystemRequired,
    ):
      fThrowLastError("PowerSetRequest(%s, PowerRequestSystemRequired) == FALSE" % repr(oSelf.__hPowerRequest));
    if oSelf.__bKeepDisplayOn and not oKernel32DLL.PowerSetRequest(
      oSelf.__hPowerRequest,
      PowerRequestDisplayRequired,
    ):
      fThrowLastError("PowerSetRequest(%s, PowerRequestDisplayRequired) == FALSE" % repr(oSelf.__hPowerRequest));
    oSelf.__bEnabled = True;
  
  def fDisable(oSelf):
    assert oSelf.__bEnabled, \
        "Not enabled";
    if not oKernel32DLL.PowerClearRequest(
      oSelf.__hPowerRequest,
      PowerRequestSystemRequired,
    ):
      fThrowLastError("PowerClearRequest(%s, PowerRequestSystemRequired) == FALSE" % repr(oSelf.__hPowerRequest));
    if oSelf.__bKeepDisplayOn and not oKernel32DLL.PowerClearRequest(
      oSelf.__hPowerRequest,
      PowerRequestDisplayRequired,
    ):
      fThrowLastError("PowerClearRequest(%s, PowerRequestDisplayRequired) == FALSE" % repr(oSelf.__hPowerRequest));
    oSelf.__bEnabled = False;

from .fdsProcessesExecutableName_by_uId import fdsProcessesExecutableName_by_uId;

def fauProcessesIdsForExecutableName(sExecutableName):
  sLoweredExecutableName = sExecutableName.lower();
  return [
    uId
    for (uId, sProcessExecutableName) in fdsProcessesExecutableName_by_uId().items()
    if sProcessExecutableName.lower() == sLoweredExecutableName
  ];

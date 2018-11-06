
def fbErrorIs(hResult, *tuAcceptableHResults):
  # Check if the hResult is in a list of acceptable errors
  return hResult.value in tuAcceptableHResults;

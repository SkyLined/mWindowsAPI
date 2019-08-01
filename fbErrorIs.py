
def fbErrorIs(ohResult, *tuAcceptableHResults):
  # Check if the hResult is in a list of acceptable errors
  return ohResult.value in tuAcceptableHResults;

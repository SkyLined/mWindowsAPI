def fsHexNumber(iNumber, u0BitsPerBlock = 16):
  # Show a number as either "0"-"9" or "0x##`####"
  # Hex digits are grouped in multiples of u0BitsPerBlock
  # bits (e.g. 8 == 0x#`##`##, 16 = 0x###`####, 32 = 0x###`########)
  # if u0BitsPerBlock is None, no grouping is done (e.g. 0x#############)
  sSign = "-" if iNumber < 0 else "";
  uNumber = abs(iNumber);
  if uNumber < 10:
    return "%s%d" % (sSign, uNumber);
  if u0BitsPerBlock is None:
    return "%s0x%X" % (sSign, uNumber);
  asNumber = [];
  uMaxValueInBlock = (1 << u0BitsPerBlock) - 1;
  while uNumber > uMaxValueInBlock:
    asNumber.insert(0, "%04X" % (uNumber & 0xFFFF));
    uNumber >>= u0BitsPerBlock;
  asNumber.insert(0, "%X" % uNumber);
  return "0x%s" % "`".join(asNumber);

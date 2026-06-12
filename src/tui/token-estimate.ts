export function estimateOutputTokensFromChars(chars: number) {
  if (!Number.isFinite(chars) || chars <= 0) return 0;
  return Math.ceil(chars / 4);
}

export function formatApproxOutputTokens(tokens: number) {
  const rounded = Math.ceil(tokens);
  if (!Number.isFinite(rounded) || rounded <= 0) return null;
  if (rounded < 1000) return `~ ${rounded} tok`;
  return `~ ${(rounded / 1000).toFixed(1)}k tok`;
}

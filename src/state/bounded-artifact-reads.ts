/** Bound both live CAS reads and pending promises in one recovery walk. */
export const RECOVERY_ARTIFACT_READ_CONCURRENCY = 8;

export async function mapArtifactReads<T, U>(
  values: readonly T[],
  visit: (value: T, index: number) => Promise<U>
): Promise<U[]> {
  const results = new Array<U>(values.length);
  let nextIndex = 0;
  let failure: { error: unknown } | undefined;
  const worker = async () => {
    while (failure === undefined) {
      const index = nextIndex++;
      if (index >= values.length) return;
      try {
        results[index] = await visit(values[index]!, index);
      } catch (error) {
        failure ??= { error };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(RECOVERY_ARTIFACT_READ_CONCURRENCY, values.length) }, worker));
  if (failure !== undefined) throw failure.error;
  return results;
}

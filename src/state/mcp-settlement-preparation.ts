/** Cache one complete local settlement plan. A rejected publication may be
 * tried again only by an explicit caller after its original task has settled.
 * The closure must retain its original native owner/claim and join every
 * issued read/write before rejecting. Never wrap dispatch or OS creation. */
export function retainMcpSettlementPreparation<T>(prepare: () => Promise<T>): () => Promise<T> {
  let retained: Promise<T> | undefined;
  return () => {
    if (!retained) {
      const task = Promise.resolve().then(prepare);
      const publication: Promise<T> = task.catch(error => {
        if (retained === publication) retained = undefined;
        throw error;
      });
      retained = publication;
    }
    return retained;
  };
}
/** Preserve the successful native release phase if a later original input
 * close rejects. The owning domain authenticates its actual native terminal
 * before invoking this fixed receiver; callbacks supply no authority. */
export function retainMcpTerminalAcknowledgement(releaseDomain: () => void, closeInput: () => void): () => void {
  let released = false, closed = false;
  return () => {
    if (!released) { releaseDomain(); released = true; }
    if (!closed) { closeInput(); closed = true; }
  };
}

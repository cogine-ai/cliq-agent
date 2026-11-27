export class ClientBusyError extends Error {
  constructor() { super('another explicit client command is still pending'); this.name = 'ClientBusyError'; }
}
export class ClientDisconnectedError extends Error {
  constructor() { super('the client is disconnected; reconnect explicitly without resending a request'); this.name = 'ClientDisconnectedError'; }
}
export class ClientPendingRequestError extends Error {
  constructor() { super('inspect or explicitly replay the original unresolved request before sending a different mutation'); this.name = 'ClientPendingRequestError'; }
}

/** Local durable-data failure, not a failed or unauthenticated peer. An
 * uncertain physical resource close retains ResourceRetirementError instead. */
export class ClientRequestPersistenceError extends Error {
  constructor(cause: unknown) { super('original request data could not be safely persisted; inspect retained requests before another mutation', { cause }); this.name = 'ClientRequestPersistenceError'; }
}

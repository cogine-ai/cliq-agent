// Qualification diagnostics only: no error text, arbitrary paths, command
// arguments, provider data or credentials can enter this closed projection.
import { types } from 'node:util';
import { writeSync } from 'node:fs';

const SOURCES = ['installed-supervisor-package.ts','supervisor-sea-builder.ts','installed-upgrade-tls.ts'] as const;
const CODES = ['', 'ENOENT', 'EACCES', 'ENOSPC', 'EIO', 'ECONNRESET', 'ECONNREFUSED', 'ENETUNREACH',
  'ENOTFOUND', 'ETIMEDOUT', 'EAI_AGAIN', 'EHOSTUNREACH', 'ERR_ASSERTION', 'ERR_INVALID_ARG_TYPE',
  'ERR_TLS_CERT_ALTNAME_INVALID', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN', 'CERT_HAS_EXPIRED',
  'UND_ERR_CONNECT_TIMEOUT','UND_ERR_HEADERS_TIMEOUT','UND_ERR_BODY_TIMEOUT','UND_ERR_SOCKET','UND_ERR_RESPONSE_STATUS_CODE',
  'EPROTO','ECONNABORTED','EROFS','EMFILE','ENFILE','ERR_INVALID_URL'] as const;
type Failure = Readonly<{type:number;code:number;frames:readonly Readonly<{source:number;line:number;column:number}>[];httpStatus?:number}>;
const nativeDomName = Object.getOwnPropertyDescriptor(DOMException.prototype,'name')?.get;
const errorKinds = new Map<object,number>([[AggregateError.prototype,5],[TypeError.prototype,2],
  [SyntaxError.prototype,3],[RangeError.prototype,4],[Error.prototype,1]]);

function nativeErrorType(value: object): number {
  if (!types.isNativeError(value)) return 0;
  let prototype: object | null = Object.getPrototypeOf(value);
  for (let depth=0;prototype !== null && depth<8;depth++) {
    // A non-Proxy exception may still inherit from a Proxy. Never ask that
    // prototype for its parent or any properties, even to classify a failure.
    if (types.isProxy(prototype)) break;
    const kind = errorKinds.get(prototype);
    if (kind !== undefined) return kind;
    prototype = Object.getPrototypeOf(prototype);
  }
  return 1;
}

function own(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value,key);
  return descriptor && Object.hasOwn(descriptor,'value') ? descriptor.value : undefined;
}

export function qualificationFailureDiagnostic(stage: 'package' | 'tls', error: unknown, phase=0) {
  if (stage !== 'package' && stage !== 'tls') throw new TypeError('unknown fixed qualification diagnostic stage');
  if (!Number.isSafeInteger(phase) || phase<0 || phase>8) throw new TypeError('unknown fixed qualification diagnostic phase');
  const pending = [error], visited = new Set<unknown>(), failures: Failure[] = [];
  while (pending.length && failures.length < 8) {
    const value = pending.shift();
    if (visited.has(value)) continue;
    visited.add(value);
    if (!value || typeof value !== 'object' || types.isProxy(value)) {
      failures.push(Object.freeze({type:0,code:0,frames:Object.freeze([])})); continue;
    }
    let domType: number | undefined;
    if (nativeDomName) {
      try {
        const name=Reflect.apply(nativeDomName,value,[]);
        if (name==='TimeoutError') domType=6;
        else if (name==='AbortError') domType=7;
      } catch { /* A non-DOM error has no trusted DOM name. */ }
    }
    const type = domType ?? nativeErrorType(value);
    const rawCode = own(value,'code');
    const code = typeof rawCode === 'string' ? Math.max(0,CODES.indexOf(rawCode as typeof CODES[number])) : 0;
    // V8's stack accessor may itself invoke caller name/message/format hooks.
    // Only already-materialized data is read. Real preparation failures also
    // carry the separately recorded fixed phase from their owning producer.
    const stack = own(value,'stack'), frames: Array<{source:number;line:number;column:number}> = [];
    if (typeof stack === 'string' && stack.length <= 65536) {
      const pattern = /(?:^|[/\\])(installed-supervisor-package|supervisor-sea-builder|installed-upgrade-tls)\.ts:([1-9][0-9]{0,6}):([1-9][0-9]{0,6})(?![0-9])/gu;
      for (const match of stack.matchAll(pattern)) {
        frames.push(Object.freeze({source:SOURCES.indexOf(`${match[1]}.ts` as typeof SOURCES[number])+1,
          line:Number(match[2]),column:Number(match[3])}));
        if (frames.length === 8) break;
      }
    }
    const message = own(value,'message');
    // This is the exact owned carrier-download assertion, never a free-form
    // message field. The status remains diagnostic and cannot authorize retry.
    const status = stage==='package' && phase===2 && code === 12 && typeof message === 'string'
      ? /^carrier download failed: ([1-5][0-9]{2})$/u.exec(message) : null;
    failures.push(Object.freeze({type,code,frames:Object.freeze(frames),...(status ? {httpStatus:Number(status[1])} : {})}));
    const cause = own(value,'cause');
    if (cause !== undefined) pending.push(cause);
    if (code === 12) {
      const actual = own(value,'actual');
      if (actual && typeof actual === 'object' && !types.isProxy(actual) && types.isNativeError(actual)) pending.push(actual);
    }
    if (type === 5) {
      const errors = own(value,'errors');
      if (Array.isArray(errors) && !types.isProxy(errors)) {
        for (let index=0;index<Math.min(errors.length,4);index++) pending.push(own(errors,String(index)));
      }
    }
  }
  return Object.freeze({version:1,stage:stage === 'package' ? 1 : 2,phase,failures:Object.freeze(failures)});
}

/** An observation failure must never replace the original qualification error
 * or prevent resource cleanup and actual process joins. */
export function emitQualificationFailure(stage: 'package' | 'tls', error: unknown, phase=0): void {
  try { writeSync(2,'CLIQ_QUALIFICATION_FAILURE_V1:' + JSON.stringify(qualificationFailureDiagnostic(stage,error,phase)) + '\n'); }
  catch { /* Diagnostic output grants no authority and cannot change failure. */ }
}

import { MODEL_TIMEOUT_MS } from '../config.js';

export function joinUrl(baseUrl: string, pathname: string) {
  return `${baseUrl.replace(/\/+$/, '')}/${pathname.replace(/^\/+/, '')}`;
}

function timeoutSignal(externalSignal: AbortSignal | null | undefined, timeoutMs: number) {
  const controller = new AbortController();
  let timedOut = false;

  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  const abortFromExternalSignal = () => {
    controller.abort(externalSignal?.reason);
  };

  if (externalSignal?.aborted) {
    abortFromExternalSignal();
  } else {
    externalSignal?.addEventListener('abort', abortFromExternalSignal, { once: true });
  }

  return {
    signal: controller.signal,
    didTimeout: () => timedOut,
    cleanup() {
      clearTimeout(timeout);
      externalSignal?.removeEventListener('abort', abortFromExternalSignal);
    }
  };
}

export async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs = MODEL_TIMEOUT_MS) {
  const signal = timeoutSignal(init.signal, timeoutMs);
  try {
    return await fetch(url, { ...init, signal: signal.signal });
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error(signal.didTimeout() ? `Model request timed out after ${timeoutMs}ms` : 'Model request cancelled');
    }

    throw error;
  } finally {
    signal.cleanup();
  }
}

export async function readJsonResponse<T>(response: Response, providerName: string): Promise<T> {
  if (!response.ok) {
    throw new Error(`${providerName} error ${response.status}: ${await response.text()}`);
  }

  return (await response.json()) as T;
}

export async function readTextStream(response: Response, onChunk: (chunk: string) => void | Promise<void>) {
  if (!response.ok) {
    throw new Error(`Model stream error ${response.status}: ${await response.text()}`);
  }

  if (!response.body) {
    throw new Error('Model stream response is missing a body');
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let output = '';

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const text = decoder.decode(value, { stream: true });
    output += text;
    await onChunk(text);
  }

  const finalText = decoder.decode();
  output += finalText;
  if (finalText) {
    await onChunk(finalText);
  }

  return output;
}

function warnMalformedStreamPayload(format: string, payload: string, error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  console.warn(`Malformed model ${format} payload skipped: ${message}; payload=${payload}`);
}

export async function readSseDeltas(
  response: Response,
  extractDelta: (json: unknown) => string | null,
  onDelta: (text: string) => void | Promise<void>
) {
  let buffer = '';
  let content = '';

  async function processFrame(frame: string) {
    for (const line of frame.split('\n')) {
      const normalized = line.trimEnd();
      if (!normalized.startsWith('data:')) continue;
      const payload = normalized.slice('data:'.length).trim();
      if (!payload || payload === '[DONE]') continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(payload);
      } catch (error) {
        warnMalformedStreamPayload('SSE', payload, error);
        continue;
      }

      const delta = extractDelta(parsed);
      if (delta) {
        content += delta;
        await onDelta(delta);
      }
    }
  }

  await readTextStream(response, async (chunk) => {
    buffer += chunk;
    const frames = buffer.split(/\r?\n\r?\n/);
    buffer = frames.pop() ?? '';

    for (const frame of frames) {
      await processFrame(frame);
    }
  });

  if (buffer.trim()) {
    await processFrame(buffer);
  }

  return content;
}

export async function readNdjsonDeltas(
  response: Response,
  extractDelta: (json: unknown) => string | null,
  onDelta: (text: string) => void | Promise<void>
) {
  let buffer = '';
  let content = '';

  async function processLine(line: string) {
    const payload = line.trim();
    if (!payload) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(payload);
    } catch (error) {
      warnMalformedStreamPayload('NDJSON', payload, error);
      return;
    }

    const delta = extractDelta(parsed);
    if (delta) {
      content += delta;
      await onDelta(delta);
    }
  }

  await readTextStream(response, async (chunk) => {
    buffer += chunk;
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';

    for (const line of lines) {
      await processLine(line);
    }
  });

  if (buffer.trim()) {
    await processLine(buffer);
  }

  return content;
}

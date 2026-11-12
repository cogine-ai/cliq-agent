// Private installed ABI shapes. Native tags and the original held selection
// validate these receivers before any operation; these types confer no authority.
import type { LocalInferenceNativeInputData } from '../kernel/local-inference-native-input.js';
import type { NativeWorkerImage } from '../sandbox/linux-worker.js';

export type NativeLocalInferenceInput = Readonly<{ assertHeld(): void; originBytes(): Buffer; close(): void }>;
export type NativeLocalInferencePeer = Readonly<{ assertHeld(): void; close(): void }>;
export type NativeLocalInferenceController = Readonly<{
  pid: number; processStartToken: string; pollReady(): boolean;
  captureOrigin(config: Buffer): Buffer;
  reserveService(source: NativeLocalInferenceInput, bootstrap: NativeWorkerImage, bubblewrap: NativeWorkerImage): void;
  cleanupRetainedService(source: NativeLocalInferenceInput, supervisorPid: number, supervisorStart: string): void;
  beginPreparation(): void; beginPreparedObservation(): void; beginCreateBlocked(): void;
  beginReleaseEngine(): void; beginPublishActive(): void; beginActiveObservation(): void; beginStop(): void;
  retainHealthPeer(): NativeLocalInferencePeer; retainModelPeer(): NativeLocalInferencePeer;
  pollReply(): Buffer | null; retirementObservation(): Buffer | undefined; close(): Promise<void>;
}>;
export type NativeLocalInferenceWorkerBinding = Readonly<{
  localInferenceInterfaceVersion: 3;
  encodeLocalInferenceInput(data: LocalInferenceNativeInputData): Buffer;
  openLocalInferenceController(helper: NativeWorkerImage, anchorFd: number): NativeLocalInferenceController;
}>;

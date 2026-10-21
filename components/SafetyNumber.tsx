'use client';

import { useEffect, useState } from 'react';
import { apiDelete, apiPost } from '@/lib/client/api';
import {
  computeSafetyNumber,
  formatSafetyNumber,
  publicKeyFingerprint,
} from '@/lib/crypto/safetyNumber';
import { base64ToBytes } from '@/lib/encoding';
import { Alert, Button } from '@/components/ui';
import { AlertIcon, CheckIcon, LockIcon, ShieldIcon } from '@/components/icons';

type Participant = {
  id: string;
  username: string;
  publicKeyB64: string;
  fingerprint: string;
};

type Verification = {
  safety_number: string;
  verified_at: string;
} | null;

export function SafetyNumber({
  conversationId,
  self,
  peer,
  initialVerification,
}: {
  conversationId: string;
  self: Participant;
  peer: Participant;
  initialVerification: Verification;
}) {
  const [safetyNumber, setSafetyNumber] = useState<string | null>(null);
  const [fingerprints, setFingerprints] = useState<{
    self: string;
    peer: string;
  } | null>(null);
  const [computeError, setComputeError] = useState<string | null>(null);
  const [verifiedAt, setVerifiedAt] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    try {
      const selfKey = base64ToBytes(self.publicKeyB64);
      const peerKey = base64ToBytes(peer.publicKeyB64);
      const number = computeSafetyNumber(self.id, selfKey, peer.id, peerKey);
      setSafetyNumber(number);
      setFingerprints({
        self: publicKeyFingerprint(selfKey),
        peer: publicKeyFingerprint(peerKey),
      });
      setVerifiedAt(
        initialVerification?.safety_number === number
          ? initialVerification.verified_at
          : null,
      );
      setComputeError(null);
    } catch {
      setComputeError('Could not compute a safety number from the published keys.');
    }
  }, [
    self.id,
    self.publicKeyB64,
    peer.id,
    peer.publicKeyB64,
    initialVerification?.safety_number,
    initialVerification?.verified_at,
  ]);

  const directoryMismatch =
    fingerprints !== null &&
    (fingerprints.self !== self.fingerprint || fingerprints.peer !== peer.fingerprint);

  const verificationMismatch =
    initialVerification !== null &&
    safetyNumber !== null &&
    initialVerification.safety_number !== safetyNumber;

  const verified = verifiedAt !== null && !verificationMismatch && !directoryMismatch;

  const verify = async () => {
    if (!safetyNumber) return;
    setBusy(true);
    setActionError(null);
    try {
      const response = await apiPost<{ verification: { verified_at: string } }>(
        `/api/conversations/${encodeURIComponent(conversationId)}/verify`,
        { safety_number: safetyNumber },
      );
      setVerifiedAt(response.verification.verified_at);
      setCopied(false);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not save verification.');
    } finally {
      setBusy(false);
    }
  };

  const unverify = async () => {
    setBusy(true);
    setActionError(null);
    try {
      await apiDelete(
        `/api/conversations/${encodeURIComponent(conversationId)}/verify`,
      );
      setVerifiedAt(null);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not remove verification.');
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    if (!safetyNumber) return;
    try {
      await navigator.clipboard.writeText(safetyNumber);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setActionError('Clipboard access was denied.');
    }
  };

  const tone = directoryMismatch || verificationMismatch
    ? 'border-rose-500/30 bg-rose-500/10'
    : verified
      ? 'border-emerald-500/25 bg-emerald-500/5'
      : 'border-amber-500/25 bg-amber-500/5';

  return (
    <div className={`border-b px-4 py-3 ${tone}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-2.5">
          {verified ? (
            <CheckIcon className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
          ) : directoryMismatch || verificationMismatch ? (
            <AlertIcon className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
          ) : (
            <ShieldIcon className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
          )}
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 text-sm font-medium text-slate-200">
              <span>
                {directoryMismatch
                  ? 'Public key mismatch'
                  : verificationMismatch
                    ? 'Safety number changed'
                    : verified
                      ? `Verified with ${peer.username}`
                      : 'Verify this contact out of band'}
              </span>
              {!verified ? (
                <span className="pill border-slate-700 bg-slate-800/60 text-slate-400">
                  TOFU
                </span>
              ) : null}
            </div>
            <p className="mt-1 max-w-2xl text-xs leading-5 text-slate-400">
              {directoryMismatch
                ? 'The server returned a public key whose fingerprint does not match what this browser computed. Stop and verify through another channel.'
                : verificationMismatch
                  ? 'A previously verified safety number no longer matches the published keys. Re-verify before trusting this conversation.'
                  : verified
                    ? 'This safety number is pinned. It changes if either ML-KEM public key changes.'
                    : 'Compare these 60 digits with your contact over a separate channel. This catches a relay substituting public keys; it cannot protect the very first exchange.'}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {safetyNumber ? (
            <>
              <Button variant="ghost" className="h-8 px-2 text-xs" onClick={() => setExpanded((v) => !v)}>
                {expanded ? 'Hide digits' : 'Show digits'}
              </Button>
              <Button variant="ghost" className="h-8 px-2 text-xs" onClick={copy}>
                {copied ? 'Copied' : 'Copy'}
              </Button>
              {verified ? (
                <Button variant="ghost" className="h-8 px-2 text-xs" onClick={unverify} disabled={busy}>
                  Remove verification
                </Button>
              ) : (
                <Button className="h-8 px-3 py-1 text-xs" onClick={verify} disabled={busy || directoryMismatch}>
                  {busy ? 'Saving…' : 'Mark verified'}
                </Button>
              )}
            </>
          ) : null}
        </div>
      </div>

      {expanded && safetyNumber ? (
        <div className="mono mt-3 rounded-xl border border-slate-800 bg-slate-950/60 p-3 text-[13px] leading-6 tracking-[0.18em] text-slate-300">
          {formatSafetyNumber(safetyNumber).map((line) => (
            <div key={line}>{line}</div>
          ))}
          <div className="mt-2 border-t border-slate-800 pt-2 text-[10px] tracking-normal text-slate-500">
            <div>you: {self.fingerprint.slice(0, 32)}…</div>
            <div>peer: {peer.fingerprint.slice(0, 32)}…</div>
          </div>
        </div>
      ) : null}

      {computeError ? <div className="mt-2"><Alert tone="error">{computeError}</Alert></div> : null}
      {actionError ? <div className="mt-2"><Alert tone="error">{actionError}</Alert></div> : null}
      {directoryMismatch && fingerprints ? (
        <div className="mono mt-2 text-[10px] text-rose-300">
          computed self {fingerprints.self.slice(0, 24)}… / server {self.fingerprint.slice(0, 24)}…
          <br />
          computed peer {fingerprints.peer.slice(0, 24)}… / server {peer.fingerprint.slice(0, 24)}…
        </div>
      ) : null}
    </div>
  );
}

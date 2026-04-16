/**
 * RADIUS UDP server.
 * Supports EAP-MSCHAPv2 (RFC 2759) and PAP (RFC 2865) authentication.
 */

import type { Config } from "../../config/default.ts";
import type { DirectoryStore } from "../store/types.ts";
import type { Server } from "../server.ts";
import type { KvStore } from "../store/kv.ts";
import { Attr, EapCode, EapType, MsAttr, RadiusCode } from "./constants.ts";
import {
  computeMessageAuthenticator,
  computeResponseAuthenticator,
  decryptPapPassword,
  encryptMppeKey,
  verifyMessageAuthenticator,
} from "./crypto.ts";
import {
  encodeEapFailure,
  encodeEapSuccess,
  encodeMsChapv2Challenge,
  encodeMsChapv2Failure,
  encodeMsChapv2Success,
  parseEapIdentity,
  parseEapPacket,
  parseMsChapv2Response,
} from "./eap.ts";
import { deriveMSK, generateAuthenticatorResponse, verifyNTResponse } from "./mschapv2.ts";
import {
  encodePacket,
  getAttrBytes,
  getAttrString,
  getEapMessage,
  makeAttr,
  makeEapMessageAttrs,
  makeMsVsaAttr,
  makeStringAttr,
  parsePacket,
  type RadiusAttribute,
  type RadiusPacket,
} from "./packet.ts";
import { deleteEapState, getEapState, hexToBytes, saveEapState } from "./state.ts";
import { getNtHash, verifyPap } from "./auth.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ENC = new TextEncoder();

function secretBytes(secret: string): Uint8Array {
  return ENC.encode(secret);
}

/**
 * Build a response packet and compute both the Response Authenticator and,
 * if the response includes EAP-Message attributes, the Message-Authenticator.
 */
function buildResponse(
  code: number,
  id: number,
  requestAuth: Uint8Array,
  attrs: RadiusAttribute[],
  secret: Uint8Array,
): Uint8Array {
  // Add Message-Authenticator placeholder (16 zero bytes) for all responses
  // (strongSwan expects it even on non-EAP messages)
  const msgAuthPlaceholder = makeAttr(Attr.MessageAuthenticator, new Uint8Array(16));
  const allAttrs = [...attrs, msgAuthPlaceholder];

  // Encode with a temporary zero authenticator to compute lengths/offsets
  const tempPkt: RadiusPacket = {
    code,
    identifier: id,
    authenticator: new Uint8Array(16), // placeholder
    attributes: allAttrs,
  };
  let buf = encodePacket(tempPkt);

  // Compute Response Authenticator
  const attrsBytes = buf.slice(20);
  const responseAuth = computeResponseAuthenticator(
    code,
    id,
    buf.length,
    requestAuth,
    attrsBytes,
    secret,
  );

  // Write Response Authenticator into buffer
  buf = buf.slice(); // copy
  buf.set(responseAuth, 4);

  // Find and overwrite Message-Authenticator (attr 80) with HMAC-MD5
  let off = 20;
  while (off + 2 <= buf.length) {
    const type = buf[off];
    const len = buf[off + 1];
    if (len < 2) break;
    if (type === Attr.MessageAuthenticator && len === 18) {
      const mac = computeMessageAuthenticator(buf, secret);
      buf.set(mac, off + 2);
      break;
    }
    off += len;
  }

  return buf;
}

// ---------------------------------------------------------------------------
// EAP handler
// ---------------------------------------------------------------------------

async function handleEap(
  req: RadiusPacket,
  eapMsg: Uint8Array,
  socket: Deno.DatagramConn,
  remoteAddr: Deno.NetAddr,
  store: DirectoryStore,
  kv: Deno.Kv,
  config: Config,
): Promise<void> {
  const secret = secretBytes(config.radius.secret);
  const eap = parseEapPacket(eapMsg);

  // We only process EAP Responses from the client
  if (eap.code !== EapCode.Response) return;

  const type = eap.data[0];

  // --- EAP Identity ---
  if (type === EapType.Identity) {
    const userName = parseEapIdentity(eap);

    // Generate server challenge and state token
    const authChallenge = new Uint8Array(16);
    crypto.getRandomValues(authChallenge);
    const stateToken = new Uint8Array(16);
    crypto.getRandomValues(stateToken);

    const nextEapId = (eap.id + 1) & 0xff;
    const msChapId = nextEapId;

    await saveEapState(kv, stateToken, {
      authChallenge: Array.from(authChallenge).map((b) => b.toString(16).padStart(2, "0")).join(""),
      eapId: nextEapId,
      msChapId,
      userName,
      createdAt: Date.now(),
    });

    const challengePkt = encodeMsChapv2Challenge(
      nextEapId,
      msChapId,
      authChallenge,
      config.radius.serverName ?? "dldap",
    );

    const attrs: RadiusAttribute[] = [
      ...makeEapMessageAttrs(challengePkt),
      makeAttr(Attr.State, stateToken),
    ];

    const resp = buildResponse(
      RadiusCode.AccessChallenge,
      req.identifier,
      req.authenticator,
      attrs,
      secret,
    );
    await socket.send(resp, remoteAddr);
    return;
  }

  // --- EAP-MSCHAPv2 Response ---
  if (type === EapType.MSCHAPv2) {
    const stateAttr = getAttrBytes(req, Attr.State);
    if (!stateAttr || stateAttr.length !== 16) {
      console.warn("RADIUS: EAP-MSCHAPv2 response missing State attribute");
      await sendReject(req, socket, remoteAddr, secret, eap.id);
      return;
    }

    const state = await getEapState(kv, stateAttr);
    if (!state) {
      console.warn("RADIUS: EAP state not found or expired");
      await sendReject(req, socket, remoteAddr, secret, eap.id);
      return;
    }

    let msChapResponse;
    try {
      msChapResponse = parseMsChapv2Response(eap);
    } catch (e) {
      console.warn("RADIUS: Failed to parse MSCHAPv2 Response:", e);
      await deleteEapState(kv, stateAttr);
      await sendReject(req, socket, remoteAddr, secret, eap.id);
      return;
    }

    const { peerChallenge, ntResponse, userName } = msChapResponse;
    const authChallenge = hexToBytes(state.authChallenge);

    // Retrieve NT hash from directory
    const ntHash = await getNtHash(userName, store, config.radius.baseDN);
    if (!ntHash) {
      console.warn(
        `RADIUS: No sambaNTPassword for user "${userName}" — is SAMBA_AUTO_HASH enabled?`,
      );
      await deleteEapState(kv, stateAttr);
      await sendReject(req, socket, remoteAddr, secret, eap.id);
      return;
    }

    const valid = await verifyNTResponse(
      authChallenge,
      peerChallenge,
      userName,
      ntHash,
      ntResponse,
    );

    await deleteEapState(kv, stateAttr);

    if (!valid) {
      console.log(`RADIUS: EAP-MSCHAPv2 auth failed for user "${userName}"`);
      await sendReject(req, socket, remoteAddr, secret, eap.id);
      return;
    }

    // Success: compute AuthenticatorResponse and MSK
    const authResp = await generateAuthenticatorResponse(
      ntHash,
      ntResponse,
      peerChallenge,
      authChallenge,
      userName,
    );
    const msk = await deriveMSK(ntHash, ntResponse);
    const sendKey = msk.slice(0, 16);
    const recvKey = msk.slice(16, 32);

    const msChapSuccessPkt = encodeMsChapv2Success(
      (eap.id + 1) & 0xff,
      state.msChapId,
      authResp,
    );
    const eapSuccessPkt = encodeEapSuccess((eap.id + 2) & 0xff);

    const attrs: RadiusAttribute[] = [
      ...makeEapMessageAttrs(msChapSuccessPkt),
      ...makeEapMessageAttrs(eapSuccessPkt),
      makeMsVsaAttr(MsAttr.MppeSendKey, encryptMppeKey(sendKey, req.authenticator, secret)),
      makeMsVsaAttr(MsAttr.MppeRecvKey, encryptMppeKey(recvKey, req.authenticator, secret)),
    ];

    const resp = buildResponse(
      RadiusCode.AccessAccept,
      req.identifier,
      req.authenticator,
      attrs,
      secret,
    );
    await socket.send(resp, remoteAddr);
    console.log(`RADIUS: EAP-MSCHAPv2 authenticated user "${userName}"`);
    return;
  }

  // Unknown EAP type
  console.warn(`RADIUS: Unsupported EAP type ${type}`);
  await sendReject(req, socket, remoteAddr, secret, eap.id);
}

async function sendReject(
  req: RadiusPacket,
  socket: Deno.DatagramConn,
  remoteAddr: Deno.NetAddr,
  secret: Uint8Array,
  eapId: number,
): Promise<void> {
  const failurePkt = encodeMsChapv2Failure(eapId, eapId);
  const eapFailure = encodeEapFailure((eapId + 1) & 0xff);
  const attrs: RadiusAttribute[] = [
    ...makeEapMessageAttrs(failurePkt),
    ...makeEapMessageAttrs(eapFailure),
  ];
  const resp = buildResponse(
    RadiusCode.AccessReject,
    req.identifier,
    req.authenticator,
    attrs,
    secret,
  );
  await socket.send(resp, remoteAddr);
}

// ---------------------------------------------------------------------------
// Main packet handler
// ---------------------------------------------------------------------------

async function handlePacket(
  data: Uint8Array,
  remoteAddr: Deno.NetAddr,
  socket: Deno.DatagramConn,
  store: DirectoryStore,
  kv: Deno.Kv,
  config: Config,
): Promise<void> {
  let req: RadiusPacket;
  try {
    req = parsePacket(data);
  } catch (e) {
    console.warn("RADIUS: Malformed packet, dropping:", e);
    return;
  }

  const secret = secretBytes(config.radius.secret);

  // --- Accounting-Request ---
  if (req.code === RadiusCode.AccountingRequest) {
    const resp = buildResponse(
      RadiusCode.AccountingResponse,
      req.identifier,
      req.authenticator,
      [],
      secret,
    );
    await socket.send(resp, remoteAddr);
    return;
  }

  // --- Access-Request ---
  if (req.code === RadiusCode.AccessRequest) {
    // Verify Message-Authenticator if present
    if (!verifyMessageAuthenticator(data, secret)) {
      console.warn("RADIUS: Message-Authenticator mismatch, dropping packet");
      return;
    }

    const eapMsg = getEapMessage(req);
    if (eapMsg) {
      await handleEap(req, eapMsg, socket, remoteAddr, store, kv, config);
      return;
    }

    // PAP fallback
    const userPasswordBytes = getAttrBytes(req, Attr.UserPassword);
    if (userPasswordBytes) {
      const userName = getAttrString(req, Attr.UserName) ?? "";
      const password = decryptPapPassword(userPasswordBytes, secret, req.authenticator);
      const ok = await verifyPap(userName, password, store, config.radius.baseDN);

      if (ok) {
        const resp = buildResponse(
          RadiusCode.AccessAccept,
          req.identifier,
          req.authenticator,
          [],
          secret,
        );
        await socket.send(resp, remoteAddr);
        console.log(`RADIUS: PAP authenticated user "${userName}"`);
      } else {
        const resp = buildResponse(
          RadiusCode.AccessReject,
          req.identifier,
          req.authenticator,
          [makeStringAttr(Attr.ReplyMessage, "Authentication failed")],
          secret,
        );
        await socket.send(resp, remoteAddr);
        console.log(`RADIUS: PAP auth failed for user "${userName}"`);
      }
      return;
    }

    console.warn("RADIUS: Access-Request with no EAP-Message or User-Password, dropping");
    return;
  }

  console.warn(`RADIUS: Unexpected packet code ${req.code}, dropping`);
}

// ---------------------------------------------------------------------------
// Server factory
// ---------------------------------------------------------------------------

export function createRadiusServer(config: Config, store: DirectoryStore): Server {
  let socket: Deno.DatagramConn | null = null;
  let closed = false;
  // Access the raw Deno.Kv via KvStore
  const kv = (store as KvStore).rawKv();

  return {
    async serve() {
      socket = Deno.listenDatagram({
        hostname: config.radius.host,
        port: config.radius.port,
        transport: "udp",
      });

      for await (const [data, remoteAddr] of socket) {
        handlePacket(
          data as Uint8Array,
          remoteAddr as Deno.NetAddr,
          socket,
          store,
          kv,
          config,
        ).catch((e) => console.error("RADIUS handler error:", e));
      }
    },

    close() {
      if (!closed) {
        closed = true;
        socket?.close();
      }
    },
  };
}

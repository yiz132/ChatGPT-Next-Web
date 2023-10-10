import { NextRequest } from "next/server";
import { getServerSideConfig } from "../config/server";
import md5 from "spark-md5";
import { ACCESS_CODE_PREFIX } from "../constant";
import * as CryptoJS from "crypto-js";

function getIP(req: NextRequest) {
  let ip = req.ip ?? req.headers.get("x-real-ip");
  const forwardedFor = req.headers.get("x-forwarded-for");

  if (!ip && forwardedFor) {
    ip = forwardedFor.split(",").at(0) ?? "";
  }

  return ip;
}

function parseApiKey(bearToken: string) {
  const token = bearToken.trim().replaceAll("Bearer ", "").trim();
  const isOpenAiKey = !token.startsWith(ACCESS_CODE_PREFIX);

  return {
    accessCode: isOpenAiKey ? "" : token.slice(ACCESS_CODE_PREFIX.length),
    apiKey: isOpenAiKey ? token : "",
  };
}

const FIXED_SYMMETRIC_KEY = CryptoJS.enc.Utf8.parse("some_secure_key_32bytes!");
const IV = CryptoJS.enc.Utf8.parse("16_byte_iv_here!");

function decryptPublicKey(encryptedKey: string): string {
  // Decode the base64 encrypted data
  const decodedEncryptedData = CryptoJS.enc.Base64.parse(encryptedKey);

  // Splitting encrypted data and date
  const encryptedData = decodedEncryptedData.words.slice(
    0,
    decodedEncryptedData.sigBytes / 4 - 2,
  ); // remove date part
  const encryptedDataWordArray = CryptoJS.lib.WordArray.create(encryptedData);

  // Decrypt
  const decryptedData = CryptoJS.AES.decrypt(
    { ciphertext: encryptedDataWordArray } as any,
    FIXED_SYMMETRIC_KEY,
    {
      iv: IV,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    },
  );

  // Convert to string
  return decryptedData.toString(CryptoJS.enc.Utf8);
}

export function auth(req: NextRequest) {
  const authToken = req.headers.get("Authorization") ?? "";

  // check if it is openai api key or user token
  let { accessCode, apiKey: token } = parseApiKey(authToken);

  console.log("[Auth] got access code:", accessCode);

  if (accessCode.length !== 16) {
    accessCode = decryptPublicKey(accessCode);
    console.log("[Auth] decrypted access code:", accessCode);
  }

  const hashedCode = md5.hash(accessCode ?? "").trim();

  const serverConfig = getServerSideConfig();
  console.log("[Auth] allowed hashed codes: ", [...serverConfig.codes]);
  console.log("[Auth] got access code:", accessCode);
  console.log("[Auth] hashed access code:", hashedCode);
  console.log("[User IP] ", getIP(req));
  console.log("[Time] ", new Date().toLocaleString());

  if (serverConfig.needCode && !serverConfig.codes.has(hashedCode) && !token) {
    return {
      error: true,
      msg: !accessCode ? "empty access code" : "wrong access code",
    };
  }

  // if user does not provide an api key, inject system api key
  if (!token) {
    const apiKey = serverConfig.apiKey;
    if (apiKey) {
      console.log("[Auth] use system api key");
      req.headers.set("Authorization", `Bearer ${apiKey}`);
    } else {
      console.log("[Auth] admin did not provide an api key");
    }
  } else {
    console.log("[Auth] use user api key");
  }

  return {
    error: false,
  };
}

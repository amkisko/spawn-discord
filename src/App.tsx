import React, { useState, useEffect, useCallback } from "react";
import "./App.scss";
import Discord from "discord.js";

import { box, randomBytes } from "tweetnacl";
import {
  decodeUTF8,
  encodeUTF8,
  encodeBase64,
  decodeBase64
} from "tweetnacl-util";

const newNonce = () => randomBytes(box.nonceLength);
export const generateKeyPair = () => box.keyPair();

export const encrypt = (
  secretOrSharedKey: Uint8Array,
  json: any,
  key?: Uint8Array
) => {
  const nonce = newNonce();
  const messageUint8 = decodeUTF8(JSON.stringify(json));
  const encrypted = key
    ? box(messageUint8, nonce, key, secretOrSharedKey)
    : box.after(messageUint8, nonce, secretOrSharedKey);

  const fullMessage = new Uint8Array(nonce.length + encrypted.length);
  fullMessage.set(nonce);
  fullMessage.set(encrypted, nonce.length);

  const base64FullMessage = encodeBase64(fullMessage);
  return base64FullMessage;
};

export const decrypt = (
  secretOrSharedKey: Uint8Array,
  messageWithNonce: string,
  key?: Uint8Array
) => {
  const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
  const nonce = messageWithNonceAsUint8Array.slice(0, box.nonceLength);
  const message = messageWithNonceAsUint8Array.slice(
    box.nonceLength,
    messageWithNonce.length
  );

  const decrypted = key
    ? box.open(message, nonce, key, secretOrSharedKey)
    : box.open.after(message, nonce, secretOrSharedKey);

  if (!decrypted) {
    throw new Error("Could not decrypt message");
  }

  const base64DecryptedMessage = encodeUTF8(decrypted);
  return JSON.parse(base64DecryptedMessage);
};

function App() {
  const [discordToken, setDiscordToken] = useState<string>();
  const [discordClient, setDiscordClient] = useState<Discord.Client>();
  const [discordChannel, setDiscordChannel] = useState<Discord.TextChannel>();
  const [discordChannelId, setDiscordChannelId] = useState<string>();
  const [discordConnectLock, setDiscordConnectLock] = useState<Boolean>(false);
  const [rateLimitTimeout, setRateLimitTimeout] = useState<number>(0);
  const [keyPair, setKeypair] = useState<nacl.BoxKeyPair>();
  const [userId, setUserName] = useState<string>();
  const [alive, setAlive] = useState<Boolean>(false);
  const [targetPublicKeys, setTargetPublicKeys] = useState<{
    [key: string]: Uint8Array;
  }>({});
  const [masterPublicKey, setMasterPublicKey] = useState();
  const [isMasterNode, setIsMasterNode] = useState(false);

  const sendMessage = (
    channel: Discord.TextChannel,
    action: string,
    data: any,
    fromUserId: string,
    toUserId: string | null = null
  ) => {
    channel.send(
      JSON.stringify({
        action: action,
        fromUserId: fromUserId,
        toUserId: toUserId,
        data: data
      })
    );
  };

  const performHandshake = (
    channel: Discord.TextChannel,
    keyPair: nacl.BoxKeyPair,
    fromUserId: string,
    action: "handshakeRequest" | "handshakeAnswer" | "setMasterKey",
    toUserId: string | null = null
  ) => {
    sendMessage(
      channel,
      action,
      {
        publicKey: encodeBase64(keyPair.publicKey)
      },
      fromUserId,
      toUserId
    );
  };

  const connectDiscord = useCallback(() => {
    console.log("connectDiscord", discordToken, discordClient, keyPair, userId);
    if (
      !discordClient ||
      !keyPair ||
      !userId ||
      !discordToken ||
      !discordChannelId
    ) {
      return;
    }

    setDiscordConnectLock(true);

    discordClient.on("rateLimit", info => {
      console.log(info);
      setRateLimitTimeout(Math.floor(info.timeout));
      console.log(rateLimitTimeout);
    });

    discordClient.on("ready", () => {
      discordClient.channels.fetch(discordChannelId).then(result => {
        const channel = result as Discord.TextChannel;
        setDiscordChannel(channel);
        performHandshake(channel, keyPair, userId, "handshakeRequest");
      });
    });

    discordClient.on("invalidated", () => {
      console.log("invalidated");
    });

    discordClient.on("message", msg => {
      if (msg.content) {
        let json;
        try {
          json = JSON.parse(msg.content);
        } catch {}
        if (json) {
          const fromUserId = json["fromUserId"];
          const toUserId = json["toUserId"];
          const action = json["action"];
          const data = json["data"];

          if (fromUserId === userId) return;
          if (toUserId !== null && toUserId !== userId) return;

          switch (action) {
            case "handshakeRequest":
              console.log(targetPublicKeys);
              if (!targetPublicKeys[fromUserId]) {
                setTargetPublicKeys(
                  Object.assign(targetPublicKeys, {
                    [fromUserId]: data["publicKey"]
                  })
                );
                performHandshake(
                  msg.channel as Discord.TextChannel,
                  keyPair,
                  userId,
                  "handshakeAnswer",
                  fromUserId
                );
              }
              break;
            case "handshakeAnswer":
              if (!targetPublicKeys[fromUserId]) {
                setTargetPublicKeys(
                  Object.assign(targetPublicKeys, {
                    [fromUserId]: decodeBase64(data["publicKey"])
                  })
                );
              }
              break;
            case "setMasterKey":
              setMasterPublicKey(decodeBase64(data["publicKey"]));
              break;
            case "transmit":
              if (!targetPublicKeys[fromUserId]) {
                return;
              }

              const sharedKey = box.before(
                targetPublicKeys[fromUserId],
                keyPair.secretKey
              );
              const decrypted = decrypt(sharedKey, data);
              console.log(decrypted);
              break;
            default:
              break;
          }
        }
      }
    });

    console.log("login", discordToken);
    discordClient.login(discordToken).then(
      () => {
        // setDiscordConnectLock(false);
      },
      error => {
        setRateLimitTimeout(2 * 60);
        // setDiscordConnectLock(false);
      }
    );
  }, [
    discordClient,
    keyPair,
    userId,
    rateLimitTimeout,
    targetPublicKeys,
    discordToken
  ]);

  useEffect(() => {
    // NOTE: rate limit guard
    if (!!rateLimitTimeout) {
      if (rateLimitTimeout > 1) {
        setTimeout(() => {
          setRateLimitTimeout(rateLimitTimeout - 1);
        }, 1000);
      } else {
        setDiscordConnectLock(false);
        setRateLimitTimeout(0);
      }
      return;
    }

    // NOTE: params guard
    console.log(userId);
    if (!userId || !discordToken) {
      return;
    }

    // NOTE: connect lock guard
    if (discordConnectLock) {
      return;
    }

    // connectDiscord();
  }, [
    connectDiscord,
    discordToken,
    discordConnectLock,
    discordClient,
    discordChannel,
    keyPair,
    userId,
    rateLimitTimeout
  ]);

  useEffect(() => {
    if (alive) {
      return;
    }

    setDiscordClient(new Discord.Client());
    setKeypair(generateKeyPair());
    setUserName(`User-${Math.floor(1000000 + Math.random() * 1000000)}`);

    window.addEventListener("beforeunload", ev => {
      ev.preventDefault();
      if (discordChannel && keyPair) {
        discordChannel.send({
          action: "stop",
          publicKey: encodeBase64(keyPair.publicKey),
          name: userId
        });
      }
    });

    setAlive(true);
  }, [discordChannel, keyPair, userId, alive]);

  const transmitData = (
    data: any,
    receiverPublicKey: Uint8Array = masterPublicKey
  ) => {
    if (!discordChannel || !keyPair || !userId) return;

    const sharedKey = box.before(receiverPublicKey, keyPair.secretKey);
    sendMessage(discordChannel, "transmit", encrypt(sharedKey, data), userId);
  };

  const onButtonClick = (event: any) => {
    transmitData({
      test: true
    });
  };

  const onMasterClick = () => {
    if (!discordChannel || !keyPair || !userId) {
      return;
    }

    setIsMasterNode(true);
    performHandshake(discordChannel, keyPair, userId, "setMasterKey");
  };

  const actionDashboard = () => {
    return (
      <div>
        <div>{Object.keys(targetPublicKeys).length}</div>
        <button
          disabled={!!masterPublicKey || isMasterNode}
          onClick={onMasterClick}
        >
          Master
        </button>
        <button disabled={isMasterNode} onClick={onButtonClick}>
          Click me
        </button>
      </div>
    );
  };

  const onTokenInputChange = (ev: any) => {
    setDiscordToken(ev.target.value);
  };

  const onChannelIdInputChange = (ev: any) => {
    setDiscordChannelId(ev.target.value);
  };

  return (
    <div className="App">
      <div>
        <div>
          Token:{" "}
          <input
            onChange={onTokenInputChange}
            onBlur={onTokenInputChange}
            onKeyUp={onTokenInputChange}
          />
        </div>
        <div>
          Channel ID:
          <input
            onChange={onChannelIdInputChange}
            onBlur={onChannelIdInputChange}
            onKeyUp={onChannelIdInputChange}
          />
        </div>
        <button
          disabled={!discordToken || !!discordChannel}
          onClick={() => connectDiscord()}
        >
          Connect
        </button>
      </div>
      <span>
        Discord is{" "}
        {discordChannel
          ? "connected"
          : !rateLimitTimeout && discordConnectLock
          ? "connecting"
          : "not connected"}
        <br />
        {!!rateLimitTimeout && `retry after ${rateLimitTimeout}`}
        {discordChannel && actionDashboard()}
      </span>
    </div>
  );
}

export default App;

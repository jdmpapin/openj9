/*******************************************************************************
 * Copyright IBM Corp. and others 2018
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse Public License 2.0 which accompanies this
 * distribution and is available at https://www.eclipse.org/legal/epl-2.0/
 * or the Apache License, Version 2.0 which accompanies this distribution and
 * is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * This Source Code may also be made available under the following
 * Secondary Licenses when the conditions for such availability set
 * forth in the Eclipse Public License, v. 2.0 are satisfied: GNU
 * General Public License, version 2 with the GNU Classpath
 * Exception [1] and GNU General Public License, version 2 with the
 * OpenJDK Assembly Exception [2].
 *
 * [1] https://www.gnu.org/software/classpath/license.html
 * [2] https://openjdk.org/legal/assembly-exception.html
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0 OR GPL-2.0-only WITH OpenJDK-assembly-exception-1.0
 *******************************************************************************/

#include "ServerStream.hpp"
#include "infra/String.hpp"

// NOTE: The length of this hello is conveniently the exact same length as the
// fixed-size prefix of the first message sent by a pre-hello client. See
// tryDetectPreHelloClient(), which relies on this.
#define HELLO "OpenJ9/JITServer"
#define HELLO_LEN (sizeof(HELLO) - 1)

namespace JITServer
{
int ServerStream::_numConnectionsOpened = 0;
int ServerStream::_numConnectionsClosed = 0;

ServerStream::ServerStream(int connfd, BIO *ssl)
   : CommunicationStream()
   , _compatibilityCheckDone(false)
   {
   initStream(connfd, ssl);
   _numConnectionsOpened++;
   _pClientSessionData = NULL;
   }

static const char *getHandshakeCpuArchName(uint32_t arch)
   {
   switch (arch)
      {
      case HandshakeCpuArch_PPC64LE:
         return "PPC64LE";
      case HandshakeCpuArch_X86_64:
         return "x86-64";
      case HandshakeCpuArch_Z:
         return "z";
      default:
         return "<unknown CPU arch>";
      }
   }

static const char *getHandshakeOsName(uint32_t os)
   {
   switch (os)
      {
      case HandshakeOs_Linux:
         return "Linux";
      default:
         return "<unknown OS>";
      }
   }

static const char *getHandshakeCompressedRefsName(uint32_t setting)
   {
   switch (setting)
      {
      case HandshakeCompressedRefs_Disabled:
         return "-Xnocompressedrefs";
      case HandshakeCompressedRefs_Enabled:
         return "-Xcompressedrefs";
      default:
         return "<unknown compressed refs setting>";
      }
   }

void ServerStream::checkCompatibilityWithClientImpl()
   {
   _compatibilityCheckDone = true;

   char helloBuf[HELLO_LEN];

   // First the client sends the hello. This is positive confirmation that the
   // client is trying to speak JITServer protocol.
   bool helloOK = true;
   bool isImmediateHangup = false;
   try
      {
      // For the first read, allow the client to hang up before it sends any
      // data at all. Clients may establish a connection and then never send a
      // compilation request on it, in which case they also might never send the
      // hello before hanging up. This prevents spurious bad hello warnings.
      bool allowImmediateEof = true;
      int32_t numBytesRead = readOnceBlocking(helloBuf, HELLO_LEN, allowImmediateEof);
      if (numBytesRead == 0)
         {
         isImmediateHangup = true;
         throw JITServer::StreamFailure("client hung up before sending any data");
         }

      if (numBytesRead < HELLO_LEN)
         {
         readBlocking(helloBuf + numBytesRead, HELLO_LEN - numBytesRead);
         }
      }
   catch (const JITServer::StreamFailure &e)
      {
      if (isImmediateHangup)
         {
         throw e;
         }
      else
         {
         // Client sent at least one byte, and there was an I/O error or end of
         // stream before the end of the hello.
         helloOK = false;
         }
      }

   // Check that the hello is correct.
   if (helloOK && strncmp(helloBuf, HELLO, HELLO_LEN) != 0)
      {
      if (!tryDetectPreHelloClient(helloBuf))
         {
         helloOK = false;
         }
      else
         {
         // Received data suggest a new client still trying to communicate
         // stream version and correctly determine incompatibility with
         // pre-hello servers. The normal hello should follow immediately.
         readBlocking(helloBuf, HELLO_LEN);
         if (strncmp(helloBuf, HELLO, HELLO_LEN) != 0)
            {
            helloOK = false;
            }
         }
      }

   if (!helloOK)
      {
      throw JITServer::BadHelloFromClient(getConnIpAddr());
      }

   // Immediately after the hello, the client sends:
   // 1. its JDK version (i.e. Java major release version),
   // 2. the CPU architecture it's running on,
   // 3. the OS it's running on,
   // 4. whether compressed refs are enabled,
   // 5. the length of version negotiation data, and
   // 6. a description of the protocol versions that it supports.
   //
   // #1-#3 are all 32-bit values, #4 is a single byte, #5 is 16-bit (to avoid
   // allocating or waiting for GB of memory), and #6 has the length specified
   // in #5.
   //
   char fixedSizeBuf[4 + 4 + 4 + 1 + 2];
   readBlocking(fixedSizeBuf, sizeof(fixedSizeBuf));

   ByteBufReader r(fixedSizeBuf, sizeof(fixedSizeBuf));
   uint32_t clientJdkVersion = r.readU32BE();
   uint32_t clientCpuArch = r.readU32BE();
   uint32_t clientOs = r.readU32BE();
   uint8_t clientCompressedRefs = r.readU8();
   uint16_t clientAllVersionDataLen = r.readU16BE();

   std::vector<char> allVersionData(clientAllVersionDataLen, '\0');
   readBlocking(&allVersionData[0], clientAllVersionDataLen);

   // For now, the server requires an exact match in all of JDK version, CPU
   // architecture, OS, and compressedRefs.
   std::vector<std::string> unsupported;
   char buf[1024];

   if (clientJdkVersion != JAVA_SPEC_VERSION)
      {
      TR::snprintfNoTrunc(
         buf,
         sizeof(buf),
         "JDK version %u vs. required: %u",
         clientJdkVersion,
         JAVA_SPEC_VERSION);

      unsupported.push_back(buf);
      }

   uint32_t serverCpuArch = CommunicationStream::getJITServerCpuArch();
   if (clientCpuArch != serverCpuArch)
      {
      TR::snprintfNoTrunc(
         buf,
         sizeof(buf),
         "%s vs. required: %s",
         getHandshakeCpuArchName(clientCpuArch),
         getHandshakeCpuArchName(serverCpuArch));

      unsupported.push_back(buf);
      }

   uint32_t serverOs = CommunicationStream::getJITServerOs();
   if (clientOs != serverOs)
      {
      TR::snprintfNoTrunc(
         buf,
         sizeof(buf),
         "%s vs. required: %s",
         getHandshakeOsName(clientOs),
         getHandshakeOsName(serverOs));

      unsupported.push_back(buf);
      }

   uint8_t serverCompressedRefs =
      TR::Compiler->om.compressObjectReferencesInCurrentProcess()
      ? HandshakeCompressedRefs_Enabled
      : HandshakeCompressedRefs_Disabled;

   if (clientCompressedRefs != serverCompressedRefs)
      {
      TR::snprintfNoTrunc(
         buf,
         sizeof(buf),
         "%s vs. required: %s",
         getHandshakeCompressedRefsName(clientCompressedRefs),
         getHandshakeCompressedRefsName(serverCompressedRefs));

      unsupported.push_back(buf);
      }

   // Check the options the client gave for protocol versions.
   r = ByteBufReader(&allVersionData[0], clientAllVersionDataLen);
   bool ok = true;
   uint16_t numVersionOptions = 0;
   int32_t selectedVersionOptionIndex = -1;

   if (!r.tryReadU16BE(numVersionOptions))
      {
      ok = false;
      }

   if (ok)
      {
      if (numVersionOptions == 0)
         {
         unsupported.push_back("client offered no protocol version options");
         }

      char serverBuildId[1024];
      CommunicationStream::getJITServerBuildId(serverBuildId, sizeof(serverBuildId));
      size_t serverBuildIdLen = strlen(serverBuildId);

      for (uint16_t versionOptionIndex = 0;
           versionOptionIndex < numVersionOptions;
           versionOptionIndex++)
         {
         // Extract the parts of a client-offered version option.
         // 1. unsigned 32-bit protocol version
         // 2. unsigned 16-bit length of version variant data
         // 3. version variant data (length specified in #2)
         uint32_t protocolVersion = 0;
         if (!r.tryReadU32BE(protocolVersion))
            {
            ok = false;
            break;
            }

         uint16_t versionVariantLen = 0;
         if (!r.tryReadU16BE(versionVariantLen))
            {
            ok = false;
            break;
            }

         const char *versionVariantData = r._cursor;
         if (r.remaining() >= versionVariantLen)
            {
            r._cursor += versionVariantLen;
            }
         else
            {
            ok = false;
            break;
            }

         // Decide whether to select this option. Currently the server only
         // supports version 0, which is a pseudo-version that can vary between
         // builds. The version variant is a build identifier so that we can
         // reject connections from clients from other builds.
         if (protocolVersion == 0
             && versionVariantLen == serverBuildIdLen
             && !strncmp(versionVariantData, serverBuildId, serverBuildIdLen))
            {
            // Select this one, but don't break. Keep looping through the rest
            // of the options to make sure they aren't malformed.
            selectedVersionOptionIndex = versionOptionIndex;
            }
         }
      }

   if (!ok)
      {
      unsupported.push_back("client offered malformed version options");
      }
   else if (selectedVersionOptionIndex < 0)
      {
      // This could be more informative in the future if there is ever a version
      // beyond zero, e.g. we could say which versions the client supports and
      // which versions the server supports. For now, the server always requires
      // an exact build match, so just say that.
      unsupported.push_back(
         "build mismatch; client and server must be from the same JVM build");
      }

   // Reject the client if we have any rejection reasons.
   if (!unsupported.empty())
      {
      std::string msg;
      msg += "server is incompatible with client: " + unsupported[0];
      for (auto it = unsupported.begin() + 1; it != unsupported.end(); it++)
         {
         msg += "; ";
         msg += *it;
         }

      // The response in case of incompatbility is:
      // 1. HandshakeResponseCode_Incompatible (one byte)
      // 2. Message length (16-bit).
      // 3. The error message in ASCII.
      //
      // The server might potentially try to send more data after this, but the
      // client should not read any further response data.
      //
      size_t fullMsgLen = msg.size();
      uint16_t msgLen = fullMsgLen <= UINT16_MAX ? (uint16_t)fullMsgLen : UINT16_MAX;

      size_t responseLen = 3 + msgLen + 1; // +1 for NUL from snprintfNoTrunc()
      std::vector<char> response(responseLen, '\0');
      char *responseStart = &response[0];

      ByteBufWriter w(responseStart, responseLen);
      w.writeU8((uint8_t)HandshakeResponseCode_Incompatible);
      w.writeU16BE(msgLen);
      w._cursor += TR::snprintfNoTrunc(
         w._cursor, w.remaining(), "%.*s", msgLen, msg.c_str());

      writeBlocking(responseStart, w._cursor - responseStart);
      throw JITServer::StreamVersionIncompatible(msg);
      }

   // The client is compatible with this server! The response is:
   // 1. HandshakeResponseCode_OK (one byte)
   // 2. The selected version option index (unsigned 16-bit).
   //
   // All following communication on this connection will be according to the
   // selected protocol version/variant.
   //
   // Note that the selected option index fits into 16 bits because the number
   // of options and even the number of bytes worth of options sent by the
   // client fit into 16 bits.
   //
   TR_ASSERT_FATAL(
      0 <= selectedVersionOptionIndex && selectedVersionOptionIndex <= UINT16_MAX,
      "selected version option index %d is out of range\n",
      selectedVersionOptionIndex);

   ByteBufWriter w(buf, 3);
   w.writeU8((uint8_t)HandshakeResponseCode_OK);
   w.writeU16BE((uint16_t)selectedVersionOptionIndex);
   writeBlocking(buf, w._cursor - buf);
   }

static uint32_t byteswapU32(uint32_t x)
   {
   uint32_t result = 0;
   result |= (x & 0xff) << 24;
   result |= ((x >> 8) & 0xff) << 16;
   result |= ((x >> 16) & 0xff) << 8;
   result |= (x >> 24) & 0xff;
   return result;
   }

static uint32_t byteswapU32(uint32_t x, bool swap)
   {
   return swap ? byteswapU32(x) : x;
   }

static uint16_t byteswapU16(uint16_t x)
   {
   return ((x & 0xff) << 8) | ((x >> 8) & 0xff);
   }

static uint16_t byteswapU16(uint16_t x, bool swap)
   {
   return swap ? byteswapU16(x) : x;
   }

// Try to recognize a pre-hello compilationRequest message.
// - If it specifies version 2.0 (actually a new client), return true.
// - If it specifies a recognized older version, respond with
//   compilationStreamVersionIncompatible and throw StreamVersionIncompatible.
// - Otherwise, return false.
bool ServerStream::tryDetectPreHelloClient(const char *compReqMetaDataBuf)
   {
   // Prior to the hello/handshake, the client would send a compilationRequest
   // message as the first communication. Each message had the following format,
   // with all integers unsigned and in client endianness:
   // - 32-bit message length
   // - 32-bit JITServer version, value: (1 << 24) | (minor << 8)
   // - 32-bit configuration word (Java version and compressed refs flag)
   // - 16-bit message type (compilationRequest for the first message)
   // - 16-bit number of top-level values sent with the message
   // - then the values
   //
   // Eventually we shouldn't need to worry about these clients anymore, but at
   // least to begin with they might try to connect, and if we just hang up due
   // to the bad hello, they won't know that the server is incompatible. Detect
   // these clients and send them a compilationFailure message that they will
   // understand. The compilationFailure message comes with two values:
   // - unsigned 32-bit status code (compilationStreamVersionIncompatible)
   // - unsigned 64-bit "other data" (-1)

   // Conveniently, the length of the hello is exactly the same as the length of
   // the fixed-size part of the message from the client (which can be seen to
   // be 16 bytes by summing the sizes of the items listed above).
   static_assert(HELLO_LEN == 16, "the buffer should have length 16");

   // Read assuming that the values are in big-endian, and adjust later if necessary.
   ByteBufReader reader(compReqMetaDataBuf, HELLO_LEN);
   uint32_t clientMsgLen = reader.readU32BE();
   uint32_t clientStreamVersion = reader.readU32BE();
   uint32_t clientConfig = reader.readU32BE();
   uint16_t clientMsgType = reader.readU16BE();
   uint16_t clientNumVals = reader.readU16BE();

   struct OldVersion
      {
      const char *_openj9Version;
      uint32_t _streamVersion;
      uint32_t _compErrorCode_compilationStreamVersionIncompatible;
      uint16_t _messageType_compilationRequest;
      };

   static const OldVersion oldVersions[] =
      {
         {
            ._openj9Version = NULL, // actually a new client (not pre-hello)
            ._streamVersion = backCompatEncodeVersion(2, 0),
            ._messageType_compilationRequest = 8,
         },
         {
            ._openj9Version = "0.55.0 (jdk25)",
            ._streamVersion = backCompatEncodeVersion(1, 88),
            ._compErrorCode_compilationStreamVersionIncompatible = 52,
            ._messageType_compilationRequest = 8,
         },
         {
            ._openj9Version = "0.53.0",
            ._streamVersion = backCompatEncodeVersion(1, 80),
            ._compErrorCode_compilationStreamVersionIncompatible = 52,
            ._messageType_compilationRequest = 8,
         },
         {
            ._openj9Version = "0.51.0",
            ._streamVersion = backCompatEncodeVersion(1, 79),
            ._compErrorCode_compilationStreamVersionIncompatible = 51,
            ._messageType_compilationRequest = 8,
         },
         {
            ._openj9Version = "0.49.0",
            ._streamVersion = backCompatEncodeVersion(1, 72),
            ._compErrorCode_compilationStreamVersionIncompatible = 51,
            ._messageType_compilationRequest = 8,
         },
         {
            ._openj9Version = "0.48.0",
            ._streamVersion = backCompatEncodeVersion(1, 65),
            ._compErrorCode_compilationStreamVersionIncompatible = 51,
            ._messageType_compilationRequest = 8,
         },
         {
            ._openj9Version = "0.46.x", // 0.46.0, 0.46.1
            ._streamVersion = backCompatEncodeVersion(1, 62),
            ._compErrorCode_compilationStreamVersionIncompatible = 51,
            ._messageType_compilationRequest = 8,
         },
         {
            ._openj9Version = "0.44.0",
            ._streamVersion = backCompatEncodeVersion(1, 59),
            ._compErrorCode_compilationStreamVersionIncompatible = 51,
            ._messageType_compilationRequest = 8,
         },
         {
            ._openj9Version = "0.41.0, 0.42.0 (jdk21), or 0.43.0",
            ._streamVersion = backCompatEncodeVersion(1, 53),
            ._compErrorCode_compilationStreamVersionIncompatible = 51,
            ._messageType_compilationRequest = 6,
         },
         {
            ._openj9Version = "0.40.0",
            ._streamVersion = backCompatEncodeVersion(1, 44),
            ._compErrorCode_compilationStreamVersionIncompatible = 51,
            ._messageType_compilationRequest = 6,
         },
         {
            ._openj9Version = "0.38.0",
            ._streamVersion = backCompatEncodeVersion(1, 43),
            ._compErrorCode_compilationStreamVersionIncompatible = 51,
            ._messageType_compilationRequest = 6,
         },
         {
            ._openj9Version = "0.36.x", // 0.36.0, 0.36.1
            ._streamVersion = backCompatEncodeVersion(1, 41),
            ._compErrorCode_compilationStreamVersionIncompatible = 51,
            ._messageType_compilationRequest = 6,
         },
         {
            ._openj9Version = "0.35.0",
            ._streamVersion = backCompatEncodeVersion(1, 40),
            ._compErrorCode_compilationStreamVersionIncompatible = 51,
            ._messageType_compilationRequest = 6,
         },
         {
            ._openj9Version = "0.33.x", // 0.33.0, 0.33.1
            ._streamVersion = backCompatEncodeVersion(1, 38),
            ._compErrorCode_compilationStreamVersionIncompatible = 51,
            ._messageType_compilationRequest = 6,
         },
         {
            ._openj9Version = "0.32.0",
            ._streamVersion = backCompatEncodeVersion(1, 37),
            ._compErrorCode_compilationStreamVersionIncompatible = 64,
            ._messageType_compilationRequest = 6,
         },
         {
            ._openj9Version = "0.30.x", // 0.30.0, 0.30.1
            ._streamVersion = backCompatEncodeVersion(1, 34),
            ._compErrorCode_compilationStreamVersionIncompatible = 64,
            ._messageType_compilationRequest = 6,
         },
         {
            ._openj9Version = "0.29.x", // 0.29.0, 0.29.1
            ._streamVersion = backCompatEncodeVersion(1, 30),
            ._compErrorCode_compilationStreamVersionIncompatible = 64,
            ._messageType_compilationRequest = 5,
         },
         {
            ._openj9Version = "0.27.0",
            ._streamVersion = backCompatEncodeVersion(1, 26),
            ._compErrorCode_compilationStreamVersionIncompatible = 64,
            ._messageType_compilationRequest = 5,
         },
      };

   OldVersion match = {};
   bool littleEndian = false;
   bool foundMatch = false;
   for (size_t i = 0; i < sizeof(oldVersions) / sizeof(oldVersions[0]); i++)
      {
      const OldVersion &candidate = oldVersions[i];
      for (int32_t j = 0; j < 2; j++)
         {
         bool leCandidate = j == 1;
         uint32_t checkVersion = byteswapU32(clientStreamVersion, leCandidate);
         uint16_t checkMsgType = byteswapU16(clientMsgType, leCandidate);
         if ((checkVersion == candidate._streamVersion
              && checkMsgType == candidate._messageType_compilationRequest))
            {
            match = candidate;
            littleEndian = leCandidate;
            foundMatch = true;
            break;
            }
         }
      }

   bool isClientSessionTerminate = false;
   if (!foundMatch)
      {
      // Old clients send a clientSessionTerminate message when they shut down
      // even if the initial connection was immediately closed due to a stream
      // version incompatibility. Unfortunately, they send it with the version
      // zeroed out even though the compatibility check never succeeded.

      // The value of clientSessionTerminate has varied...
      const uint16_t minOldClientSessionTerminate = 7;
      const uint16_t maxOldClientSessionTerminate = 10;

      for (int i = 0; i < 2; i++)
         {
         bool le = i == 1;
         uint16_t checkMsgType = byteswapU16(clientMsgType, le);
         if (minOldClientSessionTerminate <= checkMsgType
             && checkMsgType <= maxOldClientSessionTerminate
             && byteswapU16(clientNumVals, le) == 1
             && byteswapU32(clientMsgLen, le) == HELLO_LEN + 16) // 16 bytes for a UINT64
            {
            // No response is expected. We can just terminate the connection.
            throw StreamVersionIncompatible("clientSessionTerminate from pre-hello client");
            }
         }

      if (!isClientSessionTerminate)
         {
         fprintf( // XXX
            stderr,
            "jdmp no match... clientStreamVersion=%x, clientMsgType=%x, clientNumVals=%x, clientMsgLen=%x\n",
            clientStreamVersion,
            clientMsgType,
            clientNumVals,
            clientMsgLen);

         return false;
         }
      }

   if (byteswapU32(clientMsgLen, littleEndian) < HELLO_LEN)
      {
      return false; // message length is too small, bad message
      }

   if (foundMatch && match._streamVersion == backCompatEncodeVersion(2, 0))
      {
      // This is a post-hello client still trying to be sufficiently compatible
      // with pre-hello servers to correctly determine version incompatibility
      // (instead of hitting generic stream errors). Expect the hello to follow.
      return true;
      }

   uint32_t oldCompatFlags = JAVA_SPEC_VERSION & BackCompatJITServerJavaVersionMask;
   if (TR::Compiler->om.compressObjectReferencesInCurrentProcess())
      {
      oldCompatFlags |= BackCompatJITServerCompressedRef;
      }

   char outBuf[128]; // big enough...
   ByteBufWriter writer(outBuf, sizeof(outBuf));
   ByteBufWriter msgLenWriter = writer; // to fix message length at the end
   writer.writeU32BE(0); // placeholder for message length
   writer.writeU32BE(byteswapU32(backCompatEncodeVersion(2, 0), littleEndian));
   writer.writeU32BE(byteswapU32(oldCompatFlags, littleEndian));
   writer.writeU16BE(byteswapU16(BackCompatMessageType_compilationFailure, littleEndian));
   writer.writeU16BE(byteswapU16(2, littleEndian)); // two values with the message

   // First value: uint32_t compilation error code
   writer.writeU8((uint8_t)BackCompatDataType_UINT32);
   writer.writeU8(0); // no trailing padding
   writer.writeU8(0); // payload immediately follows data descriptor (+0 bytes)
   writer.writeU8(0); // vector element size (non-vector data)
   writer.writeU32BE(byteswapU32(4, littleEndian)); // data size

   uint32_t errCode = match._compErrorCode_compilationStreamVersionIncompatible;
   writer.writeU32BE(byteswapU32(errCode, littleEndian));

   // Second value: (uint64_t)-1. Just write a 32-bit -1 twice.
   writer.writeU8((uint8_t)BackCompatDataType_UINT64);
   writer.writeU8(0); // no trailing padding
   writer.writeU8(0); // payload immediately follows data descriptor (+0 bytes)
   writer.writeU8(0); // vector element size (non-vector data)
   writer.writeU32BE(byteswapU32(8, littleEndian)); // data size

   writer.writeU32BE((uint32_t)-1); // don't bother with byteswap (no effect)
   writer.writeU32BE((uint32_t)-1);

   // Fix the message length.
   uint32_t msgLen = (uint32_t)(writer._cursor - outBuf); // len includes itself
   msgLenWriter.writeU32BE(byteswapU32(msgLen, littleEndian));

   writeBlocking(outBuf, msgLen);

   // Done with outBuf for sending the response. Reuse it for the exception message.
   TR::snprintfNoTrunc(
      outBuf,
      sizeof(outBuf),
      "pre-hello client (OpenJ9 version %s)",
      match._openj9Version);

   throw JITServer::StreamVersionIncompatible(outBuf);
   }

static bool handleCreateSSLContextError(SSL_CTX *&ctx, const char *errMsg)
   {
   perror(errMsg);
   (*OERR_print_errors_fp)(stderr);
   if (ctx)
      {
      (*OSSL_CTX_free)(ctx);
      ctx = NULL;
      }
   return false;
   }

bool ServerStream::createSSLContext(SSL_CTX *&ctx, const char *sessionContextID, size_t sessionContextIDLen,
                                    const PersistentVector<std::string> &sslKeys, const PersistentVector<std::string> &sslCerts,
                                    const std::string &sslRootCerts)
   {
   ctx = (*OSSL_CTX_new)((*OSSLv23_server_method)());

   if (!ctx)
      {
      return handleCreateSSLContextError(ctx, "can't create SSL context");
      }

   (*OSSL_CTX_set_session_id_context)(ctx, (const unsigned char*)sessionContextID, sessionContextIDLen);

   if ((*OSSL_CTX_set_ecdh_auto)(ctx, 1) != 1)
      {
      return handleCreateSSLContextError(ctx, "failed to configure SSL ecdh");
      }

   TR_ASSERT_FATAL(sslKeys.size() == 1 && sslCerts.size() == 1, "only one key and cert is supported for now");
   TR_ASSERT_FATAL(sslRootCerts.size() == 0, "server does not understand root certs yet");

   // Parse and set private key
   BIO *keyMem = (*OBIO_new_mem_buf)(&sslKeys[0][0], sslKeys[0].size());
   if (!keyMem)
      {
      return handleCreateSSLContextError(ctx, "cannot create memory buffer for private key (OOM?)");
      }
   EVP_PKEY *privKey = (*OPEM_read_bio_PrivateKey)(keyMem, NULL, NULL, NULL);
   if (!privKey)
      {
      return handleCreateSSLContextError(ctx, "cannot parse private key");
      }
   if ((*OSSL_CTX_use_PrivateKey)(ctx, privKey) != 1)
      {
      return handleCreateSSLContextError(ctx, "cannot use private key");
      }

   // Parse and set certificate
   BIO *certMem = (*OBIO_new_mem_buf)(&sslCerts[0][0], sslCerts[0].size());
   if (!certMem)
      {
      return handleCreateSSLContextError(ctx, "cannot create memory buffer for cert (OOM?)");
      }
   X509 *certificate = (*OPEM_read_bio_X509)(certMem, NULL, NULL, NULL);
   if (!certificate)
      {
      return handleCreateSSLContextError(ctx, "cannot parse cert");
      }
   if ((*OSSL_CTX_use_certificate)(ctx, certificate) != 1)
      {
      return handleCreateSSLContextError(ctx, "cannot use cert");
      }

   // Verify key and cert are valid
   if ((*OSSL_CTX_check_private_key)(ctx) != 1)
      {
      return handleCreateSSLContextError(ctx, "private key check failed");
      }

   // verify server identity using standard method
   (*OSSL_CTX_set_verify)(ctx, SSL_VERIFY_PEER, NULL);

   if (TR::Options::getVerboseOption(TR_VerboseJITServer))
      TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "Successfully initialized SSL context (%s)", (*OOpenSSL_version)(0));

   return true;
   }
}

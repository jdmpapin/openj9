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

#ifndef COMMUNICATION_STREAM_H
#define COMMUNICATION_STREAM_H

#include <unistd.h>
#include "j9version.h"
#include "infra/Statistics.hpp"
#include "net/LoadSSLLibs.hpp"
#include "net/Message.hpp"
#include "net/StreamExceptions.hpp"
#include "env/VerboseLog.hpp"
#include "control/MethodToBeCompiled.hpp"

namespace JITServer
{
// The specifics around the precise version or set of extensions is worked out
// separately after a connection is successfully established.
enum HandshakeCpuArch
   {
   HandshakeCpuArch_PPC64LE = 0,
   HandshakeCpuArch_X86_64 = 1,
   HandshakeCpuArch_Z = 2, // 64-bit
   HandshakeCpuArch_AArch64 = 3,
   };

// Currently only Linux is supported.
enum HandshakeOs
   {
   HandshakeOs_Linux = 0,
   };

enum HandshakeCompressedRefs
   {
   HandshakeCompressedRefs_Disabled = 0,
   HandshakeCompressedRefs_Enabled = 1,
   };

// Avoid all multiples of 4 to allow clients to recognize when a response is
// coming from a pre-hello server.
enum HandshakeResponseCode
   {
   HandshakeResponseCode_Incompatible = 1,
   HandshakeResponseCode_OK = 2,
   };

// For communicating with clients/servers from before the new handshake.
// Just compatible enough to communicate a version mismatch to the old build.
// These are values that are consistent in all old release versions.

enum BackCompatMessageType
   {
   BackCompatMessageType_compilationFailure = 1,
   };

enum BackCompatDataType
   {
   BackCompatDataType_UINT32 = 2,
   BackCompatDataType_UINT64 = 3,
   };

enum BackCompatJITServerCompatibilityFlags
   {
   BackCompatJITServerJavaVersionMask = 0x00000FFF,
   BackCompatJITServerCompressedRef   = 0x00001000,
   };

inline uint32_t backCompatEncodeVersion(uint8_t major, uint16_t minor)
   {
   return (uint32_t)major << 24 | (uint32_t)minor << 8;
   }

// When adding another compatibility mask/flag, also add a new message in
// CommunicationStream::showFullVersionIncompatibility that handles the new enum value.
enum JITServerCompatibilityFlags
   {
   JITServerJavaVersionMask    = 0x00000FFF,
   JITServerCompressedRef      = 0x00001000,
   };

class CommunicationStream
   {
public:
   static bool useSSL();
   static void initSSL();

   static uint32_t _msgTypeCount[MessageType::MessageType_MAXTYPE];
   static uint64_t _totalMsgSize;
   static uint32_t _lastReadError;
   static uint32_t _numConsecutiveReadErrorsOfSameType;
   // The max read retry should be 1 less than the max compile attempt so we do
   // local compilations in the last attempt
   static const uint32_t MAX_READ_RETRY = MAX_COMPILE_ATTEMPTS - 1;
#if defined(MESSAGE_SIZE_STATS)
   static TR_Stats _msgSizeStats[MessageType::MessageType_MAXTYPE];
#endif /* defined(MESSAGE_SIZE_STATS) */

   static HandshakeCpuArch getJITServerCpuArch()
      {
#if !defined(TR_TARGET_64BIT)
#error "JITServer supports 64-bit only"
#elif defined(TR_TARGET_POWER)
#if !defined(__LITTLE_ENDIAN__)
#error "JITServer supports little-endian Power, but not big-endian"
#endif
      return HandshakeCpuArch_PPC64LE;
#elif defined(TR_TARGET_X86)
      return HandshakeCpuArch_X86_64;
#elif defined(TR_TARGET_S390)
      return HandshakeCpuArch_Z;
#elif defined(TR_TARGET_ARM64)
      return HandshakeCpuArch_AArch64;
#else
#error "JITServer does not support this target"
#endif
      }

   static HandshakeOs getJITServerOs()
      {
#if defined(LINUX)
      return HandshakeOs_Linux;
#else
#error "JITServer does not support this OS"
#endif
      }

   /**
    * \brief Get the JITServer build ID.
    *
    * The destination buffer must be "large enough."
    *
    * \param dest[out] destination buffer
    * \param size the length of \p dest in bytes
    */
   static void getJITServerBuildId(char *dest, size_t size);

   static void initConfigurationFlags();

   static uint32_t getJITServerVersion()
      {
      return (MAJOR_NUMBER << 24) | (MINOR_NUMBER << 8); // PATCH_NUMBER is ignored
      }

   static std::string showJITServerVersion(uint32_t fullVersion)
      {
      uint8_t majorVersion = fullVersion >> 24;
      uint16_t minorVersion = (fullVersion >> 8) & 0xFFFF;
      return std::to_string(majorVersion) + "." + std::to_string(minorVersion);
      }

   static uint64_t getJITServerFullVersion()
      {
      return Message::buildFullVersion(getJITServerVersion(), CONFIGURATION_FLAGS);
      }
   static std::string showFullVersionIncompatibility(uint64_t serverFullVersion, uint64_t clientFullVersion);

   static void printJITServerVersion()
      {
      // print the human-readable version string
      TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "JITServer version: %u.%u.%u", MAJOR_NUMBER, MINOR_NUMBER, PATCH_NUMBER);
      }

   static bool shouldReadRetry ()
      {
      return (_numConsecutiveReadErrorsOfSameType < MAX_READ_RETRY);
      }

protected:
   CommunicationStream() : _ssl(NULL), _connfd(-1) { }

   virtual ~CommunicationStream()
      {
      if (_ssl)
         (*OBIO_free_all)(_ssl);
      if (_connfd != -1)
         close(_connfd);
      }

   void initStream(int connfd, BIO *ssl)
      {
      _connfd = connfd;
      _ssl = ssl;
      }

   // Build a message sent by a remote party by reading from the socket
   // as much as possible (up to internal buffer capacity)
   void readMessage(Message &msg);
   void writeMessage(Message &msg);

   int getConnFD() const { return _connfd; }
   std::string getConnIpAddr() const;

   BIO *_ssl; // SSL connection, null if not using SSL
   int _connfd;
   ServerMessage _sMsg;
   ClientMessage _cMsg;

   // There is no need to update this version. TODO: ~elaborate~ just delete...
   static const uint8_t MAJOR_NUMBER = 1; // TODO: delete
   static const uint16_t MINOR_NUMBER = 500; // TODO: delete
   static const uint16_t PATCH_NUMBER = 0; // TODO: delete
   static const uint32_t VERSION = 0; // TODO: delete
   static uint32_t CONFIGURATION_FLAGS; // TODO: delete

   void readBlocking(char *data, size_t size)
      {
      size_t totalBytesRead = 0;
      if (_ssl)
         {
         while (totalBytesRead < size)
            {
            int bytesRead = (*OBIO_read)(_ssl, data + totalBytesRead, size - totalBytesRead);
            if (bytesRead <= 0)
               {
               (*OERR_print_errors_fp)(stderr);
               throw JITServer::StreamFailure("JITServer I/O error: read error", (*OBIO_should_retry)(_ssl));
               }
            totalBytesRead += bytesRead;
            }
         }
      else
         {
         while (totalBytesRead < size)
            {
            ssize_t bytesRead = read(_connfd, data + totalBytesRead, size - totalBytesRead);
            if (bytesRead <= 0)
               {
               if (EINTR != errno)
                  {
                  throw JITServer::StreamFailure("JITServer I/O error: read error: " +
                                                 (bytesRead ? std::string(strerror(errno)) : "connection closed by peer"), EAGAIN == errno);
                  }
               }
            else
               {
               totalBytesRead += bytesRead;
               }
            }
         }
      }

   int32_t readOnceBlocking(char *data, size_t size, bool allowImmediateEof = false)
      {
      int32_t bytesRead = -1;
      if (_ssl)
         {
         bytesRead = (*OBIO_read)(_ssl, data, size);
         if (bytesRead <= 0 && !(allowImmediateEof && bytesRead == 0))
            {
            (*OERR_print_errors_fp)(stderr);
            throw JITServer::StreamFailure("JITServer I/O error: read error", (*OBIO_should_retry)(_ssl));
            }
         }
      else
         {
         while (true)
            {
            bytesRead = read(_connfd, data, size);
            if (allowImmediateEof && bytesRead == 0)
               {
               // For allowImmediateEof, EOF is considered a successful read.
               _numConsecutiveReadErrorsOfSameType = 0;
               break;
               }

            if (bytesRead <= 0)
               {
               if (EINTR != errno)
                  {
                  if ((errno == _lastReadError) && (EAGAIN != errno))
                     {
                     _numConsecutiveReadErrorsOfSameType++;
                     }
                  else
                     {
                     // If its a new error or errno is EAGAIN then reset the counter.
                     // For EAGAIN we set the flag retryConnectionImmediately to true in the below line.
                     _numConsecutiveReadErrorsOfSameType = 0;
                     }

                  _lastReadError = errno;
                  throw JITServer::StreamFailure(
                     "JITServer I/O error: read error: "
                        + (bytesRead ? std::string(strerror(errno)) : "connection closed by peer"),
                     EAGAIN == errno);
                  }
               }
            else
               {
               _numConsecutiveReadErrorsOfSameType = 0;  // Successfull read so reset read retry counter
               break;
               }
            }
         }
      return bytesRead;
      }

   void writeBlocking(const char *data, size_t size)
      {
      size_t totalBytesWritten = 0;
      if (_ssl)
         {
         while (totalBytesWritten < size)
            {
            int bytesWritten = (*OBIO_write)(_ssl, data + totalBytesWritten, size - totalBytesWritten);
            if (bytesWritten <= 0)
               {
               (*OERR_print_errors_fp)(stderr);
               throw JITServer::StreamFailure("JITServer I/O error: write error");
               }
            totalBytesWritten += bytesWritten;
            }
         }
      else
         {
         while (totalBytesWritten < size)
            {
            ssize_t bytesWritten = write(_connfd, data + totalBytesWritten, size - totalBytesWritten);
            if (bytesWritten <= 0)
               {
               if (EINTR != errno)
                  {
                  throw JITServer::StreamFailure("JITServer I/O error: write error: " + std::string(strerror(errno)));
                  }
               }
            else
               {
               totalBytesWritten += bytesWritten;
               }
            }
         }
      }

   // Simple byte buffer serialization/deserialization util for handshake.
   struct ByteBufReader
      {
      const char *_cursor;
      const char *_end;

      ByteBufReader(const char *buf, size_t size) : _cursor(buf), _end(buf + size) {}

      size_t remaining() const { return (size_t)(_end - _cursor); }

      void read(void *dest, size_t n)
         {
         TR_ASSERT_FATAL(remaining() >= n, "insufficient remaining data");
         memcpy(dest, _cursor, n);
         _cursor += n;
         }

      uint8_t readU8()
         {
         uint8_t result;
         read(&result, 1);
         return result;
         }

      uint16_t readU16BE()
         {
         uint16_t result = 0;
         result |= (uint16_t)readU8() << 8;
         result |= (uint16_t)readU8();
         return result;
         }

      uint32_t readU32BE()
         {
         uint32_t result = 0;
         result |= (uint32_t)(uint8_t)readU8() << 24;
         result |= (uint32_t)(uint8_t)readU8() << 16;
         result |= (uint32_t)(uint8_t)readU8() << 8;
         result |= (uint32_t)(uint8_t)readU8();
         return result;
         }

      bool tryReadU8(uint8_t &dest)
         {
         return remaining() < 1 ? (dest = 0, false) : (dest = readU8(), true);
         }

      bool tryReadU16BE(uint16_t &dest)
         {
         return remaining() < 2 ? (dest = 0, false) : (dest = readU16BE(), true);
         }

      bool tryReadU32BE(uint32_t &dest)
         {
         return remaining() < 4 ? (dest = 0, false) : (dest = readU32BE(), true);
         }

      // Native-endian. Needed for back-compat mock compilationRequest message.
      uint16_t readU16NE()
         {
         uint16_t result;
         read(&result, sizeof(result));
         return result;
         }

      uint32_t readU32NE()
         {
         uint32_t result;
         read(&result, sizeof(result));
         return result;
         }
      };

   struct ByteBufWriter
      {
      char *_cursor;
      char *_end;

      ByteBufWriter(char *buf, size_t size) : _cursor(buf), _end(buf + size) {}

      size_t remaining() const { return (size_t)(_end - _cursor); }

      void write(void *src, size_t n)
         {
         TR_ASSERT_FATAL(remaining() >= n, "insufficient remaining space");
         memcpy(_cursor, src, n);
         _cursor += n;
         }

      void writeU8(uint8_t value)
         {
         write(&value, 1);
         }

      void writeU16BE(uint16_t value)
         {
         writeU8((value >> 8) & 0xff);
         writeU8(value & 0xff);
         }

      void writeU32BE(uint32_t value)
         {
         writeU8((value >> 24) & 0xff);
         writeU8((value >> 16) & 0xff);
         writeU8((value >> 8) & 0xff);
         writeU8(value & 0xff);
         }

      // Native endian. Needed for back-compat mock compilationRequest message.
      void writeU16NE(uint16_t value)
         {
         write(&value, sizeof(value));
         }

      void writeU32NE(uint32_t value)
         {
         write(&value, sizeof(value));
         }
      };

   }; // class CommunicationStream
}; // namespace JITServer

#endif // COMMUNICATION_STREAM_H

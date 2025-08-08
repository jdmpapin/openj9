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

#include "ClientStream.hpp"
#include "control/Options.hpp"
#include "env/VerboseLog.hpp"
#include "net/LoadSSLLibs.hpp"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>	/* for TCP_NODELAY option */
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> /// gethostname, read, write
#include <openssl/err.h>

#include "infra/String.hpp"

namespace JITServer
{
int ClientStream::_numConnectionsOpened = 0;
int ClientStream::_numConnectionsClosed = 0;

// used for checking server compatibility
int ClientStream::_incompatibilityCount = 0;
uint64_t ClientStream::_incompatibleStartTime = 0;
const uint64_t ClientStream::RETRY_COMPATIBILITY_INTERVAL_MS = 10000; //ms
const int ClientStream::INCOMPATIBILITY_COUNT_LIMIT = 1; // This needs to be smaller than the recompilation retry count (3)

// Create SSL context, load certs and keys. Only needs to be done once.
// This is called during startup from rossa.cpp
int ClientStream::static_init(TR::CompilationInfo *compInfo)
   {
   if (!CommunicationStream::useSSL())
      return 0;

   TR_ASSERT_FATAL(_sslCtx == NULL, "SSL context already initialized");

   CommunicationStream::initSSL();

   SSL_CTX *ctx = (*OSSL_CTX_new)((*OSSLv23_client_method)());
   if (!ctx)
      {
      perror("can't create SSL context");
      (*OERR_print_errors_fp)(stderr);
      return -1;
      }

   if ((*OSSL_CTX_set_ecdh_auto)(ctx, 1) != 1)
      {
      perror("failed to configure SSL ecdh");
      (*OERR_print_errors_fp)(stderr);
      return -1;
      }

   auto &sslKeys = compInfo->getJITServerSslKeys();
   auto &sslCerts = compInfo->getJITServerSslCerts();
   auto &sslRootCerts = compInfo->getJITServerSslRootCerts();

   // We could also set up keys and certs here, if it's necessary to use TLS client keys
   // it's not needed for a basic setup.
   TR_ASSERT_FATAL(sslKeys.size() == 0 && sslCerts.size() == 0, "client keypairs are not yet supported, use a root cert chain instead");

   // Parse and set certificate chain
   BIO *certMem = (*OBIO_new_mem_buf)(&sslRootCerts[0], sslRootCerts.size());
   if (!certMem)
      {
      perror("cannot create memory buffer for cert (OOM?)");
      (*OERR_print_errors_fp)(stderr);
      return -1;
      }
   STACK_OF(X509_INFO) *certificates = (*OPEM_X509_INFO_read_bio)(certMem, NULL, NULL, NULL);
   if (!certificates)
      {
      perror("cannot parse cert");
      (*OERR_print_errors_fp)(stderr);
      return -1;
      }
   X509_STORE *certStore = (*OSSL_CTX_get_cert_store)(ctx);
   if (!certStore)
      {
      perror("cannot get cert store");
      (*OERR_print_errors_fp)(stderr);
      return -1;
      }

   // add all certificates in the chain to the cert store
   for (size_t i = 0; i < (*Osk_X509_INFO_num)(certificates); i++)
      {
      X509_INFO *certInfo = (*Osk_X509_INFO_value)(certificates, i);
      if (certInfo->x509)
         (*OX509_STORE_add_cert)(certStore, certInfo->x509);
      if (certInfo->crl)
         (*OX509_STORE_add_crl)(certStore, certInfo->crl);
      }
   (*Osk_X509_INFO_pop_free)(certificates, (*OX509_INFO_free));

   // verify server identity using standard method
   (*OSSL_CTX_set_verify)(ctx, SSL_VERIFY_PEER, NULL);

   _sslCtx = ctx;

   if (TR::Options::getVerboseOption(TR_VerboseJITServer))
      TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "Successfully initialized SSL context (%s)", (*OOpenSSL_version)(0));
   return 0;
   }

void ClientStream::freeSSLContext()
   {
   if (_sslCtx)
      {
      (*OSSL_CTX_free)(_sslCtx);
      _sslCtx = NULL;
      }
   }

SSL_CTX *ClientStream::_sslCtx = NULL;

static int
openConnection(const std::string &address, uint32_t port, uint32_t timeoutMs)
   {
   // TODO consider support for IPv6
   struct addrinfo hints;
   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_INET;    // Allow IPv4 only; could use AF_UNSPEC to allow IPv6 too
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = 0;
   hints.ai_protocol = 0; // Any protocol

   char portName[12];
   int r = snprintf(portName, 12, "%d", port);
   if (r < 0 || r > 11)
      throw StreamFailure("snprintf failed");

   struct addrinfo *addrList = NULL;
   int res = getaddrinfo(address.c_str(), portName, &hints, &addrList);
   if (res != 0)
      throw StreamFailure("Cannot resolve server name: " + std::string(gai_strerror(res)));

   struct addrinfo *pAddr;
   int sockfd = -1;
   for (pAddr = addrList; pAddr; pAddr = pAddr->ai_next)
      {
      sockfd = socket(pAddr->ai_family, pAddr->ai_socktype, pAddr->ai_protocol);
      if (sockfd >= 0)
         break; // Use the first address for which a socket could be created
      // Try next address
      }
   if (sockfd < 0)
      {
      int err = errno;
      freeaddrinfo(addrList);
      throw StreamFailure("Cannot create socket: " + std::string(strerror(err)));
      }

   int flag = 1;
   if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0)
      {
      int err = errno;
      freeaddrinfo(addrList);
      close(sockfd);
      throw StreamFailure("Cannot set option SO_KEEPALIVE on socket: " + std::string(strerror(err)));
      }

   struct linger lingerVal = { 1, 2 }; // linger 2 seconds
   if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &lingerVal, sizeof(lingerVal)) < 0)
      {
      int err = errno;
      freeaddrinfo(addrList);
      close(sockfd);
      throw StreamFailure("Cannot set option SO_LINGER on socket: " + std::string(strerror(err)));
      }

   struct timeval timeout = { timeoutMs / 1000 , (timeoutMs % 1000) * 1000 };
   if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
      {
      int err = errno;
      freeaddrinfo(addrList);
      close(sockfd);
      throw StreamFailure("Cannot set option SO_RCVTIMEO on socket: " + std::string(strerror(err)));
      }
   if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
      {
      int err = errno;
      freeaddrinfo(addrList);
      close(sockfd);
      throw StreamFailure("Cannot set option SO_SNDTIMEO on socket: " + std::string(strerror(err)));
      }

   if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
      {
      int err = errno;
      freeaddrinfo(addrList);
      close(sockfd);
      throw StreamFailure("Cannot set option TCP_NODELAY on socket: " + std::string(strerror(err)));
      }

   if (connect(sockfd, pAddr->ai_addr, pAddr->ai_addrlen) < 0)
      {
      int err = errno;
      freeaddrinfo(addrList);
      close(sockfd);
      throw StreamFailure("Connect failed: " + std::string(strerror(err)));
      }

   freeaddrinfo(addrList);
   return sockfd;
   }

static BIO *
openSSLConnection(SSL_CTX *ctx, int connfd)
   {
   if (!ctx)
      return NULL;

   BIO *bio = (*OBIO_new_ssl)(ctx, true);
   if (!bio)
      {
      (*OERR_print_errors_fp)(stderr);
      throw JITServer::StreamFailure("Failed to make new BIO");
      }

   SSL *ssl = NULL;
   if ((*OBIO_ctrl)(bio, BIO_C_GET_SSL, false, (char *)&ssl) != 1) // BIO_get_ssl(bio, &ssl)
      {
      (*OERR_print_errors_fp)(stderr);
      (*OBIO_free_all)(bio);
      throw JITServer::StreamFailure("Failed to get BIO SSL");
      }

   if ((*OSSL_set_fd)(ssl, connfd) != 1)
      {
      (*OERR_print_errors_fp)(stderr);
      (*OBIO_free_all)(bio);
      throw JITServer::StreamFailure("Cannot set file descriptor for SSL");
      }

   if ((*OSSL_connect)(ssl) != 1)
      {
      (*OERR_print_errors_fp)(stderr);
      (*OBIO_free_all)(bio);
      throw JITServer::StreamFailure("Failed to SSL_connect");
      }

   X509 *cert = (*OSSL_get_peer_certificate)(ssl);
   if (!cert)
      {
      (*OERR_print_errors_fp)(stderr);
      (*OBIO_free_all)(bio);
      throw JITServer::StreamFailure("Server certificate unspecified");
      }
   (*OX509_free)(cert);

   if (X509_V_OK != (*OSSL_get_verify_result)(ssl))
      {
      (*OERR_print_errors_fp)(stderr);
      (*OBIO_free_all)(bio);
      throw JITServer::StreamFailure("Server certificate verification failed");
      }

   if (TR::Options::getVerboseOption(TR_VerboseJITServer))
      TR_VerboseLog::writeLineLocked(TR_Vlog_JITServer, "SSL connection on socket 0x%x, Version: %s, Cipher: %s",
                                     connfd, (*OSSL_get_version)(ssl), (*OSSL_get_cipher)(ssl));
   return bio;
   }

ClientStream::ClientStream(TR::PersistentInfo *info)
   : CommunicationStream(), _compatibilityCheckDone(false), _serverIsCompatible(false)
   {
   int connfd = openConnection(info->getJITServerAddress(), info->getJITServerPort(), info->getSocketTimeout());
   BIO *ssl = openSSLConnection(_sslCtx, connfd);
   initStream(connfd, ssl);
   _numConnectionsOpened++;
   }

void
ClientStream::checkCompatibilityWithServerImpl()
   {
   _compatibilityCheckDone = true;

   char buildId[1024];
   CommunicationStream::getJITServerBuildId(buildId, sizeof(buildId));

   char buf[1024]; // big enough...
   ByteBufWriter w(buf, sizeof(buf));

   // Start with the back-compat mock compilationRequest message. If we're
   // connecting to a pre-hello server, it will respond with compilationFailure
   // with reason compilationStreamVersionIncompatible. If we're connecting to a
   // newer server, it will expect to see the hello following this, and it will
   // respond the same way it would if the hello were sent at the beginning.
   //
   // NOTE: Because this is meant to be (minimally) compatible with older
   // servers, which determined compatibility based on data embedded in the
   // usual message serialization scheme, the data here needs to be in native-
   // endian (for the client). If we try to connect to a pre-hello server with
   // opposite endianness, then we'll get a general stream error instead of a
   // clean incompatible version message, but that's also what would have
   // happened if a pre-hello client connected to an opposite-endian pre-hello
   // server, and there isn't much we can do about it.
   //
   // Eventually, when there is little enough risk of attempting to connect to a
   // pre-hello server, this back-compat mock compilation request message can be
   // eliminated.
   //
   ByteBufWriter backCompatCompReqLenWriter = w; // to fix the length at the end
   w.writeU32NE(0); // message length
   w.writeU32NE(backCompatEncodeVersion(2, 0));

   uint32_t oldConfigFlags = JAVA_SPEC_VERSION & BackCompatJITServerJavaVersionMask;
   if (TR::Options::useCompressedPointers())
      {
      oldConfigFlags |= BackCompatJITServerCompressedRef;
      }

   // NOTE: 8 was the most recent value of MessageType::compilationRequest at
   // the time the new handshake was established. Over time the value has
   // changed, so it's not possible to send a value that will be interpreted as
   // compilationRequest by all old servers. However, the server should check
   // for version compatibility before it checks for the expected message type.
   w.writeU32NE(oldConfigFlags);
   w.writeU16NE(8); // compilationRequest
   w.writeU16NE(0); // number of values sent with the message

   // Now that the back-compat part has been buffered, add the hello.
   w._cursor += TR::snprintfNoTrunc(w._cursor, w.remaining(), "OpenJ9/JITServer");

   HandshakeCompressedRefs compressedRefs = TR::Options::useCompressedPointers()
      ? HandshakeCompressedRefs_Enabled
      : HandshakeCompressedRefs_Disabled;

   w.writeU32BE(JAVA_SPEC_VERSION);
   w.writeU32BE(CommunicationStream::getJITServerCpuArch());
   w.writeU32BE(CommunicationStream::getJITServerOs());
   w.writeU8(compressedRefs);

   ByteBufWriter versionDataLengthWriter = w; // to fix the length at the end
   w.writeU16BE(0);

   char *versionDataStart = w._cursor; // to calculate the length at the end

   // This client only supports version zero with the particular build ID of
   // whatever build is running.

   w.writeU16BE(1); // server only gets to choose from one option

   // Write out protocol version option zero.
   w.writeU32BE(0); // protocol version zero
   w.writeU16BE(strlen(buildId));
   w._cursor += TR::snprintfNoTrunc(w._cursor, w.remaining(), "%s", buildId);

   // Fix the version option data length.
   versionDataLengthWriter.writeU16BE(w._cursor - versionDataStart);

   // Fix the length field of the back-compat compilationRequest message.
   // It can't just be 16 bytes because older servers (and, at time of writing,
   // current servers) receiving a normal message will hang up if they receive
   // more data than the length field specifies. So even though the back-compat
   // part of the message specifies zero additional values, set the length to
   // the full length of the data that we're sending.
   backCompatCompReqLenWriter.writeU32NE(w._cursor - buf);

   // Send the hello and handshake info to the server. Done with buf now.
   writeBlocking(buf, w._cursor - buf);

   // Reuse buf for the response.
   readBlocking(buf, 1);
   if (buf[0] == (char)HandshakeResponseCode_OK)
      {
      // Get the selected option.
      readBlocking(buf, 2);
      uint16_t selectedOptionIndex = ByteBufReader(buf, 2).readU16BE();

      // The selected option must be option 0, since there was only one of them.
      if (selectedOptionIndex == 0)
         {
         _serverIsCompatible = true;
         return; // OK!
         }
      else
         {
         throw JITServer::StreamFailure(
            "server selected nonexistent protocol version option");
         }
      }
   else if (buf[0] == (char)HandshakeResponseCode_Incompatible)
      {
      // Get the length of the error message.
      readBlocking(buf, 2);
      uint16_t msgLen = ByteBufReader(buf, 2).readU16BE();

      // Get the error message.
      std::vector<char> msg(msgLen + 1, '\0');
      readBlocking(&msg[0], msgLen);
      throw JITServer::StreamVersionIncompatible(&msg[0]);
      }
   else
      {
      if (buf[0] % 4 == 0)
         {
         // Pre-hello servers respond with a message in their usual serialization
         // format. The first 4 bytes are an unsigned 32-bit length in native
         // endian. (Server native endian to be specific, but if there hasn't been
         // a general stream error then that matches client native endian.) For
         // little-endian, the first byte is the low byte, which will be a multiple
         // of 4 due to padding. For big-endian, the first byte is the high byte,
         // which should be zero, which is also a multiple of 4. The handshake
         // response codes avoid multiples of 4 to ensure that they can be
         // distinguished from the response of a pre-hello server.
         readBlocking(&buf[1], 15); // read the rest of the message metadata

         ByteBufReader r(buf, 16);
         uint32_t responseLen = r.readU32NE();
         uint32_t serverStreamVersion = r.readU32NE();
         uint32_t serverConfig = r.readU32NE();
         uint16_t responseMsgType = r.readU16NE();
         uint16_t responseNumValues = r.readU16NE();

         // compilationStreamVersionIncompatible messages have the stream version
         // set to zero. Maybe this was the case for all messages sent from the
         // server to the client?
         if (responseLen >= 16
             && serverStreamVersion == 0
             && responseMsgType == BackCompatMessageType_compilationFailure
             && responseNumValues == 2)
            {
            // Any reason whatsoever means that the stream version is incompatible,
            // so we don't have to decode the compilation error code.
            throw JITServer::StreamVersionIncompatible(
               "server must be from the same OpenJ9 JVM build");
            }
         }

      throw JITServer::StreamVersionIncompatible(
         "server sent an unrecognized handshake response");
      }
   }

void
ClientStream::checkCompatibilityWithServerIgnoringErrors()
   {
   try
      {
      checkCompatibilityWithServer();
      }
   catch (...)
      {
      return;
      }
   }

}

/*
*  SSL client demonstration program
*
*  Copyright (C) 2006-2013, Brainspark B.V.
*
*  This file is part of PolarSSL (http://www.polarssl.org)
*  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
*
*  All rights reserved.
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License along
*  with this program; if not, write to the Free Software Foundation, Inc.,
*  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <inc/sslclient.h>
#include <inc/keys.h>

#include <polarssl2/polarssl/config.h>

#include <polarssl2/polarssl/ssl.h>
#include <polarssl2/polarssl/entropy.h>
#include <polarssl2/polarssl/ctr_drbg.h>
#include <polarssl2/polarssl/error.h>
#include <polarssl2/polarssl/certs.h>

#define __SUBCOMPONENT__ "sslclient"

#define SERVER_PORT 4433
#define SERVER_NAME "localhost"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

#define DEBUG_LEVEL 1

static void my_debug(void *ctx, int level, const char *str)
{
	if (level < DEBUG_LEVEL)
	{
		KLog(LInfo, "%s", str);
	}
}

int net_recv(void *ctx, unsigned char *buf, size_t size)
{
	return 0;
}

int net_send(void *ctx, const unsigned char *buf, size_t size)
{
	return 0;
}

int net_connect(int *socket_fd, const char *host, int port)
{
	return 0;
}

void net_close(int socket_fd)
{
	return;
}

int ssl_client_test()
{
	int ret, len, server_fd = -1;
	unsigned char buf[1024];
	const char *pers = "ssl_client1";

	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
	ssl_context ssl;
	x509_crt cacert;

	InitKernelCallbacks(NULL);

	/*
	* 0. Initialize the RNG and the session data
	*/
	memset(&ssl, 0, sizeof(ssl_context));
	x509_crt_init(&cacert);

	KLog(LInfo,"\n  . Seeding the random number generator...");

	entropy_init(&entropy);
	if ((ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy,
		(const unsigned char *)pers,
		strlen(pers))) != 0)
	{
		KLog(LInfo," failed\n  ! ctr_drbg_init returned %d\n", ret);
		goto exit;
	}

	KLog(LInfo," ok\n");

	/*
	* 0. Initialize certificates
	*/
	KLog(LInfo,"  . Loading the CA root certificate ...");

#if defined(POLARSSL_CERTS_C)
	ret = x509_crt_parse(&cacert, CA_Cert,
		strlen(CA_Cert));

	if (ret < 0)
	{
		KLog(LInfo, " failed\n  !  x509_crt_parse returned -0x%x\n\n", -ret);
		goto exit;
	}

	ret = x509_crt_parse(&cacert, Client_Cert,
		strlen(Client_Cert));

	if (ret < 0)
	{
		KLog(LInfo, " failed\n  !  x509_crt_parse returned -0x%x\n\n", -ret);
		goto exit;
	}

#else
	ret = 1;
	KLog(LInfo,"POLARSSL_CERTS_C not defined.");

	if (ret < 0)
	{
		KLog(LInfo, " failed\n  !  x509_crt_parse returned -0x%x\n\n", -ret);
		goto exit;
	}
#endif

	KLog(LInfo," ok (%d skipped)\n", ret);

	/*
	* 1. Start the connection
	*/
	KLog(LInfo,"  . Connecting to tcp/%s/%4d...", SERVER_NAME,
		SERVER_PORT);

	if ((ret = net_connect(&server_fd, SERVER_NAME,
		SERVER_PORT)) != 0)
	{
		KLog(LInfo," failed\n  ! net_connect returned %d\n\n", ret);
		goto exit;
	}

	KLog(LInfo," ok\n");

	/*
	* 2. Setup stuff
	*/
	KLog(LInfo,"  . Setting up the SSL/TLS structure...");

	if ((ret = ssl_init(&ssl)) != 0)
	{
		KLog(LInfo," failed\n  ! ssl_init returned %d\n\n", ret);
		goto exit;
	}

	KLog(LInfo," ok\n");

	ssl_set_endpoint(&ssl, SSL_IS_CLIENT);
	ssl_set_authmode(&ssl, SSL_VERIFY_OPTIONAL);
	ssl_set_ca_chain(&ssl, &cacert, NULL, "PolarSSL Server 1");

	ssl_set_rng(&ssl, ctr_drbg_random, &ctr_drbg);
	ssl_set_dbg(&ssl, my_debug, NULL);
	ssl_set_bio(&ssl, net_recv, &server_fd,
		net_send, &server_fd);

	/*
	* 4. Handshake
	*/
	KLog(LInfo,"  . Performing the SSL/TLS handshake...");

	while ((ret = ssl_handshake(&ssl)) != 0)
	{
		if (ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
		{
			KLog(LInfo," failed\n  ! ssl_handshake returned -0x%x\n\n", -ret);
			goto exit;
		}
	}

	KLog(LInfo," ok\n");

	/*
	* 5. Verify the server certificate
	*/
	KLog(LInfo,"  . Verifying peer X.509 certificate...");

	if ((ret = ssl_get_verify_result(&ssl)) != 0)
	{
		KLog(LInfo," failed\n");

		if ((ret & BADCERT_EXPIRED) != 0)
			KLog(LInfo,"  ! server certificate has expired\n");

		if ((ret & BADCERT_REVOKED) != 0)
			KLog(LInfo,"  ! server certificate has been revoked\n");

		if ((ret & BADCERT_CN_MISMATCH) != 0)
			KLog(LInfo,"  ! CN mismatch (expected CN=%s)\n", "PolarSSL Server 1");

		if ((ret & BADCERT_NOT_TRUSTED) != 0)
			KLog(LInfo,"  ! self-signed or not signed by a trusted CA\n");

		KLog(LInfo,"\n");
	}
	else
		KLog(LInfo," ok\n");

	/*
	* 3. Write the GET request
	*/
	KLog(LInfo,"  > Write to server:");
	

	len = 0;
	while ((ret = ssl_write(&ssl, buf, len)) <= 0)
	{
		if (ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
		{
			KLog(LInfo," failed\n  ! ssl_write returned %d\n\n", ret);
			goto exit;
		}
	}

	len = ret;
	KLog(LInfo," %d bytes written\n\n%s", len, (char *)buf);

	/*
	* 7. Read the HTTP response
	*/
	KLog(LInfo,"  < Read from server:");

	do
	{
		len = sizeof(buf)-1;
		memset(buf, 0, sizeof(buf));
		ret = ssl_read(&ssl, buf, len);

		if (ret == POLARSSL_ERR_NET_WANT_READ || ret == POLARSSL_ERR_NET_WANT_WRITE)
			continue;

		if (ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY)
			break;

		if (ret < 0)
		{
			KLog(LInfo,"failed\n  ! ssl_read returned %d\n\n", ret);
			break;
		}

		if (ret == 0)
		{
			KLog(LInfo,"\n\nEOF\n\n");
			break;
		}

		len = ret;
		KLog(LInfo," %d bytes read\n\n%s", len, (char *)buf);
	} while (1);

	ssl_close_notify(&ssl);

exit:

#ifdef POLARSSL_ERROR_C
	if (ret != 0)
	{
		char error_buf[100];
		polarssl_strerror(ret, error_buf, 100);
		KLog(LInfo,"Last error was: %d - %s\n\n", ret, error_buf);
	}
#endif

	x509_crt_free(&cacert);
	net_close(server_fd);
	ssl_free(&ssl);
	entropy_free(&entropy);

	memset(&ssl, 0, sizeof(ssl));

	KLog(LInfo, "Ended");

	return(ret);
}

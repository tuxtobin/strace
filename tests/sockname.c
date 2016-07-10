/*
 * Check decoding of getsockname, getpeername, accept, and accept4 syscalls.
 *
 * Copyright (c) 2016 Dmitry V. Levin <ldv@altlinux.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "tests.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifndef TEST_SYSCALL_NAME
# error TEST_SYSCALL_NAME must be defined
#endif

#define TEST_SYSCALL_STR__(a) #a
#define TEST_SYSCALL_STR_(a) TEST_SYSCALL_STR__(a)
#define TEST_SYSCALL_STR TEST_SYSCALL_STR_(TEST_SYSCALL_NAME)
#define TEST_SOCKET TEST_SYSCALL_STR ".socket"

#ifdef TEST_SYSCALL_PREPARE
# define PREPARE_TEST_SYSCALL_INVOCATION do { TEST_SYSCALL_PREPARE; } while (0)
#else
# define PREPARE_TEST_SYSCALL_INVOCATION do {} while (0)
#endif

#ifndef FLAGS_ARG
# define FLAGS_ARG
#endif
#ifndef FLAGS_STR
# define FLAGS_STR ""
#endif

static void
test_sockname_syscall(const int fd)
{
	socklen_t *const plen = tail_alloc(sizeof(*plen));
	*plen = sizeof(struct sockaddr_un);
	struct sockaddr_un *addr = tail_alloc(*plen);

	PREPARE_TEST_SYSCALL_INVOCATION;
	int rc = TEST_SYSCALL_NAME(fd, (void *) addr, plen FLAGS_ARG);
	if (rc < 0)
		perror_msg_and_skip(TEST_SYSCALL_STR);
	printf("%s(%d, {sa_family=AF_UNIX, sun_path=\"%s\"}"
	       ", [%d]%s) = %d\n",
	       TEST_SYSCALL_STR, fd, addr->sun_path,
	       (int) *plen, FLAGS_STR, rc);

	memset(addr, 0, sizeof(*addr));
	PREPARE_TEST_SYSCALL_INVOCATION;
	rc = TEST_SYSCALL_NAME(fd, (void *) addr, plen FLAGS_ARG);
	if (rc < 0)
		perror_msg_and_skip(TEST_SYSCALL_STR);
	printf("%s(%d, {sa_family=AF_UNIX, sun_path=\"%s\"}"
	       ", [%d]%s) = %d\n",
	       TEST_SYSCALL_STR, fd, addr->sun_path,
	       (int) *plen, FLAGS_STR, rc);

	PREPARE_TEST_SYSCALL_INVOCATION;
	rc = TEST_SYSCALL_NAME(fd, (void *) addr, 0 FLAGS_ARG);
	printf("%s(%d, %p, NULL%s) = %d %s (%m)\n",
	       TEST_SYSCALL_STR, fd, addr, FLAGS_STR, rc, errno2name());

	PREPARE_TEST_SYSCALL_INVOCATION;
	rc = TEST_SYSCALL_NAME(fd, 0, 0 FLAGS_ARG);
	if (rc < 0)
		printf("%s(%d, NULL, NULL%s) = %d %s (%m)\n",
		       TEST_SYSCALL_STR, fd, FLAGS_STR, rc, errno2name());
	else
		printf("%s(%d, NULL, NULL%s) = %d\n",
		       TEST_SYSCALL_STR, fd, FLAGS_STR, rc);

	PREPARE_TEST_SYSCALL_INVOCATION;
	rc = TEST_SYSCALL_NAME(fd, (void *) addr, plen + 1 FLAGS_ARG);
	printf("%s(%d, %p, %p%s) = %d %s (%m)\n",
	       TEST_SYSCALL_STR, fd, addr,
	       plen + 1, FLAGS_STR, rc, errno2name());

	++addr;
	*plen = sizeof(struct sockaddr);
	addr = (void *) addr - *plen;

	const size_t offsetof_sun_path = offsetof(struct sockaddr_un, sun_path);
	PREPARE_TEST_SYSCALL_INVOCATION;
	rc = TEST_SYSCALL_NAME(fd, (void *) addr, plen FLAGS_ARG);
	if (rc < 0)
		perror_msg_and_skip(TEST_SYSCALL_STR);
	printf("%s(%d, {sa_family=AF_UNIX, sun_path=\"%.*s\"}"
	       ", [%d->%d]%s) = %d\n",
	       TEST_SYSCALL_STR, fd,
	       (int) (sizeof(struct sockaddr) - offsetof_sun_path),
	       addr->sun_path, (int) sizeof(struct sockaddr),
	       (int) *plen, FLAGS_STR, rc);

	PREPARE_TEST_SYSCALL_INVOCATION;
	rc = TEST_SYSCALL_NAME(fd, (void *) addr, plen FLAGS_ARG);
	printf("%s(%d, %p, [%d]%s) = %d %s (%m)\n",
	       TEST_SYSCALL_STR, fd, addr,
	       *plen, FLAGS_STR, rc, errno2name());
}

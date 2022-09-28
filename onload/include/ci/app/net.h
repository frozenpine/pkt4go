/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_app */
#ifndef __CI_APP_NET_H__
#define __CI_APP_NET_H__

# include <arpa/inet.h>
# include <netinet/in.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <sys/un.h>
# include <netdb.h>


/**********************************************************************
 ** CI typechecked socket error codes.
 */
typedef struct { int val; } ci_sock_err_t;

/* All socket related errors which are used or generated by CI libraries. Other
   system generated socket errors may be passed through suitably wrapped */
extern ci_sock_err_t  CI_SOCK_OK;
extern ci_sock_err_t  CI_SOCK_INVALID;
extern ci_sock_err_t  CI_SOCK_EWOULDBLOCK;
extern ci_sock_err_t  CI_SOCK_EMSGSIZE;
extern ci_sock_err_t  CI_SOCK_ETIMEDOUT;
extern ci_sock_err_t  CI_SOCK_ECONNREFUSED;
extern ci_sock_err_t  CI_SOCK_ECONNABORTED;
extern ci_sock_err_t  CI_SOCK_EOPNOTSUPP;
extern ci_sock_err_t  CI_SOCK_ENOBUFS;

ci_inline ci_sock_err_t 
ci_sock_err(int val)		/*!< construct sock_err from errno */
{
  ci_sock_err_t e;
  e.val = val;
  return e;
}

ci_inline int
ci_sock_iserrno(ci_sock_err_t e) /*!< test whether system errno matches */
{
  return (e.val == CI_SOCK_ERRNO());  /*! \TODO rename these macros */
}

/*! Comment? */
ci_inline int
ci_sock_errok(ci_sock_err_t e) { return (e.val == CI_SOCK_OK.val); }

/*! Comment? */
ci_inline int
ci_sock_erreq(ci_sock_err_t a, ci_sock_err_t b) { return (a.val == b.val); }

/*! Comment? */
ci_inline int
ci_sock_errcode(ci_sock_err_t a) { return -a.val; }

ci_inline int/*bool*/
is_v4mapped(const struct in6_addr* addr)
{
  static const uint16_t prefix[] = {0,0,0,0,0,0xffff};
  return ! memcmp(prefix, addr, sizeof(prefix));
}

ci_inline size_t
sockaddr_size_by_family(int family)
{
  switch( family ) {
    case AF_INET: return sizeof(struct sockaddr_in);
    case AF_INET6: return sizeof(struct sockaddr_in6);
    case AF_UNIX: return sizeof(struct sockaddr_un);
  }
  return 0;
}

ci_inline size_t
sockaddr_size(const struct sockaddr_storage* sa)
{
  return sockaddr_size_by_family(sa->ss_family);
}

/* Change just the port part of 'sa'. 'port' is in host byte order. Returns -1
 * on error (e.g. sa->ss_family invalid, port number out of range). */
int sockaddr_set_port(struct sockaddr_storage* sa, int port);

/* Returns the port part of 'sa' in host byte order, or -1 if sa->ss_family is
 * unknown */
int sockaddr_get_port(const struct sockaddr_storage* sa);

/* Modifies the host part of 'sa' to the 'any' IP address, based on the
 * current value of sa->ss_family. Returns -1 on unknown family. */
int sockaddr_set_any(struct sockaddr_storage* sa);

/* Modifies the host part of 'sa' to the 'loopback' IP address, based on the
 * current value of sa->ss_family. Returns -1 on unknown family. */
int sockaddr_set_loopback(struct sockaddr_storage* sa);

/**********************************************************************
 ** Useful helpers (not error checked).
 */

  /*! Parse [hp], which must be in the format: <host>, <port> or
  ** <host:port>.  Returns 0 on success, or negative error code on failure.
  */
extern int ci_hostport_to_sockaddr(int hint_af, const char* hp,
                                   struct sockaddr_storage* addr_out);

/* deprecated (but still widely used in tests) */
extern int ci_hostport_to_sockaddr_in(const char* hp,
				   struct sockaddr_in* addr_out);

  /*! Convert hostname and port to sockaddr.  [host] may be null, in which
  ** case INADDR_ANY is used.  Returns 0 on success, or negative error code
  ** on failure.
  */
extern int ci_host_port_to_sockaddr_in(const char* host, int port,
				    struct sockaddr_in* addr_out);

  /*! Set blocking mode for [fd]. */
extern int ci_setfdblocking(int fd, int blocking);


#endif  /* __CI_APP_NET_H__ */

/*! \cidoxg_end */
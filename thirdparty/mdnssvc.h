/* minimal tinysvcmdns header */
#ifndef MDNSSVC_H
#define MDNSSVC_H
#include <stdint.h>
#include <stdbool.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

struct mdnsd;

struct mdnsd *mdnsd_start(struct in_addr bind_addr, bool loopback);
void mdnsd_stop(struct mdnsd *svr);
void mdnsd_set_hostname(struct mdnsd *svr, const char *hostname, struct in_addr addr);
void mdnsd_register_svc(struct mdnsd *svr, const char *instance_name, 
                        const char *type, uint16_t port, 
                        const char *hostname, const char *txt[]);

#endif

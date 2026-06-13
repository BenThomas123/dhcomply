#ifndef DHCOMPLYLIFECYCLE_H
#define DHCOMPLYLIFECYCLE_H

#include "dhcomplyBuildMessageFunctions.h"
#include "dhcomplyParseMessageFunctions.h"
#include "dhcomplySendMessageFunctions.h"

void statefulLifeCycle(config_t *, char *, int, char *);
int confirmLifeCycle(config_t *, char *);
int releaseLifeCycle(config_t *, char *);
void statelessLifeCycle(config_t *, char *, int);

#endif //DHCOMPLYLIFECYCLE_H

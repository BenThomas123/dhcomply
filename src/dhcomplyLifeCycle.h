#ifndef DHCOMPLYLIFECYCLE_H
#define DHCOMPLYLIFECYCLE_H

#include "dhcomplyBuildMessageFunctions.h"
#include "dhcomplyParseMessageFunctions.h"
#include "dhcomplySendMessageFunctions.h"

void statefulLifeCycle(config_t *, char *, int, char *);
void statelessLifeCycle(config_t *, char *, int);

#endif //DHCOMPLYLIFECYCLE_H

#ifndef __SECURITY_DEBUG_H_
#define __SECURITY_DEBUG_H_

#include "dm-security.h"

void print_bio(struct bio* bio);
void print_convert_context(struct convert_context* ctx);

#endif /* __SECURITY_DEBUG_H_ */
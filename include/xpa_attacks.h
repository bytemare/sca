#ifndef SCA_2_XPA_ATTACKS_H
#define SCA_2_XPA_ATTACKS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <constants.h>

void dpa(container *data);

void cpa(container *data, FILE *output_file);

#endif /*SCA_2_XPA_ATTACKS_H*/

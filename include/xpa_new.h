//
// Created by dan on 11/02/18.
//

#ifndef SCA_2_XPA_NEW_H
#define SCA_2_XPA_NEW_H

#include <xpa_attacks.h>

/**
 * Wrapper function for dpa and cpa
 * Mode is chosen by specifying "dpa" or "cpa" in mode parameter
 * @param data
 * @param mode
 */
void xpa(container *data, char xpa_mode[4]);

#endif /*SCA_2_XPA_NEW_H*/
